/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2026 Osza Tools contributors
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#include "threatblockmanager.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "qztools.h"
#include "settings.h"
#include "datapaths.h"

#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QLocale>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QWebEngineProfile>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimerEvent>
#include <QUrl>

namespace {

// Refresh cadence: like every mainstream browser with a built-in bad
// list, a few downloads per day keep the list fresh while the local
// copy keeps working when offline.
const int kRefreshIntervalMs = 12 * 60 * 60 * 1000;

// Safety valve against a broken or hostile list source. The default
// host feed is around a hundred thousand entries; anything beyond
// this is almost certainly not a host list.
const int kMaxListEntries = 1000000;

const char kListHeader[] = "# Osza Browser threat blocklist";
const char kListSourcePrefix[] = "# source: ";
const char kListUpdatedPrefix[] = "# updated: ";

// One matching walk for every question of the shape "which entry of
// this set covers this host": the host itself first, then each parent
// domain in turn, closest first. The dot boundary in the walk is what
// keeps "evilbad.example" from matching "bad.example". Returns the
// entry that matched, or an empty string when nothing does - the
// caller decides what that means (blocked, session-allowed, flagged).
// The caller holds the mutex guarding the set (or owns it).
QString matchingEntry(const QString &host, const QSet<QString> &set)
{
    if (host.isEmpty() || set.isEmpty()) {
        return QString();
    }

    if (set.contains(host)) {
        return host;
    }

    QString name = host;
    for (;;) {
        const int dot = name.indexOf(QLatin1Char('.'));
        if (dot < 0 || dot + 1 >= name.size()) {
            return QString();
        }
        name = name.mid(dot + 1);
        if (set.contains(name)) {
            return name;
        }
    }
}

// The freshness judgment, spoken once: a list is due for a refresh
// when its last update is older than the refresh interval. The
// manager's own timer (through checkForUpdate -> isListStale), the
// public isListStale() the padlock row asks, and the interstitial's
// list-state row (which already holds the mutex and cannot ask the
// self-locking query) all read the age through this one helper, so
// the browser can never consider a list fresh in one place and
// stale in another. The caller holds the mutex (or owns the value).
bool listIsStale(const QDateTime &updated)
{
    return !updated.isValid() || updated.msecsTo(QDateTime::currentDateTimeUtc()) > kRefreshIntervalMs;
}

} // namespace

ThreatBlockManager::ThreatBlockManager(QObject *parent)
    : QObject(parent)
    , m_enabled(true)
    , m_updating(false)
    , m_lastError()
    , m_lastDelta(0)
    , m_deltaValid(false)
    , m_nam(nullptr)
    , m_reply(nullptr)
    , m_refreshTimerId(0)
{
}

// The default blocklist source: the StevenBlack hosts list - a
// curated, MIT-licensed aggregation of adware and malware hosts
// (itself built from sources like MalwareDomainList and Spam404). It
// is downloaded in bulk, without any information about the browsing
// that identified it, and the parser also accepts plain URL or
// host-per-line feeds. The recommended-baseline preset and the
// sidebar read the default from here, so the URL lives once.
QString ThreatBlockManager::defaultSourceUrl()
{
    return QSL("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts");
}

void ThreatBlockManager::loadSettings()
{
    QString source;
    bool enabled = true;

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        enabled = settings.value(QSL("ThreatBlockEnabled"), true).toBool();
        source = settings.value(QSL("ThreatBlockSource"), ThreatBlockManager::defaultSourceUrl()).toString();
        settings.endGroup();
    }

    if (source.trimmed().isEmpty()) {
        source = ThreatBlockManager::defaultSourceUrl();
    }

    {
        QMutexLocker lock(&m_mutex);
        m_enabled = enabled;
        m_sourceUrl = source;
    }

    loadList();

    // Keep the list fresh while the browser runs.
    if (!m_refreshTimerId) {
        m_refreshTimerId = startTimer(kRefreshIntervalMs, Qt::VeryCoarseTimer);
    }

    if (m_enabled && !mApp->isTestModeEnabled()) {
        checkForUpdate();
    }
}

bool ThreatBlockManager::isEnabled() const
{
    QMutexLocker lock(&m_mutex);
    return m_enabled;
}

void ThreatBlockManager::setEnabled(bool enabled)
{
    {
        QMutexLocker lock(&m_mutex);
        if (m_enabled == enabled) {
            return;
        }
        m_enabled = enabled;
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("ThreatBlockEnabled"), enabled);
    settings.endGroup();

    if (enabled && !mApp->isTestModeEnabled()) {
        checkForUpdate();
    }

    Q_EMIT enabledChanged(enabled);
}

QString ThreatBlockManager::sourceUrl() const
{
    QMutexLocker lock(&m_mutex);
    return m_sourceUrl;
}

void ThreatBlockManager::setSourceUrl(const QString &url)
{
    const QString trimmed = url.trimmed();

    if (trimmed.isEmpty()) {
        return;
    }

    {
        QMutexLocker lock(&m_mutex);
        m_sourceUrl = trimmed;
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("ThreatBlockSource"), trimmed);
    settings.endGroup();
}

QDateTime ThreatBlockManager::lastUpdate() const
{
    QMutexLocker lock(&m_mutex);
    return m_lastUpdate;
}

int ThreatBlockManager::hostCount() const
{
    QMutexLocker lock(&m_mutex);
    return m_blockedHosts.size();
}

bool ThreatBlockManager::isListLoaded() const
{
    QMutexLocker lock(&m_mutex);
    return !m_blockedHosts.isEmpty();
}

bool ThreatBlockManager::isUpdating() const
{
    // The interstitial reads this on the WebEngine IO thread, so the
    // flag lives under the mutex like every state that page reports
    // on - written on the UI thread only (fetchList and the reply's
    // finished handler), read from anywhere.
    QMutexLocker lock(&m_mutex);
    return m_updating;
}

QString ThreatBlockManager::lastUpdateError() const
{
    QMutexLocker lock(&m_mutex);
    return m_lastError;
}

bool ThreatBlockManager::isListStale() const
{
    QMutexLocker lock(&m_mutex);
    return m_blockedHosts.isEmpty() || listIsStale(m_lastUpdate);
}

QString ThreatBlockManager::describeListAge(const QDateTime &since)
{
    if (!since.isValid()) {
        return tr("unknown date");
    }

    // The age of the evidence, not the wall-clock time it arrived:
    // clamped at zero so a clock skew into the future reads as
    // "just now" instead of a negative age.
    const qint64 elapsed = qMax<qint64>(0, since.secsTo(QDateTime::currentDateTimeUtc()));

    if (elapsed < 60) {
        return tr("less than a minute ago");
    }

    const qint64 minutes = elapsed / 60;

    if (minutes < 60) {
        return tr("%n minute(s) ago", nullptr, int(minutes));
    }

    const qint64 hours = minutes / 60;

    if (hours < 24) {
        return tr("%n hour(s) ago", nullptr, int(hours));
    }

    return tr("%n day(s) ago", nullptr, int(hours / 24));
}

bool ThreatBlockManager::isHostBlocked(const QString &host) const
{
    const QString name = normalizeHost(host);

    QMutexLocker lock(&m_mutex);

    // Subdomains of a listed host belong to the same operator; the
    // dot boundary lives in the one shared walk.
    return !matchingEntry(name, m_blockedHosts).isEmpty();
}

QString ThreatBlockManager::matchingListEntry(const QString &host) const
{
    const QString name = normalizeHost(host);

    QMutexLocker lock(&m_mutex);

    return matchingEntry(name, m_blockedHosts);
}

bool ThreatBlockManager::shouldBlock(const QString &host) const
{
    const QString name = normalizeHost(host);

    if (name.isEmpty()) {
        return false;
    }

    QMutexLocker lock(&m_mutex);

    if (!m_enabled || m_blockedHosts.isEmpty()) {
        return false;
    }

    // The "proceed anyway" exception covers the host and its
    // subdomains, symmetric with how the blocklist matches.
    if (isSessionAllowedLocked(name)) {
        return false;
    }

    // Subdomains of a listed host belong to the same operator; the
    // dot boundary lives in the one shared walk.
    return !matchingEntry(name, m_blockedHosts).isEmpty();
}

bool ThreatBlockManager::isSessionAllowed(const QString &host) const
{
    const QString name = normalizeHost(host);

    if (name.isEmpty()) {
        return false;
    }

    QMutexLocker lock(&m_mutex);
    return isSessionAllowedLocked(name);
}

bool ThreatBlockManager::isSessionAllowedLocked(const QString &host) const
{
    // The exception covers subdomains of the allowed host as well,
    // through the same walk the blocklist matches with.
    return !matchingEntry(host, m_sessionAllowed).isEmpty();
}

void ThreatBlockManager::allowForSession(const QString &host)
{
    const QString name = normalizeHost(host);

    if (name.isEmpty()) {
        return;
    }

    {
        QMutexLocker lock(&m_mutex);
        m_sessionAllowed.insert(name);
    }
}

void ThreatBlockManager::removeSessionAllow(const QString &host)
{
    const QString name = normalizeHost(host);

    if (name.isEmpty()) {
        return;
    }

    {
        QMutexLocker lock(&m_mutex);

        // The revoke covers what the allow covered: the host and its
        // subdomains. An allow created for "example" is what keeps
        // "www.example" out of the interstitial, so removing only the
        // exact name would leave the protection paused for the names
        // the user actually sees - the mirror of isSessionAllowedLocked.
        m_sessionAllowed.remove(name);
        QString parent = name;
        for (;;) {
            const int dot = parent.indexOf(QLatin1Char('.'));
            if (dot < 0 || dot + 1 >= parent.size()) {
                break;
            }
            parent = parent.mid(dot + 1);
            m_sessionAllowed.remove(parent);
        }
    }
}

void ThreatBlockManager::checkForUpdate()
{
    // The one staleness judgment: the same isListStale() the padlock
    // row and the interstitial report through, so the timer never
    // fetches a list those surfaces would still call fresh - nor
    // leaves alone one they already call due.
    if (isListStale()) {
        fetchList();
    }
}

void ThreatBlockManager::updateNow()
{
    fetchList();
}

void ThreatBlockManager::abortUpdate()
{
    if (m_reply) {
        m_reply->abort();
    }
}

void ThreatBlockManager::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == m_refreshTimerId) {
        if (isEnabled() && !mApp->isTestModeEnabled()) {
            checkForUpdate();
        }
        return;
    }

    QObject::timerEvent(event);
}

int ThreatBlockManager::parseListData(const QByteArray &data, QSet<QString> *hosts)
{
    const int before = hosts->size();
    const QList<QByteArray> lines = data.split('\n');

    for (const QByteArray &rawLine : lines) {
        const QString line = QString::fromUtf8(rawLine).trimmed();

        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }

        QString host;

        // Format 1: a full URL, like every line of the URLhaus export.
        if (line.contains(QL1S("://"))) {
            const QUrl url = QUrl::fromEncoded(rawLine.trimmed());
            host = url.host();
        } else {
            const QStringList tokens = line.split(QRegularExpression(QSL("\\s+")), Qt::SkipEmptyParts);

            // Format 2: a hosts-file line ("0.0.0.0 bad.example").
            if (tokens.size() >= 2 && !QHostAddress(tokens.at(0)).isNull()) {
                // Every name after the address is blocked by the line.
                for (int i = 1; i < tokens.size(); ++i) {
                    const QString normalized = normalizeHost(tokens.at(i));
                    if (!normalized.isEmpty() && normalized != QSL("localhost")) {
                        hosts->insert(normalized);
                    }
                }
                if (hosts->size() >= kMaxListEntries) {
                    break;
                }
                continue;
            }
            // Format 3: a bare host name.
            else if (tokens.size() == 1 && !line.contains(QLatin1Char('/'))) {
                host = tokens.at(0);
            }
        }

        const QString normalized = normalizeHost(host);

        if (normalized.isEmpty() || normalized == QSL("localhost")) {
            continue;
        }

        hosts->insert(normalized);

        if (hosts->size() >= kMaxListEntries) {
            break;
        }
    }

    return hosts->size() - before;
}

QString ThreatBlockManager::normalizeHost(const QString &host)
{
    QString name = host.trimmed().toLower();

    while (name.startsWith(QLatin1Char('[')) && name.endsWith(QLatin1Char(']'))) {
        name = name.mid(1, name.size() - 2);
    }

    while (name.endsWith(QLatin1Char('.'))) {
        name.chop(1);
    }

    if (name.isEmpty()) {
        return QString();
    }

    // Internationalized names are stored in their ASCII-compatible
    // encoding, exactly like the engine reports them.
    const QString ace = QString::fromLatin1(QUrl::toAce(name));

    return ace.isEmpty() ? name : ace;
}

int ThreatBlockManager::applyListData(const QByteArray &data)
{
    QSet<QString> hosts;
    parseListData(data, &hosts);

    const QDateTime now = QDateTime::currentDateTimeUtc();

    // The movement the new list brings, remembered beside the swap
    // it describes: the count of the list in place against the
    // count of the list landing. This is the one path a renewal
    // takes (the downloader's reply handler; the manual import and
    // the tests ride it too) - never the startup load from disk -
    // so a movement is only ever remembered for a list that
    // actually replaced one, and the first list a profile ever sees
    // arrives with no movement to claim. Remembered before the
    // swap lands, so the delta is already in place when the
    // listUpdated handlers run.
    const int previousCount = hostCount();

    {
        QMutexLocker lock(&m_mutex);
        m_lastDelta = hosts.size() - previousCount;
        m_deltaValid = previousCount > 0;
    }

    applyList(hosts, now);
    saveList(hosts, now);

    return hosts.size();
}

void ThreatBlockManager::applyList(const QSet<QString> &hosts, const QDateTime &when)
{
    {
        QMutexLocker lock(&m_mutex);
        m_blockedHosts = hosts;
        m_lastUpdate = when;

        // A list landed: whatever the last attempt failed with, this
        // one succeeded - the error state the surfaces report ends
        // with the success they report.
        m_lastError.clear();
    }

    Q_EMIT listUpdated(hosts.size());
}

bool ThreatBlockManager::saveList(const QSet<QString> &hosts, const QDateTime &when)
{
    QFile file(listFilePath());

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "ThreatBlock: cannot write the blocklist:" << file.errorString();
        return false;
    }

    QString source;
    {
        QMutexLocker lock(&m_mutex);
        source = m_sourceUrl;
    }

    file.write(QByteArray(kListHeader) + '\n');
    file.write(QByteArray(kListSourcePrefix) + source.toUtf8() + '\n');
    file.write(QByteArray(kListUpdatedPrefix) + when.toString(Qt::ISODate).toUtf8() + '\n');

    QList<QString> sorted = hosts.values();
    std::sort(sorted.begin(), sorted.end());
    for (const QString &host : std::as_const(sorted)) {
        file.write(host.toUtf8() + '\n');
    }

    return true;
}

bool ThreatBlockManager::loadList()
{
    QFile file(listFilePath());

    if (!file.exists()) {
        return false;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "ThreatBlock: cannot read the blocklist:" << file.errorString();
        return false;
    }

    QSet<QString> hosts;
    QDateTime updated;

    while (!file.atEnd()) {
        const QByteArray line = file.readLine().trimmed();

        if (line.startsWith(QByteArrayLiteral("# updated: "))) {
            updated = QDateTime::fromString(QString::fromUtf8(line.mid(11)), Qt::ISODate);
        } else if (!line.isEmpty() && !line.startsWith('#')) {
            hosts.insert(QString::fromUtf8(line));
        }
    }

    if (hosts.isEmpty()) {
        return false;
    }

    applyList(hosts, updated);
    return true;
}

void ThreatBlockManager::fetchList()
{
    {
        QMutexLocker lock(&m_mutex);

        if (m_updating) {
            return;
        }

        // A new attempt is under way: the previous attempt's error
        // stops being the last word (a success will clear it for
        // good, a failure replaces it) - while it runs, the surfaces
        // report the refresh in flight instead of a verdict.
        m_updating = true;
        m_lastError.clear();
    }

    // The attempt has begun: announced outside the mutex (a slot
    // may ask the state back through the self-locking queries), and
    // before the source is even validated - an attempt against an
    // invalid source is still an attempt, and the chrome's pulse
    // blinks once for it before updateFailed ends it. Emitted from
    // this one site only: every surface that wants to witness a
    // renewal from its start - the location bar's pulse, a menu
    // that stays open - hears it here.
    Q_EMIT updateStarted();

    const QUrl url(sourceUrl());

    if (!url.isValid() || (url.scheme() != QSL("https") && url.scheme() != QSL("http") && url.scheme() != QSL("file"))) {
        QString error;
        {
            QMutexLocker lock(&m_mutex);
            m_updating = false;
            m_lastError = tr("The blocklist source URL is not valid.");
            error = m_lastError;
        }
        Q_EMIT updateFailed(error);
        return;
    }

    if (!m_nam) {
        m_nam = new QNetworkAccessManager(this);
        m_nam->setProxy(QNetworkProxy::applicationProxy());
    }

    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    if (mApp->webProfile()) {
        request.setHeader(QNetworkRequest::UserAgentHeader, mApp->webProfile()->httpUserAgent());
    }

    m_reply = m_nam->get(request);

    connect(m_reply, &QNetworkReply::finished, this, [this]() {
        QString error;
        {
            QMutexLocker lock(&m_mutex);
            m_updating = false;
        }

        QNetworkReply *reply = m_reply;
        m_reply = nullptr;
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            error = reply->errorString();
        } else {
            const QByteArray data = reply->readAll();

            if (data.isEmpty()) {
                error = tr("The blocklist source returned no data.");
            } else {
                const int count = applyListData(data);

                if (count == 0) {
                    error = tr("The blocklist source did not contain any valid hosts.");
                } else {
                    qWarning() << "ThreatBlock: blocklist updated with" << count << "hosts";
                }
            }
        }

        // The failure is remembered, not just announced: the
        // interstitial and the padlock row answer for it long after
        // the signal has come and gone, until a retry succeeds.
        if (!error.isEmpty()) {
            {
                QMutexLocker lock(&m_mutex);
                m_lastError = error;
            }
            Q_EMIT updateFailed(error);
        }
    });
}

QString ThreatBlockManager::listFilePath() const
{
    return DataPaths::currentProfilePath() + QSL("/threatblock-hosts.txt");
}

QUrl ThreatBlockManager::blockPageUrl(const QUrl &blockedUrl, bool proceed)
{
    // The blocked URL is carried in a single fully percent-encoded
    // query value so that it survives the round trip byte-exactly;
    // a raw '&' can only be Osza's own separator.
    const QByteArray encoded = QUrl::toPercentEncoding(blockedUrl.toString());

    QString page = QSL("osza:threatblocked?url=") + QString::fromLatin1(encoded);

    if (proceed) {
        page += QSL("&proceed=1");
    }

    return QUrl(page);
}

QUrl ThreatBlockManager::blockedUrlFromPageUrl(const QUrl &pageUrl)
{
    if (pageUrl.scheme() != QSL("osza") || pageUrl.path() != QSL("threatblocked")) {
        return QUrl();
    }

    const QString encoded = pageUrl.toString(QUrl::FullyEncoded);
    const int index = encoded.indexOf(QSL("?url="));

    if (index < 0) {
        return QUrl();
    }

    QString value = encoded.mid(index + 5);
    const int separator = value.indexOf(QLatin1Char('&'));

    if (separator >= 0) {
        value.truncate(separator);
    }

    return QUrl(QUrl::fromPercentEncoding(value.toUtf8()));
}

bool ThreatBlockManager::isProceedPageUrl(const QUrl &pageUrl)
{
    return pageUrl.scheme() == QSL("osza")
        && pageUrl.path() == QSL("threatblocked")
        && pageUrl.toString(QUrl::FullyEncoded).endsWith(QSL("&proceed=1"));
}

QUrl ThreatBlockManager::refreshListPageUrl(const QUrl &blockedUrl)
{
    // The same single fully percent-encoded query value blockPageUrl
    // carries, with Osza's own separator - the interstitial's
    // "refresh now" action rides on the same round trip the "proceed
    // anyway" choice uses.
    const QByteArray encoded = QUrl::toPercentEncoding(blockedUrl.toString());

    return QUrl(QSL("osza:threatblocked?url=") + QString::fromLatin1(encoded) + QSL("&update=1"));
}

bool ThreatBlockManager::isRefreshListPageUrl(const QUrl &pageUrl)
{
    return pageUrl.scheme() == QSL("osza")
        && pageUrl.path() == QSL("threatblocked")
        && pageUrl.toString(QUrl::FullyEncoded).endsWith(QSL("&update=1"));
}

QString ThreatBlockManager::interstitialPage(const QUrl &blockedUrl) const
{
    static QString templatePage;

    if (templatePage.isEmpty()) {
        templatePage = QzTools::readAllFileContents(QSL(":html/threatblocked.html"));

        templatePage.replace(QLatin1String("%TITLE%"), tr("Dangerous site blocked"));
        templatePage.replace(QLatin1String("%HEADING%"), tr("Dangerous site blocked"));
        templatePage.replace(QLatin1String("%LEAD%"), tr("Osza stopped this page from loading."));
        templatePage.replace(QLatin1String("%EXPLAIN-1%"), tr("The site <b>%HOST%</b> is on a blocklist of known dangerous hosts. Attack sites try to install programs that steal private information, use your device to attack others, or damage your system."));
        templatePage.replace(QLatin1String("%EXPLAIN-2%"), tr("This protection is part of the Osza security tools. It can be turned off in Preferences &gt; Privacy &gt; Security tools."));
        templatePage.replace(QLatin1String("%WHY-LINK%"), tr("Why is this site flagged?"));
        templatePage.replace(QLatin1String("%BLOCKED-URL%"), tr("Blocked URL"));
        templatePage.replace(QLatin1String("%MATCH-ENTRY%"), tr("Matching entry"));
        templatePage.replace(QLatin1String("%SOURCE-LABEL%"), tr("Blocklist source"));
        templatePage.replace(QLatin1String("%LIST-STATE%"), tr("Blocklist"));
        templatePage.replace(QLatin1String("%BACK-LABEL%"), tr("Back to safety"));
        templatePage.replace(QLatin1String("%PROCEED-LABEL%"), tr("Proceed anyway (not recommended)"));
        templatePage.replace(QLatin1String("%PROCEED-WARN%"), tr("Visiting a dangerous site can harm your device. Only continue if you are certain this warning is wrong."));
    }

    QString page = templatePage;

    const QString host = blockedUrl.host().toHtmlEscaped();
    page.replace(QLatin1String("%HOST%"), host);
    page.replace(QLatin1String("%URL%"), blockedUrl.toDisplayString().toHtmlEscaped());

    // The "why is this site flagged?" answer: which entry of which
    // list flagged the site, read under the same lock as the list
    // state so the three rows describe one coherent snapshot of the
    // blocklist - never the decision of one refresh mixed with the
    // entries of another.
    const QString name = normalizeHost(blockedUrl.host());

    QString listInfo;
    QString matchInfo;
    QString sourceInfo;
    bool wantsRefresh = false;
    {
        QMutexLocker lock(&m_mutex);

        if (m_blockedHosts.isEmpty()) {
            listInfo = tr("not downloaded yet");
        } else {
            const QString count = QLocale().toString(m_blockedHosts.size());
            listInfo = tr("%1 hosts, updated %2", "number of hosts in the blocklist, last update time").arg(
                count,
                describeListAge(m_lastUpdate));

            // The movement the list in place arrived with, spoken
            // next to its size and age: how much the last refresh
            // changed the evidence this warning stands on. Only a
            // refresh that replaced a list has a movement to speak
            // (the first download and a restart's disk load arrive
            // with nothing to compare against - silence, not an
            // invented number); a refresh that changed nothing says
            // so, which is itself evidence. Read under the one lock
            // the whole snapshot already holds, like every state
            // this row reports.
            if (m_deltaValid) {
                if (m_lastDelta == 0) {
                    listInfo += tr(" (unchanged since the last refresh)");
                } else {
                    const QString movement = (m_lastDelta > 0 ? QSL("+") : QSL("-"))
                        + QLocale().toString(qAbs(m_lastDelta));
                    listInfo += tr(" (%1 hosts since the last refresh)", "host-count change the last refresh brought").arg(movement);
                }
            }
        }

        // The update lifecycle rides on the same row, read under the
        // same one lock: a refresh in flight (no action while one
        // runs), the last refresh's failure (the action says "try
        // again" in that state), and a list older than the refresh
        // interval - the same listIsStale() judgment the manager's
        // own timer refreshes through, spoken by the file-local
        // helper because the public isListStale() would take this
        // lock a second time. The blocked-URL-less states cannot be
        // reached through a real navigation (no list means nothing
        // is blocked), but a hand-crafted address still gets an
        // honest row.
        if (m_updating) {
            listInfo += tr(" - updating now");
        } else if (!m_lastError.isEmpty()) {
            listInfo += tr(" - the last update failed: %1").arg(m_lastError.toHtmlEscaped());
            wantsRefresh = true;
        } else if (m_blockedHosts.isEmpty() || listIsStale(m_lastUpdate)) {
            wantsRefresh = true;
        }

        // The entry that matched, and how it matched. The page can be
        // reached without a current match (a stale address reloaded
        // after a refresh, a hand-crafted osza: URL), and it must say
        // so rather than invent an entry.
        const QString entry = matchingEntry(name, m_blockedHosts);

        if (m_blockedHosts.isEmpty()) {
            matchInfo = tr("unknown (the blocklist is not loaded)");
        } else if (entry.isEmpty()) {
            matchInfo = tr("not on the current blocklist");
        } else if (entry == name) {
            matchInfo = tr("%1 (the host itself is on the list)", "matching blocklist entry, exact match").arg(entry.toHtmlEscaped());
        } else {
            matchInfo = tr("%1 (the visited host is a subdomain of this entry)", "matching blocklist entry, matched through a parent domain").arg(entry.toHtmlEscaped());
        }

        // The list the decision was made against, and where it came
        // from. Never empty: an unconfigured manager still protects
        // through the default source.
        sourceInfo = (m_sourceUrl.isEmpty() ? defaultSourceUrl() : m_sourceUrl).toHtmlEscaped();
    }

    // The "refresh now" action: an osza: address the scheme handler
    // answers by starting the refresh and re-serving this page, so
    // the evidence renews in place - wired like both ways out of the
    // page, not a script. The separator is escaped for the href
    // attribute; the blocked URL rides percent-encoded, so the
    // replace can only touch Osza's own '&'.
    if (wantsRefresh) {
        QString refreshHref = refreshListPageUrl(blockedUrl).toString(QUrl::FullyEncoded);
        refreshHref.replace(QLatin1Char('&'), QSL("&amp;"));
        listInfo += QSL(" <a href=\"%1\">%2</a>").arg(refreshHref, tr("Refresh the blocklist now").toHtmlEscaped());
    }

    page.replace(QLatin1String("%LIST-INFO%"), listInfo);
    page.replace(QLatin1String("%MATCH-INFO%"), matchInfo);
    page.replace(QLatin1String("%SOURCE-INFO%"), sourceInfo);

    page.replace(QLatin1String("%PROCEED-URL%"),
                 QString::fromLatin1(QUrl::toPercentEncoding(blockedUrl.toString())));
    page = QzTools::applyDirectionToPage(page);

    return page;
}

