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

} // namespace

ThreatBlockManager::ThreatBlockManager(QObject *parent)
    : QObject(parent)
    , m_enabled(true)
    , m_nam(nullptr)
    , m_reply(nullptr)
    , m_updating(false)
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
    return m_updating;
}

bool ThreatBlockManager::isHostBlocked(const QString &host) const
{
    QString name = normalizeHost(host);

    if (name.isEmpty()) {
        return false;
    }

    QMutexLocker lock(&m_mutex);

    if (m_blockedHosts.isEmpty()) {
        return false;
    }

    if (m_blockedHosts.contains(name)) {
        return true;
    }

    // Subdomains of a listed host belong to the same operator; the
    // dot boundary keeps "evilbad.example" from matching "bad.example".
    for (;;) {
        const int dot = name.indexOf(QLatin1Char('.'));
        if (dot < 0 || dot + 1 >= name.size()) {
            return false;
        }
        name = name.mid(dot + 1);
        if (m_blockedHosts.contains(name)) {
            return true;
        }
    }
}

bool ThreatBlockManager::shouldBlock(const QString &host) const
{
    QString name = normalizeHost(host);

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

    if (m_blockedHosts.contains(name)) {
        return true;
    }

    // Subdomains of a listed host belong to the same operator; the
    // dot boundary keeps "evilbad.example" from matching "bad.example".
    for (;;) {
        const int dot = name.indexOf(QLatin1Char('.'));
        if (dot < 0 || dot + 1 >= name.size()) {
            return false;
        }
        name = name.mid(dot + 1);
        if (m_blockedHosts.contains(name)) {
            return true;
        }
    }
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
    QString name = host;

    if (m_sessionAllowed.contains(name)) {
        return true;
    }

    // The exception covers subdomains of the allowed host as well.
    for (;;) {
        const int dot = name.indexOf(QLatin1Char('.'));
        if (dot < 0 || dot + 1 >= name.size()) {
            return false;
        }
        name = name.mid(dot + 1);
        if (m_sessionAllowed.contains(name)) {
            return true;
        }
    }
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
    QDateTime updated;
    int count = 0;

    {
        QMutexLocker lock(&m_mutex);
        updated = m_lastUpdate;
        count = m_blockedHosts.size();
    }

    const bool stale = !updated.isValid() || updated.msecsTo(QDateTime::currentDateTimeUtc()) > kRefreshIntervalMs;

    if (count == 0 || stale) {
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
    if (m_updating) {
        return;
    }

    const QUrl url(sourceUrl());

    if (!url.isValid() || (url.scheme() != QSL("https") && url.scheme() != QSL("http") && url.scheme() != QSL("file"))) {
        Q_EMIT updateFailed(tr("The blocklist source URL is not valid."));
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

    m_updating = true;
    m_reply = m_nam->get(request);

    connect(m_reply, &QNetworkReply::finished, this, [this]() {
        m_updating = false;

        QNetworkReply *reply = m_reply;
        m_reply = nullptr;
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            Q_EMIT updateFailed(reply->errorString());
            return;
        }

        const QByteArray data = reply->readAll();

        if (data.isEmpty()) {
            Q_EMIT updateFailed(tr("The blocklist source returned no data."));
            return;
        }

        const int count = applyListData(data);

        if (count == 0) {
            Q_EMIT updateFailed(tr("The blocklist source did not contain any valid hosts."));
            return;
        }

        qWarning() << "ThreatBlock: blocklist updated with" << count << "hosts";
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
        templatePage.replace(QLatin1String("%DETAILS-HEADING%"), tr("Details"));
        templatePage.replace(QLatin1String("%BLOCKED-URL%"), tr("Blocked URL"));
        templatePage.replace(QLatin1String("%LIST-STATE%"), tr("Blocklist"));
        templatePage.replace(QLatin1String("%BACK-LABEL%"), tr("Back to safety"));
        templatePage.replace(QLatin1String("%PROCEED-LABEL%"), tr("Proceed anyway (not recommended)"));
        templatePage.replace(QLatin1String("%PROCEED-WARN%"), tr("Visiting a dangerous site can harm your device. Only continue if you are certain this warning is wrong."));
    }

    QString page = templatePage;

    const QString host = blockedUrl.host().toHtmlEscaped();
    page.replace(QLatin1String("%HOST%"), host);
    page.replace(QLatin1String("%URL%"), blockedUrl.toDisplayString().toHtmlEscaped());

    QString listInfo;
    {
        QMutexLocker lock(&m_mutex);

        if (m_blockedHosts.isEmpty()) {
            listInfo = tr("not downloaded yet");
        } else {
            const QString count = QLocale().toString(m_blockedHosts.size());
            listInfo = tr("%1 hosts, updated %2", "number of hosts in the blocklist, last update time").arg(
                count,
                m_lastUpdate.isValid() ? QLocale().toString(m_lastUpdate.toLocalTime(), QLocale::ShortFormat) : tr("unknown date"));
        }
    }
    page.replace(QLatin1String("%LIST-INFO%"), listInfo);

    page.replace(QLatin1String("%PROCEED-URL%"),
                 QString::fromLatin1(QUrl::toPercentEncoding(blockedUrl.toString())));
    page = QzTools::applyDirectionToPage(page);

    return page;
}

