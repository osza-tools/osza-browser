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
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#include "cookielifecyclemanager.h"
#include "cookiejar.h"
#include "mainapplication.h"
#include "securitymanager.h"
#include "settings.h"

#include <QNetworkCookie>
#include <QTimer>

namespace {

// The engine delivers the persisted cookies shortly after the jar's
// loadAllCookies() - well inside this grace period, which starts when
// loadSettings() runs at startup. Long enough that the snapshot is
// never taken before the disk's own cookies arrive, short enough that
// a first page's fresh cookies still land after it (they belong to
// the session, and SessionOnly says so).
const int kSnapshotDelayMs = 10000;

}

Q_GLOBAL_STATIC(CookieLifecycleManager, qz_cookie_lifecycle_manager)

CookieLifecycleManager::CookieLifecycleManager(QObject *parent)
    : QObject(parent)
    , m_mode(Off)
    , m_keepSites()
{
}

CookieLifecycleManager *CookieLifecycleManager::instance()
{
    return qz_cookie_lifecycle_manager();
}

void CookieLifecycleManager::loadSettings()
{
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    const int mode = settings.value(QSL("CookieLifecycleMode"), static_cast<int>(Off)).toInt();
    m_keepSites = settings.value(QSL("CookieKeepSites"), QStringList()).toStringList();
    settings.endGroup();

    // A corrupted value lands on the tool's honest default - off -
    // never on an unknown mode: unlike the referrer guard, the
    // out-of-the-box strength of an exit sweep is "not enabled",
    // because the sweep ends sessions on exit and that is a choice,
    // not a floor every page is already standing on.
    if (mode >= Off && mode <= ClearOnExit) {
        m_mode = static_cast<Mode>(mode);
    } else {
        m_mode = Off;
    }

    // The startup snapshot, once per process, whatever the mode is
    // right now: the mode can be switched on later in the session,
    // and the snapshot still describes what existed at startup. A
    // private window's profile keeps nothing, so there is nothing
    // worth remembering (and no sweep will ever run there -
    // MainApplication::saveSettings() returns before it).
    if (!m_snapshotScheduled && !m_snapshotTaken && mApp && !mApp->isPrivate()) {
        m_snapshotScheduled = true;
        QTimer::singleShot(kSnapshotDelayMs, this, &CookieLifecycleManager::takeStartupSnapshot);
    }
}

CookieLifecycleManager::Mode CookieLifecycleManager::mode() const
{
    return m_mode;
}

void CookieLifecycleManager::setMode(Mode mode)
{
    if (m_mode == mode) {
        return;
    }

    m_mode = mode;

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("CookieLifecycleMode"), static_cast<int>(mode));
        settings.endGroup();
    }

    Q_EMIT modeChanged(mode);
}

bool CookieLifecycleManager::isEnabled() const
{
    return m_mode != Off;
}

bool CookieLifecycleManager::isKept(const QString &cookieDomain) const
{
    // The cookie's domain arrives as the site spelled it - ".example.com"
    // or "example.com" - and the keep-list speaks hosts, so the leading
    // dot the cookie grammar allows is dropped before the suite's own
    // matching runs.
    QString host = cookieDomain.trimmed().toLower();

    if (host.startsWith(QLatin1Char('.'))) {
        host.remove(0, 1);
    }

    if (host.isEmpty()) {
        return false;
    }

    for (const QString &entry : m_keepSites) {
        if (hostMatchesEntry(host, entry)) {
            return true;
        }
    }

    return false;
}

QStringList CookieLifecycleManager::keepSites() const
{
    return m_keepSites;
}

void CookieLifecycleManager::addKeepSite(const QString &host)
{
    const QString trimmed = host.trimmed().toLower();

    if (trimmed.isEmpty()) {
        return;
    }

    if (!m_keepSites.contains(trimmed, Qt::CaseInsensitive)) {
        m_keepSites.append(trimmed);
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("CookieKeepSites"), m_keepSites);
    settings.endGroup();

    Q_EMIT keepSitesChanged();
}

void CookieLifecycleManager::removeKeepSite(const QString &host)
{
    const QString trimmed = host.trimmed().toLower();

    if (trimmed.isEmpty()) {
        return;
    }

    for (int i = m_keepSites.size() - 1; i >= 0; --i) {
        if (m_keepSites.at(i).trimmed().compare(trimmed, Qt::CaseInsensitive) == 0) {
            m_keepSites.removeAt(i);
        }
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("CookieKeepSites"), m_keepSites);
    settings.endGroup();

    Q_EMIT keepSitesChanged();
}

void CookieLifecycleManager::setKeepSites(const QStringList &hosts)
{
    m_keepSites.clear();

    for (const QString &host : hosts) {
        const QString trimmed = host.trimmed().toLower();

        if (!trimmed.isEmpty() && !m_keepSites.contains(trimmed, Qt::CaseInsensitive)) {
            m_keepSites.append(trimmed);
        }
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("CookieKeepSites"), m_keepSites);
    settings.endGroup();

    Q_EMIT keepSitesChanged();
}

bool CookieLifecycleManager::sweepsAtExit(const QNetworkCookie &cookie) const
{
    if (m_mode == Off) {
        return false;
    }

    // A session cookie dies with the browser anyway; deleting it
    // would claim a removal that was never this tool's doing.
    if (cookie.expirationDate().isNull()) {
        return false;
    }

    if (isKept(cookie.domain())) {
        return false;
    }

    // The session strength keeps what the browser started with: a
    // cookie already present at startup survives, only the ones this
    // session picked up go.
    if (m_mode == SessionOnly && m_startupSnapshot.contains(cookieKey(cookie))) {
        return false;
    }

    return true;
}

void CookieLifecycleManager::takeStartupSnapshot()
{
    // Once per process, whatever called it: the timer's own firing
    // and the autotest's direct call describe the same moment - what
    // existed at startup - and re-taking it mid-session would turn
    // "this session's cookies" into "the last ten minutes'".
    if (m_snapshotTaken || !mApp) {
        return;
    }

    m_snapshotTaken = true;

    if (!mApp->cookieJar()) {
        return;
    }

    const QVector<QNetworkCookie> cookies = mApp->cookieJar()->getAllCookies();

    for (const QNetworkCookie &cookie : cookies) {
        // Only persistent cookies can outlive the exit; a session
        // cookie is not something the sweep will ever have to judge.
        if (!cookie.expirationDate().isNull()) {
            m_startupSnapshot.insert(cookieKey(cookie));
        }
    }
}

bool CookieLifecycleManager::hasStartupSnapshot() const
{
    return m_snapshotTaken;
}

quint64 CookieLifecycleManager::performExitSweep(CookieJar *jar)
{
    if (m_mode == Off || !jar) {
        return 0;
    }

    quint64 swept = 0;
    const QVector<QNetworkCookie> cookies = jar->getAllCookies();

    for (const QNetworkCookie &cookie : cookies) {
        if (!sweepsAtExit(cookie)) {
            continue;
        }

        // The same asynchronous store call the Cookie Manager's own
        // delete-on-close and the cookie dialog's per-cookie removal
        // use; the deletions are on their way to the engine before
        // the profile is torn down.
        jar->deleteCookie(cookie);
        ++swept;
    }

    if (swept > 0) {
        SecurityManager::instance()->reportCookiesSwept(swept);
    }

    return swept;
}

bool CookieLifecycleManager::hostMatchesEntry(const QString &host, const QString &entry)
{
    const QString trimmed = entry.trimmed();

    if (trimmed.isEmpty() || host.isEmpty()) {
        return false;
    }

    // Wildcard pattern: *.example.com matches every subdomain.
    if (trimmed.startsWith(QSL("*"))) {
        return host.endsWith(trimmed.mid(1), Qt::CaseInsensitive);
    }

    // Exact host or any subdomain of the entry: example.com matches
    // example.com and www.example.com. The same matcher the
    // referrer guard and the GPC exceptions apply, so a host means
    // one thing everywhere in the suite.
    return host.compare(trimmed, Qt::CaseInsensitive) == 0
        || host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive);
}

QString CookieLifecycleManager::cookieKey(const QNetworkCookie &cookie)
{
    // The identity of a cookie slot: its name, its domain and its
    // path. A cookie whose value is refreshed mid-session is still
    // the cookie that existed at startup - the slot, not the value,
    // is what SessionOnly judges. Domains are case-insensitive;
    // names and paths are not.
    return QString::fromUtf8(cookie.name())
        + QLatin1Char('|')
        + cookie.domain().toLower()
        + QLatin1Char('|')
        + cookie.path();
}
