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
#ifndef COOKIELIFECYCLEMANAGER_H
#define COOKIELIFECYCLEMANAGER_H

#include <QSet>
#include <QString>
#include <QStringList>
#include <QObject>

#include "qzcommon.h"

class CookieJar;
class QNetworkCookie;

/*
 * Cookie lifecycle on exit, the ninth bundled security tool.
 *
 * A cookie is the one tracker built to outlive the session that
 * created it: a site leaves a persistent cookie behind and the next
 * launch hands your identity back to whoever reads it. The Cookie
 * Manager's own "delete cookies on close" answers with one all-or-
 * nothing pass; this tool gives the exit discipline the suite's
 * shape - a mode, a keep-list with the suite's host matching, and a
 * per-site decision one click away in the padlock menu, in two
 * strengths:
 *
 *   SessionOnly   - at exit, delete the persistent cookies that were
 *                   NOT already present when this browser started.
 *                   The logins you arrived with survive; the crumbs
 *                   this session picked up (including new logins) go;
 *   ClearOnExit   - at exit, delete every persistent cookie except
 *                   those anchored on the kept sites.
 *
 * Only persistent cookies are ever swept, and only the sweep's own
 * deletions are counted: a session cookie (no expiry) dies with the
 * browser anyway, so deleting or counting it would be a claim the
 * tool did not earn. The sweep runs once, from
 * MainApplication::saveSettings() - which already returns early for
 * private windows, whose profile keeps nothing anyway - before the
 * Cookie Manager's own delete-on-close pass, so the counter speaks
 * about exactly the cookies this tool removed itself; the two
 * passes compose the way any two deletions compose (the stricter
 * outcome wins, and a kept site's cookies survive the Cookie
 * Manager's pass only when that pass itself keeps them).
 *
 * The keep-list is anchored on the site whose cookies survive - the
 * cookie's own domain. Entries match the listed host and its
 * subdomains; "*.domain" wildcards are supported, like every other
 * exception list in the suite.
 *
 * SessionOnly needs to know which cookies existed when the browser
 * started. The engine delivers the persisted cookies shortly after
 * launch (the jar's loadAllCookies()), so the manager snapshots the
 * persistent cookies' identities once, a grace period after
 * loadSettings() runs - whatever mode is active at that moment,
 * because the mode can be switched on later and the snapshot
 * describes a fact about the session, not about a setting. The
 * snapshot is never persisted: it describes this process, and a
 * browser that never exits never sweeps.
 */
class OSZA_EXPORT CookieLifecycleManager : public QObject
{
    Q_OBJECT

public:
    enum Mode {
        Off = 0,
        SessionOnly = 1,
        ClearOnExit = 2
    };

    static CookieLifecycleManager *instance();

    explicit CookieLifecycleManager(QObject *parent = nullptr);

    void loadSettings();

    Mode mode() const;
    void setMode(Mode mode);

    bool isEnabled() const;

    // The kept sites, persisted like the other tools' exception
    // lists. There is no IO-thread half to refresh: the sweep reads
    // the manager at exit, on the GUI thread, so a change here is
    // simply in force the next time the sweep runs.
    bool isKept(const QString &cookieDomain) const;
    QStringList keepSites() const;
    void addKeepSite(const QString &host);
    void removeKeepSite(const QString &host);

    // Replaces the whole list (the settings porter's import path:
    // the document's list is the complete effective list after the
    // import). Persists.
    void setKeepSites(const QStringList &hosts);

    // The one judgment the sweep is made of, exposed for the
    // autotest: would this cookie be deleted at exit, given the mode,
    // the keep-list and the startup snapshot in force right now?
    bool sweepsAtExit(const QNetworkCookie &cookie) const;

    // Records which persistent cookies exist at this moment (the
    // startup snapshot; scheduled by loadSettings(), callable
    // directly by the autotest). Once taken, a snapshot is never
    // retaken - it describes what existed when the browser started.
    void takeStartupSnapshot();

    // Whether the startup snapshot has been taken yet.
    bool hasStartupSnapshot() const;

    // The exit sweep itself. Walks the jar's cookies, deletes
    // through CookieJar::deleteCookie() - the same asynchronous
    // store call the Cookie Manager's own delete-on-close and the
    // per-cookie removal in the cookie dialog use - and reports the
    // number of cookies removed to the security dashboard's totals.
    // Returns the number swept.
    quint64 performExitSweep(CookieJar *jar);

Q_SIGNALS:
    void modeChanged(CookieLifecycleManager::Mode mode);
    void keepSitesChanged();

private:
    static bool hostMatchesEntry(const QString &host, const QString &entry);
    static QString cookieKey(const QNetworkCookie &cookie);

    Mode m_mode = Off;
    QStringList m_keepSites;

    bool m_snapshotScheduled = false;
    bool m_snapshotTaken = false;
    QSet<QString> m_startupSnapshot;
};

#endif // COOKIELIFECYCLEMANAGER_H
