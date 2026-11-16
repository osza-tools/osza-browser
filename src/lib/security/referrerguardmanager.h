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
#ifndef REFERRERGUARDMANAGER_H
#define REFERRERGUARDMANAGER_H

#include <QObject>
#include <QStringList>

#include "qzcommon.h"

/*
 * Cross-site referrer protection, the UI-thread half of the tool.
 *
 * A Referer header tells the receiving site where the request came
 * from - and under a page's own "unsafe-url" policy that is the full
 * URL of the page you were reading, path and query included. The
 * engine's default policy already keeps cross-site referrers down to
 * the site's address; a page can opt into sending more, and the
 * reader of a link click has no way to notice. This tool makes the
 * limit a floor no page can lower, in two strengths:
 *
 *   OriginOnly - requests to another site carry at most the site's
 *                address (scheme, host, port), never its URLs;
 *   NoReferrer - requests to another site carry no referrer at all.
 *
 * The rewrite itself runs in NetworkUrlInterceptor on the WebEngine
 * IO thread, on the real Referer header of the real request (read
 * through QWebEngineUrlRequestInfo::httpHeaders(), QtWebEngine 6.5+),
 * so the tool never introduces a referrer where the engine sent none
 * and never fabricates one. This manager owns the persisted state -
 * the mode and the per-site exceptions - and every change callers
 * make here is followed by mApp->networkManager()->loadSettings(),
 * which reloads the interceptor's IO-thread copy of the same keys.
 *
 * Exclusions are anchored on the site whose URLs would leak - the
 * referrer's host: while you are on an excluded site, its outgoing
 * requests keep whatever referrer the site's own policy sends. The
 * entries match the listed host and its subdomains; "*.domain"
 * wildcards are supported, like the fingerprint and HTTPS-Only
 * exceptions.
 */
class OSZA_EXPORT ReferrerGuardManager : public QObject
{
    Q_OBJECT

public:
    enum Mode {
        Off = 0,
        OriginOnly = 1,
        NoReferrer = 2
    };

    static ReferrerGuardManager *instance();

    explicit ReferrerGuardManager(QObject *parent = nullptr);

    void loadSettings();

    // Whether this build can run the tool at all: the rewrite reads
    // the request's headers, which the interceptor API only exposes
    // since QtWebEngine 6.5. On older engines the UI stays honest
    // (the switch is disabled with a version note) and the porter
    // skips the section with that reason.
    static bool isSupported();

    Mode mode() const;
    void setMode(Mode mode);

    bool isEnabled() const;

    // The per-site exclusions, persisted like the GPC exceptions.
    // Callers that change the list refresh the network stack
    // (mApp->networkManager()->loadSettings()) so the IO-thread
    // half follows at once.
    bool isExcluded(const QString &host) const;
    QStringList exclusions() const;
    void addExclusion(const QString &host);
    void removeExclusion(const QString &host);

    // Replaces the whole list (the settings porter's import path:
    // the document's list is the complete effective list after the
    // import). Persists.
    void setExclusions(const QStringList &hosts);

Q_SIGNALS:
    void modeChanged(ReferrerGuardManager::Mode mode);
    void exclusionsChanged();

private:
    static bool hostMatchesEntry(const QString &host, const QString &entry);

    Mode m_mode = OriginOnly;
    QStringList m_exclusions;
};

#endif // REFERRERGUARDMANAGER_H
