/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2015-2018 David Rosca <nowrep@gmail.com>
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

#ifndef NETWORKURLINTERCEPTOR_H
#define NETWORKURLINTERCEPTOR_H

#include <QMutex>
#include <QStringList>
#include <QWebEngineUrlRequestInterceptor>
#include <QUrl>

#include "qzcommon.h"

class UrlInterceptor;

class OSZA_EXPORT NetworkUrlInterceptor : public QWebEngineUrlRequestInterceptor
{
public:
    explicit NetworkUrlInterceptor(QObject* parent = nullptr);

    void interceptRequest(QWebEngineUrlRequestInfo &info) Q_DECL_OVERRIDE;

    void installUrlInterceptor(UrlInterceptor *interceptor);
    void removeUrlInterceptor(UrlInterceptor *interceptor);

    void loadSettings();

    // The cross-site judgment of the referrer guard: whether a
    // request from "referrer" to "target" stays inside one site -
    // same scheme with the same host, or with two hosts of one
    // domain family (a.com and sub.a.com, either side either way;
    // ports are not compared - a port shuffle is one site's own
    // arrangement). A scheme mismatch is never same-site, a
    // downgrade (https page, http destination) least of all.
    static bool isSameSite(const QUrl &referrer, const QUrl &target);

    // The referrer origin the OriginOnly mode sends: scheme, host
    // and port, with an empty path and nothing else - the site's
    // address, never its URLs.
    static QString referrerOrigin(const QUrl &referrer);

private:
    QUrl stripTrackingParameters(const QUrl &url) const;

    // True when the host matches an entry of the GPC exclusion
    // list: the entry host itself, any of its subdomains, or a
    // "*.domain" wildcard entry - the same matching the GpcManager
    // applies to frames.
    static bool hostMatchesExclusionEntry(const QString &host, const QString &entry);

    // The exclusion check for interceptRequest(), called with the
    // mutex already held (the IO thread path).
    bool gpcHostExcludedLocked(const QString &host) const;

    // The referrer guard's exclusion check for interceptRequest(),
    // called with the mutex already held. Same entry matching as
    // the GPC half, but anchored on the referrer's host - the site
    // whose URLs would leak.
    bool referrerGuardHostExcludedLocked(const QString &host) const;

    // The cross-site referrer rewrite, called with the mutex
    // already held. Reads the request's real Referer header and
    // only ever touches requests that already carry one, so the
    // guard can never introduce a referrer where the engine sent
    // none.
    void applyReferrerGuardLocked(QWebEngineUrlRequestInfo &info) const;

    QMutex m_mutex;
    QList<UrlInterceptor*> m_interceptors;
    bool m_sendDNT = false;
    bool m_sendGPC = true;
    QStringList m_gpcExclusions;
    int m_referrerGuardMode = 1; // ReferrerGuardManager::OriginOnly
    QStringList m_referrerGuardExclusions;
    bool m_usePerDomainUserAgent = false;
    bool m_stripTrackingQuery = true;
    QHash<QString, QString> m_userAgentsList;
};

#endif // NETWORKURLINTERCEPTOR_H
