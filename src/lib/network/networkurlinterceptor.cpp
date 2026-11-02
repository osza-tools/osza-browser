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
#include "networkurlinterceptor.h"
#include "urlinterceptor.h"
#include "settings.h"
#include "mainapplication.h"
#include "useragentmanager.h"

#include <QMutexLocker>
#include <QUrlQuery>

namespace {

/*
 * Query parameters that exist only to link a click/visit back to a
 * tracking campaign. They are never needed for the page to work, so
 * stripping them is safe; signed CDN URLs use different parameters.
 */
QStringList trackingParameterNames()
{
    return {
        // Google Analytics / Urchin
        QSL("utm_source"), QSL("utm_medium"), QSL("utm_campaign"),
        QSL("utm_term"), QSL("utm_content"), QSL("utm_id"),
        QSL("utm_source_platform"), QSL("utm_creative_format"),
        QSL("utm_marketing_tactic"), QSL("_ga"),
        // Platform click identifiers
        QSL("fbclid"), QSL("gclid"), QSL("gclsrc"), QSL("dclid"),
        QSL("gbraid"), QSL("wbraid"), QSL("msclkid"), QSL("twclid"),
        QSL("ttclid"), QSL("yclid"), QSL("igshid"), QSL("li_fat_id"),
        // Mail / marketing vendors
        QSL("mc_cid"), QSL("mc_eid"), QSL("_hsenc"), QSL("_hsmi"),
        QSL("vero_id"), QSL("vero_conv"), QSL("oly_anon_id"),
        QSL("oly_enc_id"), QSL("s_kwcid"), QSL("rb_clickid"),
        QSL("wickedid")
    };
}

} // namespace

NetworkUrlInterceptor::NetworkUrlInterceptor(QObject *parent)
    : QWebEngineUrlRequestInterceptor(parent)
    , m_sendDNT(false)
{
}

void NetworkUrlInterceptor::interceptRequest(QWebEngineUrlRequestInfo &info)
{
    QMutexLocker lock(&m_mutex);

    if (m_sendDNT) {
        info.setHttpHeader(QByteArrayLiteral("DNT"), QByteArrayLiteral("1"));
    }

    if (m_stripTrackingQuery) {
        const QUrl requestUrl = info.requestUrl();
        const QString scheme = requestUrl.scheme();
        if (scheme == QSL("http") || scheme == QSL("https")) {
            const QUrl stripped = stripTrackingParameters(requestUrl);
            if (stripped != requestUrl) {
                info.redirect(stripped);
                return;
            }
        }
    }

    const QString host = info.firstPartyUrl().host();

    if (m_usePerDomainUserAgent) {
        QString userAgent;
        if (m_userAgentsList.contains(host)) {
            userAgent = m_userAgentsList.value(host);
        } else {
            QHashIterator<QString, QString> i(m_userAgentsList);
            while (i.hasNext()) {
                i.next();
                if (host.endsWith(i.key())) {
                    userAgent = i.value();
                    break;
                }
            }
        }
        if (!userAgent.isEmpty()) {
            info.setHttpHeader(QByteArrayLiteral("User-Agent"), userAgent.toUtf8());
        }
    }

    for (UrlInterceptor *interceptor : std::as_const(m_interceptors)) {
        interceptor->interceptRequest(info);
    }
}

void NetworkUrlInterceptor::installUrlInterceptor(UrlInterceptor *interceptor)
{
    QMutexLocker lock(&m_mutex);

    if (!m_interceptors.contains(interceptor)) {
        m_interceptors.append(interceptor);
    }
}

void NetworkUrlInterceptor::removeUrlInterceptor(UrlInterceptor *interceptor)
{
    QMutexLocker lock(&m_mutex);

    m_interceptors.removeOne(interceptor);
}

QUrl NetworkUrlInterceptor::stripTrackingParameters(const QUrl &url) const
{
    QUrlQuery query(url);
    if (query.isEmpty()) {
        return url;
    }

    bool changed = false;

    for (const QString &name : trackingParameterNames()) {
        while (query.hasQueryItem(name)) {
            query.removeQueryItem(name);
            changed = true;
        }
    }

    if (!changed) {
        return url;
    }

    QUrl stripped = url;
    stripped.setQuery(query);

    return stripped;
}

void NetworkUrlInterceptor::loadSettings()
{
    QMutexLocker lock(&m_mutex);

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    m_sendDNT = settings.value(QSL("DoNotTrack"), false).toBool();
    m_stripTrackingQuery = settings.value(QSL("StripTrackingQuery"), true).toBool();
    settings.endGroup();

    m_usePerDomainUserAgent = mApp->userAgentManager()->usePerDomainUserAgents();
    m_userAgentsList = mApp->userAgentManager()->perDomainUserAgentsList();
}
