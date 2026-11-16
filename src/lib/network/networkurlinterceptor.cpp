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
#include "securitymanager.h"
#include "referrerguardmanager.h"
#include "settings.h"
#include "mainapplication.h"
#include "useragentmanager.h"

#include <QtWebEngineCoreVersion>

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
    , m_sendGPC(true)
{
}

void NetworkUrlInterceptor::interceptRequest(QWebEngineUrlRequestInfo &info)
{
    QMutexLocker lock(&m_mutex);

    if (m_sendDNT) {
        info.setHttpHeader(QByteArrayLiteral("DNT"), QByteArrayLiteral("1"));
    }

    // Global Privacy Control: the network half of the signal (the DOM
    // half is navigator.globalPrivacyControl, installed by GpcManager).
    // Sent with every request, navigations and subresources alike, as
    // the GPC specification requires - except to the hosts the user
    // excluded from the signal, where the request's own target host
    // decides. That anchor keeps the exclusion as narrow as the choice
    // it expresses: while browsing an excluded site, every request to
    // every other host still carries the opt-out, and the excluded
    // host's own servers stop seeing it - the same host set whose
    // frames GpcManager leaves untouched.
    if (m_sendGPC && !gpcHostExcludedLocked(info.requestUrl().host())) {
        info.setHttpHeader(QByteArrayLiteral("Sec-GPC"), QByteArrayLiteral("1"));
    }

    if (m_stripTrackingQuery) {
        const QUrl requestUrl = info.requestUrl();
        const QString scheme = requestUrl.scheme();
        if (scheme == QSL("http") || scheme == QSL("https")) {
            const QUrl stripped = stripTrackingParameters(requestUrl);
            if (stripped != requestUrl) {
                info.redirect(stripped);
                SecurityManager::instance()->reportTrackerStripped(requestUrl.host());
                return;
            }
        }
    }

    /*
     * Cross-site referrer protection: the header half of the tool
     * (the mode and the exceptions live in ReferrerGuardManager,
     * this is the IO-thread copy). It runs only when the build's
     * QtWebEngine can expose the request's headers (6.5+); an older
     * engine keeps the tool off everywhere, which loadSettings()
     * and the manager's isSupported() already agree on.
     */
#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    if (m_referrerGuardMode != 0) { // ReferrerGuardManager::Off
        applyReferrerGuardLocked(info);
    }
#endif

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
    m_sendGPC = settings.value(QSL("GlobalPrivacyControl"), true).toBool();
    m_gpcExclusions = settings.value(QSL("GpcExclusions"), QStringList()).toStringList();
    m_stripTrackingQuery = settings.value(QSL("StripTrackingQuery"), true).toBool();

    // The IO-thread copy of the referrer guard's state. The mode is
    // stored with the ReferrerGuardManager's enum values and read
    // through a copy of its numeric range check, so a corrupted
    // setting can only ever land on a known mode (never an
    // out-of-range value the rewrite would have to guess about),
    // and the guard is never active on an engine that cannot run
    // it (the version check in interceptRequest() mirrors the one
    // ReferrerGuardManager::isSupported() answers).
    m_referrerGuardMode = settings.value(QSL("ReferrerGuardMode"), 1).toInt();
    if (m_referrerGuardMode < 0 || m_referrerGuardMode > 2) {
        m_referrerGuardMode = 1;
    }
    m_referrerGuardExclusions = settings.value(QSL("ReferrerGuardExclusions"), QStringList()).toStringList();
    settings.endGroup();

    m_usePerDomainUserAgent = mApp->userAgentManager()->usePerDomainUserAgents();
    m_userAgentsList = mApp->userAgentManager()->perDomainUserAgentsList();
}

bool NetworkUrlInterceptor::gpcHostExcludedLocked(const QString &host) const
{
    const QString normalized = host.trimmed();

    if (normalized.isEmpty()) {
        return false;
    }

    for (const QString &entry : m_gpcExclusions) {
        if (hostMatchesExclusionEntry(normalized, entry)) {
            return true;
        }
    }

    return false;
}

bool NetworkUrlInterceptor::hostMatchesExclusionEntry(const QString &host, const QString &entry)
{
    const QString trimmed = entry.trimmed();

    if (trimmed.isEmpty() || host.isEmpty()) {
        return false;
    }

    // Wildcard pattern: *.example.com matches every subdomain.
    if (trimmed.startsWith(QSL("*"))) {
        return host.endsWith(trimmed.mid(1), Qt::CaseInsensitive);
    }

    // Exact host or any subdomain of the entry.
    return host.compare(trimmed, Qt::CaseInsensitive) == 0
        || host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive);
}

bool NetworkUrlInterceptor::referrerGuardHostExcludedLocked(const QString &host) const
{
    const QString normalized = host.trimmed();

    if (normalized.isEmpty()) {
        return false;
    }

    for (const QString &entry : m_referrerGuardExclusions) {
        if (hostMatchesExclusionEntry(normalized, entry)) {
            return true;
        }
    }

    return false;
}

#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 5, 0)
void NetworkUrlInterceptor::applyReferrerGuardLocked(QWebEngineUrlRequestInfo &info) const
{
    /*
     * The cross-site referrer rewrite. Everything the guard does is
     * derived from the request's own Referer header - the one value
     * that says where the request really comes from:
     *
     *  - a request with no Referer keeps having none: the guard
     *    never introduces a referrer, whatever the site declared;
     *  - a referrer the exception list covers (the site whose URLs
     *    would leak) keeps whatever the site's own policy sends;
     *  - a request staying inside one site (same origin, or a
     *    domain family on the same scheme) keeps its referrer too -
     *    the site is only telling itself where you were;
     *  - everything else is a request to another site, and it
     *    carries at most the referrer's address (OriginOnly) or
     *    nothing (NoReferrer) - never the URL of the page you were
     *    reading, whatever "unsafe-url" the page declared.
     *
     * Setting the header to an empty value is how the value is
     * removed: QtWebEngine forwards the override into the engine's
     * own referrer field, and an empty referrer means no header
     * leaves the browser.
     */

    const QUrl target = info.requestUrl();
    const QString targetScheme = target.scheme();

    if (targetScheme != QSL("http") && targetScheme != QSL("https")) {
        return;
    }

    // The request's real Referer, read through the same header map
    // the setter writes to. QtWebEngine plants the engine's referrer
    // into it whenever the request carries one, so absence is the
    // engine's own "no referrer" - and the guard stops there.
    const QByteArray refererValue = info.httpHeaders().value(QByteArrayLiteral("Referer"));

    if (refererValue.isEmpty()) {
        return;
    }

    const QUrl referrer = QUrl(QString::fromUtf8(refererValue));

    if (!referrer.isValid()) {
        return;
    }

    const QString referrerScheme = referrer.scheme();

    if (referrerScheme != QSL("http") && referrerScheme != QSL("https")) {
        return;
    }

    if (referrer.host().isEmpty()) {
        return;
    }

    if (referrerGuardHostExcludedLocked(referrer.host())) {
        return;
    }

    if (isSameSite(referrer, target)) {
        return;
    }

    // A downgrade (https page, http destination) always clears,
    // in both modes: the engine's own policies send nothing on a
    // downgrade, so the guard never sends more than they would -
    // not even the site's address.
    const bool downgrade = referrerScheme == QSL("https") && targetScheme == QSL("http");

    if (downgrade || m_referrerGuardMode == 2) { // ReferrerGuardManager::NoReferrer
        info.setHttpHeader(QByteArrayLiteral("Referer"), QByteArrayLiteral(""));
    } else {
        info.setHttpHeader(QByteArrayLiteral("Referer"), referrerOrigin(referrer).toUtf8());
    }

    // Counted against the site whose URLs just stopped leaking.
    SecurityManager::instance()->reportReferrerTrimmed(referrer.host());
}
#endif

bool NetworkUrlInterceptor::isSameSite(const QUrl &referrer, const QUrl &target)
{
    // A referrer never survives a scheme downgrade: https pages
    // sending an http request lose the referrer entirely, whatever
    // the hosts are - the engine's own default policies agree, and
    // the guard never keeps more than they would.
    const QString referrerScheme = referrer.scheme();
    const QString targetScheme = target.scheme();

    if (referrerScheme == QSL("https") && targetScheme == QSL("http")) {
        return false;
    }

    if (referrerScheme != targetScheme) {
        return false;
    }

    const QString referrerHost = referrer.host();
    const QString targetHost = target.host();

    if (referrerHost.isEmpty() || targetHost.isEmpty()) {
        return false;
    }

    // Same host, or two hosts of one domain family (a.com and
    // sub.a.com, either side either way): the site telling itself
    // where you were. The dot boundary keeps unrelated hosts apart
    // (a.com and nota.com are different sites).
    if (referrerHost.compare(targetHost, Qt::CaseInsensitive) == 0) {
        return true;
    }

    if (referrerHost.endsWith(QSL(".") + targetHost, Qt::CaseInsensitive)
        || targetHost.endsWith(QSL(".") + referrerHost, Qt::CaseInsensitive)) {
        return true;
    }

    // Ports never enter the judgment: the host comparisons above
    // already decided "one site" for every port shuffle of the same
    // host family, so what is left here is only ever another site.
    return false;
}

QString NetworkUrlInterceptor::referrerOrigin(const QUrl &referrer)
{
    // The site's address: scheme, host, explicit port, empty path.
    QUrl origin;
    origin.setScheme(referrer.scheme());
    origin.setHost(referrer.host());

    const int port = referrer.port(-1);

    if (port != -1) {
        origin.setPort(port);
    }

    origin.setPath(QSL("/"));

    return origin.toString();
}
