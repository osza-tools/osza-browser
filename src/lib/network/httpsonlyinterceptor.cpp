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
#include "httpsonlyinterceptor.h"
#include "settings.h"

#include <QHostAddress>
#include <QMutexLocker>
#include <QUrl>

HttpsOnlyInterceptor::HttpsOnlyInterceptor(QObject *parent)
    : UrlInterceptor(parent)
    , m_enabled(false)
{
}

void HttpsOnlyInterceptor::loadSettings()
{
    QMutexLocker lock(&m_mutex);

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    m_enabled = settings.value(QSL("HttpsOnlyMode"), false).toBool();
    m_exclusions = settings.value(QSL("HttpsOnlyExclusions"), QStringList()).toStringList();
    settings.endGroup();
}

void HttpsOnlyInterceptor::interceptRequest(QWebEngineUrlRequestInfo &request)
{
    QMutexLocker lock(&m_mutex);

    if (!m_enabled) {
        return;
    }

    const QUrl url = request.requestUrl();

    if (url.scheme().compare(QSL("http"), Qt::CaseInsensitive) != 0) {
        return;
    }

    if (isExcluded(url.host())) {
        return;
    }

    QUrl upgraded = url;
    upgraded.setScheme(QSL("https"));
    request.redirect(upgraded);
}

bool HttpsOnlyInterceptor::isExcluded(const QString &host) const
{
    if (host.isEmpty() || isLoopbackHost(host) || isPrivateAddress(host)) {
        return true;
    }

    for (const QString &entry : m_exclusions) {
        const QString trimmed = entry.trimmed();

        if (trimmed.isEmpty()) {
            continue;
        }

        // Wildcard pattern: *.example.com
        if (trimmed.startsWith(QSL("*"))) {
            if (host.endsWith(trimmed.mid(1), Qt::CaseInsensitive)) {
                return true;
            }
            continue;
        }

        // Exact host or any subdomain of the entry: example.com matches
        // example.com and www.example.com
        if (host.compare(trimmed, Qt::CaseInsensitive) == 0 || host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive)) {
            return true;
        }
    }

    return false;
}

bool HttpsOnlyInterceptor::isLoopbackHost(const QString &host)
{
    if (host.compare(QSL("localhost"), Qt::CaseInsensitive) == 0) {
        return true;
    }

    if (host.endsWith(QSL(".localhost"), Qt::CaseInsensitive) || host.endsWith(QSL(".local"), Qt::CaseInsensitive)) {
        return true;
    }

    const QHostAddress address(host);

    return !address.isNull() && address.isLoopback();
}

bool HttpsOnlyInterceptor::isPrivateAddress(const QString &host)
{
    const QHostAddress address(host);

    if (address.isNull()) {
        return false;
    }

    // Never upgrade LAN / private destinations - they typically have no
    // TLS certificate and the user explicitly typed an address there.
    if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        return address.isInSubnet(QHostAddress::parseSubnet(QSL("fc00::/7"))) ||
               address.isInSubnet(QHostAddress::parseSubnet(QSL("fe80::/10")));
    }

    const quint32 ip = address.toIPv4Address();

    return (ip >> 24) == 10u ||                                    // 10.0.0.0/8
           (ip >> 16) == 0xC0A8u ||                                // 192.168.0.0/16
           ((ip >> 16) >= 0xAC10u && (ip >> 16) <= 0xAC1Fu) ||     // 172.16.0.0/12
           (ip >> 16) == 0xA9FEu;                                  // 169.254.0.0/16
}
