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
#include "threatblockinterceptor.h"
#include "securitymanager.h"
#include "threatblockmanager.h"

#include <QUrl>
#include <QWebEngineUrlRequestInfo>

ThreatBlockInterceptor::ThreatBlockInterceptor(ThreatBlockManager *manager, QObject *parent)
    : UrlInterceptor(parent)
    , m_manager(manager)
{
}

void ThreatBlockInterceptor::interceptRequest(QWebEngineUrlRequestInfo &request)
{
    const QUrl url = request.requestUrl();
    const QString scheme = url.scheme();

    if (scheme != QSL("http") && scheme != QSL("https")) {
        return;
    }

    const QString host = ThreatBlockManager::normalizeHost(url.host());

    if (host.isEmpty() || !m_manager->shouldBlock(host)) {
        return;
    }

    if (request.resourceType() == QWebEngineUrlRequestInfo::ResourceTypeMainFrame) {
        request.redirect(ThreatBlockManager::blockPageUrl(url));
    } else {
        request.block(true);
    }

    SecurityManager::instance()->reportThreatBlocked(host);
}
