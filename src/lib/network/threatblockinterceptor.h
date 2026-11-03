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
#ifndef THREATBLOCKINTERCEPTOR_H
#define THREATBLOCKINTERCEPTOR_H

#include "qzcommon.h"
#include "urlinterceptor.h"

class ThreatBlockManager;

/*
 * Request-side half of the malicious-site protection.
 *
 * Runs on the WebEngine IO thread inside every URL request. Top-level
 * navigations to a listed host are redirected to the osza:threatblocked
 * interstitial; any other request to a listed host (subresources,
 * frames, workers, ...) is blocked outright, exactly like an AdBlock
 * rule would block it.
 *
 * All state lives in ThreatBlockManager, whose queries are mutex
 * guarded, so this interceptor holds no locks of its own.
 */
class OSZA_EXPORT ThreatBlockInterceptor : public UrlInterceptor
{
public:
    explicit ThreatBlockInterceptor(ThreatBlockManager *manager, QObject *parent = nullptr);

    // Runs on IO thread!
    void interceptRequest(QWebEngineUrlRequestInfo &request) override;

private:
    ThreatBlockManager *m_manager;
};

#endif // THREATBLOCKINTERCEPTOR_H
