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
#ifndef HTTPSONLYINTERCEPTOR_H
#define HTTPSONLYINTERCEPTOR_H

#include "qzcommon.h"
#include "urlinterceptor.h"

#include <QMutex>
#include <QStringList>

class OSZA_EXPORT HttpsOnlyInterceptor : public UrlInterceptor
{
public:
    explicit HttpsOnlyInterceptor(QObject *parent = nullptr);

    // Runs on IO thread!
    void interceptRequest(QWebEngineUrlRequestInfo &request) override;

    // Must be called after Settings have been created
    void loadSettings();

private:
    bool isExcluded(const QString &host) const;
    static bool isLoopbackHost(const QString &host);
    static bool isPrivateAddress(const QString &host);

    QMutex m_mutex;
    bool m_enabled;
    QStringList m_exclusions;
};

#endif // HTTPSONLYINTERCEPTOR_H
