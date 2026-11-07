/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2013-2015  David Rosca <nowrep@gmail.com>
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
#include "html5permissionsmanager.h"
#include "html5permissionsnotification.h"
#include "settings.h"
#include "webview.h"
#include "mainapplication.h"
#include "sitesettingsmanager.h"

#include <QtWebEngineWidgetsVersion>


HTML5PermissionsManager::HTML5PermissionsManager(QObject* parent)
    : QObject(parent)
{
}

void HTML5PermissionsManager::requestPermissions(WebPage* page, QWebEnginePermission permission)
{
    if (!page) {
        return;
    }

    const QWebEnginePermission::PermissionType permissionType = permission.permissionType();

    if (!mApp->siteSettingsManager()->getSupportedFeatures().contains(permissionType)) {
        qWarning() << "HTML5PermissionsManager: Unknown permission type" << permissionType;
        return;
    }

    auto sitePermission = mApp->siteSettingsManager()->getPermission(permissionType, permission.origin());
    if (sitePermission == SiteSettingsManager::Default) {
        sitePermission = mApp->siteSettingsManager()->getDefaultPermission(permissionType);
    }

    if (sitePermission == SiteSettingsManager::Allow) {
        permission.grant();
    }
    else if (sitePermission == SiteSettingsManager::Deny) {
        permission.deny();
    }
    else {
        auto* notif = new HTML5PermissionsNotification(permission, page);
        page->view()->addNotification(notif);
    }
}

void HTML5PermissionsManager::rememberPermissions(const QUrl &origin, const QWebEnginePermission::PermissionType &permissionType,
        const QWebEnginePermission::State &state)
{
    if (origin.isEmpty()) {
        return;
    }

    if (state == QWebEnginePermission::State::Granted) {
        mApp->siteSettingsManager()->setOption(permissionType, origin, SiteSettingsManager::Allow);
    }
    else {
        mApp->siteSettingsManager()->setOption(permissionType, origin, SiteSettingsManager::Deny);
    }
}
