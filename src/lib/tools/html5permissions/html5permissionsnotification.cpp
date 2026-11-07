/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2013-2018 David Rosca <nowrep@gmail.com>
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
#include "ui_html5permissionsnotification.h"
#include "html5permissionsnotification.h"
#include "html5permissionsmanager.h"
#include "mainapplication.h"
#include "iconprovider.h"

#include <QTimer>
#include <QWebEnginePage>
#include <QWebEngineView>
#include <QtWebEngineWidgetsVersion>


HTML5PermissionsNotification::HTML5PermissionsNotification(QWebEnginePermission permission, QWebEnginePage* page)
    : AnimatedWidget(AnimatedWidget::Down, 300, nullptr)
    , ui(new Ui::HTML5PermissionsNotification)
    , m_permission(permission)
    , m_page(page)
{
    setAutoFillBackground(true);
    ui->setupUi(widget());

    ui->close->setIcon(IconProvider::standardIcon(QStyle::SP_DialogCloseButton));

    const QString site = m_permission.origin().host().isEmpty() ? tr("this site") : QSL("<b>%1</b>").arg(m_permission.origin().host());

    switch (m_permission.permissionType()) {
    case QWebEnginePermission::PermissionType::Notifications:
        ui->textLabel->setText(tr("Allow %1 to show desktop notifications?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::Geolocation:
        ui->textLabel->setText(tr("Allow %1 to locate your position?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::MediaAudioCapture:
        ui->textLabel->setText(tr("Allow %1 to use your microphone?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::MediaVideoCapture:
        ui->textLabel->setText(tr("Allow %1 to use your camera?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::MediaAudioVideoCapture:
        ui->textLabel->setText(tr("Allow %1 to use your microphone and camera?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::MouseLock:
        ui->textLabel->setText(tr("Allow %1 to hide your pointer?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::DesktopVideoCapture:
        ui->textLabel->setText(tr("Allow %1 to capture your screen?").arg(site));
        break;

    case QWebEnginePermission::PermissionType::DesktopAudioVideoCapture:
        ui->textLabel->setText(tr("Allow %1 to capture your screen and audio?").arg(site));
        break;
    default:
        qWarning() << "Unknown permission type" << m_permission.permissionType();
        break;
    }

    connect(ui->allow, &QAbstractButton::clicked, this, &HTML5PermissionsNotification::grantPermissions);
    connect(ui->deny, &QAbstractButton::clicked, this, &HTML5PermissionsNotification::denyPermissions);
    connect(ui->close, &QAbstractButton::clicked, this, &HTML5PermissionsNotification::denyPermissions);

    connect(m_page.data(), &QWebEnginePage::loadStarted, this, &QObject::deleteLater);
    // A withdrawn request no longer announces itself: the Qt 5
    // featurePermissionRequestCanceled signal is deprecated without
    // a successor and fires no more, so the notification stands
    // until it is answered or the page moves on (loadStarted
    // above) - answering a request the page already withdrew is
    // harmless, the handle simply resolves nothing.

    startAnimation();
}

void HTML5PermissionsNotification::grantPermissions()
{
    if (!m_page) {
        return;
    }

    QTimer::singleShot(0, this, [this]() {
        // We need to have cursor inside view to correctly grab mouse
        if (m_permission.permissionType() == QWebEnginePermission::PermissionType::MouseLock) {
            QWidget *view = QWebEngineView::forPage(m_page);
            QCursor::setPos(view->mapToGlobal(view->rect().center()));
        }

        m_permission.grant();
    });

    if (ui->remember->isChecked()) {
        mApp->html5PermissionsManager()->rememberPermissions(m_permission.origin(), m_permission.permissionType(), QWebEnginePermission::State::Granted);
    }

    hide();
}

void HTML5PermissionsNotification::denyPermissions()
{
    if (!m_page) {
        return;
    }

    m_permission.deny();

    if (ui->remember->isChecked()) {
        mApp->html5PermissionsManager()->rememberPermissions(m_permission.origin(), m_permission.permissionType(), QWebEnginePermission::State::Denied);
    }

    hide();
}

HTML5PermissionsNotification::~HTML5PermissionsNotification()
{
    delete ui;
}
