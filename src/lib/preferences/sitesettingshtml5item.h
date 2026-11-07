/*
 * Osza - Permission item for HTML5 features for preferences
 * SPDX-FileCopyrightText: 2024 Juraj Oravec <jurajoravec@mailo.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SITESETTINGSHTML5ITEM_H
#define SITESETTINGSHTML5ITEM_H

#include "sitesettingsmanager.h"

#include <QWidget>
#include <QScopedPointer>
#include <QWebEnginePermission>

namespace Ui
{
class SiteSettingsHtml5Item;
}

class SiteSettingsHtml5Item : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QWebEnginePermission::PermissionType feature READ feature)

public:
    SiteSettingsHtml5Item(const QWebEnginePermission::PermissionType a_feature, QWidget* parent = nullptr);
    ~SiteSettingsHtml5Item();

    QWebEnginePermission::PermissionType feature() const;
    SiteSettingsManager::Permission permission() const;

public Q_SLOTS:
    void showBrowseDialog();

private:
    QWebEnginePermission::PermissionType m_feature;

    void setPermission();

private:
    QScopedPointer<Ui::SiteSettingsHtml5Item> m_ui;
};

#endif // SITESETTINGSHTML5ITEM_H
