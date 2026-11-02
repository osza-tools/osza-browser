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
#ifndef SECURITYSIDEBAR_H
#define SECURITYSIDEBAR_H

#include <QWidget>

#include "qzcommon.h"

class QLabel;
class QCheckBox;
class QTimer;
class QToolButton;

class BrowserWindow;

/*
 * Security dashboard sidebar.
 *
 * Shows live counters for the bundled security tools (blocked ads,
 * stripped trackers, HTTPS upgrades) with totals and per-site values,
 * plus quick switches for every protection. Counters are refreshed on
 * a short timer while the sidebar is visible, so updates coming from
 * the IO thread are picked up without cross-thread signals.
 */
class OSZA_EXPORT SecuritySideBar : public QWidget
{
    Q_OBJECT

public:
    explicit SecuritySideBar(BrowserWindow* window, QWidget* parent = nullptr);

public Q_SLOTS:
    void refresh();
    void resetCounters();
    void toggleAdBlock(bool enabled);
    void toggleHttpsOnly(bool enabled);
    void toggleStripTracking(bool enabled);
    void toggleSecureDns(bool enabled);

private:
    QWidget* createCounterTile(const QString &caption, QLabel **valueOut);
    QWidget* createHostRow(const QString &caption, QLabel **valueOut);
    void createLayout();
    void updateStatus();
    void updateToggles();
    QString currentHost() const;
    QString formatCount(quint64 count) const;

    BrowserWindow* m_window;

    QLabel* m_statusIcon;
    QLabel* m_statusLabel;

    QLabel* m_adsValue;
    QLabel* m_trackersValue;
    QLabel* m_upgradesValue;

    QLabel* m_siteLabel;
    QLabel* m_siteAdsValue;
    QLabel* m_siteTrackersValue;
    QLabel* m_siteUpgradesValue;

    QCheckBox* m_adBlockToggle;
    QCheckBox* m_httpsOnlyToggle;
    QCheckBox* m_stripTrackingToggle;
    QCheckBox* m_secureDnsToggle;
    QLabel* m_secureDnsState;

    QToolButton* m_resetButton;

    QTimer* m_refreshTimer;
};

#endif // SECURITYSIDEBAR_H
