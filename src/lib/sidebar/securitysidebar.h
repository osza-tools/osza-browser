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
class QMenu;
class QTimer;
class QToolButton;

class BrowserWindow;

/*
 * Security dashboard sidebar.
 *
 * Shows live counters for the bundled security tools (blocked ads,
 * stripped trackers, HTTPS upgrades) with totals and per-site values,
 * plus quick switches for every protection and a shortcut to the
 * osza:selftest page. Counters are refreshed on a short timer while
 * the sidebar is visible, so updates coming from the IO thread are
 * picked up without cross-thread signals.
 *
 * Every protection row also links to its part of the recommended
 * baseline's diff (openToolDiff): the same osza:settings-diff
 * address the diff page's own "#" anchors and the import preview
 * dialog's "view as page" link carry, focused on that tool's
 * section - so from the row that shows a tool's state, one click
 * shows what the project's recommendation would change about it.
 */
class OSZA_EXPORT SecuritySideBar : public QWidget
{
    Q_OBJECT

public:
    explicit SecuritySideBar(BrowserWindow* window, QWidget* parent = nullptr);

public Q_SLOTS:
    void refresh();
    void resetCounters();
    void openSelfTest();
    void exportSecuritySettings();
    void importSecuritySettings();
    void saveSecurityPresetToFile(const QString &id);
    void applySecurityPreset(const QString &id);
    void previewSecurityBaselines();
    void openToolDiff(const QString &toolKey);
    void toggleAdBlock(bool enabled);
    void toggleHttpsOnly(bool enabled);
    void toggleStripTracking(bool enabled);
    void toggleSecureDns(bool enabled);
    void toggleThreatBlock(bool enabled);
    void toggleFingerprintProtection(bool enabled);
    void toggleGpc(bool enabled);

private:
    QWidget* createCounterTile(const QString &caption, QLabel **valueOut);
    QWidget* createHostRow(const QString &caption, QLabel **valueOut);
    QWidget* createToolRow(QCheckBox *toggle, const QString &toolKey);
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
    QLabel* m_threatsValue;

    QLabel* m_siteLabel;
    QLabel* m_siteAdsValue;
    QLabel* m_siteTrackersValue;
    QLabel* m_siteUpgradesValue;
    QLabel* m_siteThreatsValue;

    QCheckBox* m_adBlockToggle;
    QCheckBox* m_httpsOnlyToggle;
    QCheckBox* m_stripTrackingToggle;
    QCheckBox* m_secureDnsToggle;
    QLabel* m_secureDnsState;
    QCheckBox* m_threatBlockToggle;
    QLabel* m_threatBlockState;
    QCheckBox* m_fingerprintToggle;
    QLabel* m_fingerprintState;
    QCheckBox* m_gpcToggle;
    QLabel* m_gpcState;

    QToolButton* m_resetButton;
    QToolButton* m_selfTestButton;
    QToolButton* m_backupButton;
    QMenu* m_backupMenu;

    QTimer* m_refreshTimer;
};

#endif // SECURITYSIDEBAR_H
