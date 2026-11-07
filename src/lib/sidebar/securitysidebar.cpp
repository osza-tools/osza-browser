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
#include "securitysidebar.h"
#include "browserwindow.h"
#include "adblockmanager.h"
#include "dnsoverhttpsmanager.h"
#include "fingerprintmanager.h"
#include "gpcmanager.h"
#include "httpsonlyinterceptor.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "qztools.h"
#include "securityimportpreviewdialog.h"
#include "securitymanager.h"
#include "securitypresets.h"
#include "securitysettingsporter.h"
#include "settingsdiffpage.h"
#include "settings.h"
#include "tabwidget.h"
#include "tabbedwebview.h"
#include "threatblockmanager.h"

#include <QAction>
#include <QCheckBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QMenu>
#include <QMessageBox>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

const int kRefreshIntervalMs = 1000;

QLabel* headingLabel(const QString &text)
{
    auto *label = new QLabel(text);
    QFont font = label->font();
    font.setBold(true);
    label->setFont(font);
    return label;
}

} // namespace

SecuritySideBar::SecuritySideBar(BrowserWindow* window, QWidget* parent)
    : QWidget(parent)
    , m_window(window)
{
    createLayout();

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(kRefreshIntervalMs);
    connect(m_refreshTimer, &QTimer::timeout, this, &SecuritySideBar::refresh);
    m_refreshTimer->start();

    connect(AdBlockManager::instance(), &AdBlockManager::enabledChanged, this, &SecuritySideBar::refresh);

    auto *threatManager = mApp->networkManager()->threatBlockManager();
    connect(threatManager, &ThreatBlockManager::enabledChanged, this, &SecuritySideBar::refresh);
    connect(threatManager, &ThreatBlockManager::listUpdated, this, &SecuritySideBar::refresh);
    connect(threatManager, &ThreatBlockManager::updateFailed, this, &SecuritySideBar::refresh);

    if (m_window) {
        // The tab switch rides the stack's own currentChanged signal.
        // TabWidget::currentTabChanged reads like one but is a plain
        // public method - the handler the tab bar calls when a switch
        // lands - so a member-pointer connect to it compiles clean
        // and then resolves nothing at runtime ("signal not found"):
        // the sidebar was left to its timer alone.
        connect(m_window->tabWidget(), &TabWidget::currentChanged, this, &SecuritySideBar::refresh);
    }

    connect(m_adBlockToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleAdBlock);
    connect(m_httpsOnlyToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleHttpsOnly);
    connect(m_stripTrackingToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleStripTracking);
    connect(m_secureDnsToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleSecureDns);
    connect(m_threatBlockToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleThreatBlock);
    connect(m_fingerprintToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleFingerprintProtection);
    connect(m_gpcToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleGpc);
    connect(m_resetButton, &QToolButton::clicked, this, &SecuritySideBar::resetCounters);
    connect(m_selfTestButton, &QToolButton::clicked, this, &SecuritySideBar::openSelfTest);

    connect(m_backupMenu->addAction(tr("Export settings...")), &QAction::triggered,
            this, &SecuritySideBar::exportSecuritySettings);
    connect(m_backupMenu->addAction(tr("Import settings...")), &QAction::triggered,
            this, &SecuritySideBar::importSecuritySettings);

    // The recommended baselines live next to the importer they are
    // built on: applying a preset goes through the very same
    // validation as importing a file.
    m_backupMenu->addSeparator();
    QMenu *presetsMenu = m_backupMenu->addMenu(tr("Apply recommended baseline"));
    presetsMenu->setToolTipsVisible(true);

    for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
        QAction *action = presetsMenu->addAction(preset.name);
        action->setToolTip(preset.description);
        connect(action, &QAction::triggered, this, [this, id = preset.id]() {
            applySecurityPreset(id);
        });
    }

    // The informed path to the same decision: the diff page shows
    // what a baseline would change here, per tool, before anything
    // is applied.
    presetsMenu->addSeparator();
    QAction *previewAction = presetsMenu->addAction(tr("Preview what a baseline would change..."));
    previewAction->setToolTip(tr("Open the osza:settings-diff page: what each recommended baseline would change in this profile, computed live. Nothing is applied by the preview."));
    connect(previewAction, &QAction::triggered, this, &SecuritySideBar::previewSecurityBaselines);

    // A baseline can also be handed to another machine or profile
    // without first applying it here: the picker saves any preset
    // as a checksum-verified settings file.
    QMenu *savePresetMenu = m_backupMenu->addMenu(tr("Save baseline to file..."));
    savePresetMenu->setToolTipsVisible(true);

    for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
        QAction *action = savePresetMenu->addAction(preset.name);
        action->setToolTip(preset.description);
        connect(action, &QAction::triggered, this, [this, id = preset.id]() {
            saveSecurityPresetToFile(id);
        });
    }

    refresh();
}

void SecuritySideBar::createLayout()
{
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(8, 8, 8, 8);
    mainLayout->setSpacing(8);

    // Protection status
    auto *statusRow = new QHBoxLayout;
    statusRow->setSpacing(6);
    m_statusIcon = new QLabel(this);
    m_statusIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/safe.svg")).scaled(16, 16, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    statusRow->addWidget(m_statusIcon);
    statusRow->addWidget(m_statusLabel, 1);
    mainLayout->addLayout(statusRow);

    // Totals: a 2x2 grid keeps the four tiles readable even in a
    // narrow sidebar.
    mainLayout->addWidget(headingLabel(tr("Protection totals")));

    auto *tilesLayout = new QGridLayout;
    tilesLayout->setSpacing(6);
    auto *adsTile = createCounterTile(tr("Ads blocked"), &m_adsValue);
    auto *trackersTile = createCounterTile(tr("Trackers stripped"), &m_trackersValue);
    auto *upgradesTile = createCounterTile(tr("HTTPS upgrades"), &m_upgradesValue);
    auto *threatsTile = createCounterTile(tr("Threats blocked"), &m_threatsValue);
    tilesLayout->addWidget(adsTile, 0, 0);
    tilesLayout->addWidget(trackersTile, 0, 1);
    tilesLayout->addWidget(upgradesTile, 1, 0);
    tilesLayout->addWidget(threatsTile, 1, 1);
    mainLayout->addLayout(tilesLayout);

    // Current site
    mainLayout->addWidget(headingLabel(tr("This site")));
    m_siteLabel = new QLabel(this);
    m_siteLabel->setWordWrap(true);
    mainLayout->addWidget(m_siteLabel);

    auto *siteGrid = new QGridLayout;
    siteGrid->setHorizontalSpacing(8);
    siteGrid->setVerticalSpacing(2);
    auto *siteAdsRow = createHostRow(tr("Ads blocked"), &m_siteAdsValue);
    auto *siteTrackersRow = createHostRow(tr("Trackers stripped"), &m_siteTrackersValue);
    auto *siteUpgradesRow = createHostRow(tr("HTTPS upgrades"), &m_siteUpgradesValue);
    auto *siteThreatsRow = createHostRow(tr("Threats blocked"), &m_siteThreatsValue);
    siteGrid->addWidget(siteAdsRow, 0, 0);
    siteGrid->addWidget(siteTrackersRow, 1, 0);
    siteGrid->addWidget(siteUpgradesRow, 2, 0);
    siteGrid->addWidget(siteThreatsRow, 3, 0);
    mainLayout->addLayout(siteGrid);

    // Quick switches
    mainLayout->addWidget(headingLabel(tr("Protections")));
    m_adBlockToggle = new QCheckBox(tr("AdBlock"), this);
    m_httpsOnlyToggle = new QCheckBox(tr("HTTPS-Only mode"), this);
    m_httpsOnlyToggle->setToolTip(tr("Automatically upgrade all insecure http:// connections to https://."));
    m_stripTrackingToggle = new QCheckBox(tr("Strip tracking parameters"), this);
    m_secureDnsToggle = new QCheckBox(tr("Secure DNS (DNS-over-HTTPS)"), this);
    m_secureDnsState = new QLabel(this);
    m_secureDnsState->setContentsMargins(20, 0, 0, 0);
    m_secureDnsState->setWordWrap(true);
    m_threatBlockToggle = new QCheckBox(tr("Malicious site protection"), this);
    m_threatBlockToggle->setToolTip(tr("Block navigations and resources of sites on a curated malware and adware blocklist (StevenBlack hosts by default; the source is configurable)."));
    m_threatBlockState = new QLabel(this);
    m_threatBlockState->setObjectName(QSL("threatBlockState"));
    m_threatBlockState->setContentsMargins(20, 0, 0, 0);
    m_threatBlockState->setWordWrap(true);
    m_fingerprintToggle = new QCheckBox(tr("Fingerprint protection"), this);
    m_fingerprintToggle->setToolTip(tr("Randomize canvas, WebGL, audio and hardware fingerprints per site. Sites can be excluded from the padlock menu or the exceptions dialog in Preferences."));
    m_fingerprintState = new QLabel(this);
    m_fingerprintState->setContentsMargins(20, 0, 0, 0);
    m_fingerprintState->setWordWrap(true);
    m_gpcToggle = new QCheckBox(tr("Global Privacy Control (Sec-GPC)"), this);
    m_gpcToggle->setToolTip(tr("Send the Global Privacy Control opt-out with every request and report it to page scripts. Where the law recognizes GPC, sites must honor it as an opt-out from the sale or sharing of personal data."));
    m_gpcState = new QLabel(this);
    m_gpcState->setContentsMargins(20, 0, 0, 0);
    m_gpcState->setWordWrap(true);

    // One row per tool: the quick switch, and beside it the deep link
    // to that tool's part of the recommended baseline's diff. The
    // state labels of the tools that carry one sit under their row.
    mainLayout->addWidget(createToolRow(m_adBlockToggle, QSL("adblock")));
    mainLayout->addWidget(createToolRow(m_httpsOnlyToggle, QSL("httpsOnly")));
    mainLayout->addWidget(createToolRow(m_stripTrackingToggle, QSL("trackingParameters")));
    mainLayout->addWidget(createToolRow(m_secureDnsToggle, QSL("secureDns")));
    mainLayout->addWidget(m_secureDnsState);
    mainLayout->addWidget(createToolRow(m_threatBlockToggle, QSL("threatBlock")));
    mainLayout->addWidget(m_threatBlockState);
    mainLayout->addWidget(createToolRow(m_fingerprintToggle, QSL("fingerprintProtection")));
    mainLayout->addWidget(m_fingerprintState);
    mainLayout->addWidget(createToolRow(m_gpcToggle, QSL("globalPrivacyControl")));
    mainLayout->addWidget(m_gpcState);

    mainLayout->addStretch(1);

    auto *footerLayout = new QHBoxLayout;
    m_selfTestButton = new QToolButton(this);
    m_selfTestButton->setObjectName(QSL("selftestButton"));
    m_selfTestButton->setText(tr("Security self-test"));
    m_selfTestButton->setAutoRaise(true);
    m_selfTestButton->setToolTip(tr("Open the osza:selftest page and watch the fingerprint randomization verify itself live."));
    footerLayout->addWidget(m_selfTestButton);
    m_resetButton = new QToolButton(this);
    m_resetButton->setText(tr("Reset counters"));
    m_resetButton->setAutoRaise(true);
    m_resetButton->setToolTip(tr("Reset the protection counters. Per-site values are cleared too."));
    footerLayout->addWidget(m_resetButton);
    m_backupButton = new QToolButton(this);
    m_backupButton->setObjectName(QSL("backupButton"));
    m_backupButton->setText(tr("Import / Export"));
    m_backupButton->setAutoRaise(true);
    m_backupButton->setPopupMode(QToolButton::InstantPopup);
    m_backupButton->setToolTip(tr("Save the configuration of every security tool to a file, or apply such a file to this profile."));
    m_backupMenu = new QMenu(m_backupButton);
    m_backupButton->setMenu(m_backupMenu);
    footerLayout->addWidget(m_backupButton);
    footerLayout->addStretch(1);
    mainLayout->addLayout(footerLayout);
}

QWidget* SecuritySideBar::createCounterTile(const QString &caption, QLabel **valueOut)
{
    auto *frame = new QFrame(this);
    frame->setFrameShape(QFrame::StyledPanel);

    auto *layout = new QVBoxLayout(frame);
    layout->setContentsMargins(6, 6, 6, 6);
    layout->setSpacing(2);

    auto *value = new QLabel(QSL("0"), frame);
    value->setAlignment(Qt::AlignCenter);
    QFont font = value->font();
    font.setBold(true);
    font.setPointSize(font.pointSize() + 3);
    value->setFont(font);

    auto *captionLabel = new QLabel(caption, frame);
    captionLabel->setAlignment(Qt::AlignCenter);
    captionLabel->setWordWrap(true);

    layout->addWidget(value);
    layout->addWidget(captionLabel);

    *valueOut = value;

    return frame;
}

QWidget* SecuritySideBar::createHostRow(const QString &caption, QLabel **valueOut)
{
    auto *widget = new QWidget(this);

    auto *layout = new QHBoxLayout(widget);
    layout->setContentsMargins(12, 0, 0, 0);
    layout->setSpacing(6);

    auto *captionLabel = new QLabel(caption, widget);
    auto *value = new QLabel(QSL("0"), widget);

    layout->addWidget(captionLabel, 1);
    layout->addWidget(value);

    *valueOut = value;

    return widget;
}

QWidget* SecuritySideBar::createToolRow(QCheckBox *toggle, const QString &toolKey)
{
    // A tool's row: the quick switch, and beside it the deep link to
    // that tool's part of the recommended baseline's diff. The link
    // is only built when it can be honest - the porter's key list
    // must know the key (the page judges a "tool" item by that same
    // list) and the preset catalog must carry the recommended
    // baseline - so a row can never promise a section the page has
    // no answer for.
    auto *row = new QWidget(this);

    auto *layout = new QHBoxLayout(row);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);

    layout->addWidget(toggle, 1);

    const SecurityPresets::Preset baseline = SettingsDiffPage::recommendedBaseline();

    if (SecuritySettingsPorter::toolKeys().contains(toolKey) && !baseline.id.isEmpty()) {
        const QUrl url = SettingsDiffPage::pageUrl(baseline.id, toolKey);

        auto *link = new QLabel(row);
        link->setObjectName(QSL("%1DiffLink").arg(toolKey));
        link->setTextFormat(Qt::RichText);
        // osza: URLs belong to the browser, never to the OS.
        link->setOpenExternalLinks(false);
        link->setText(QSL("<a href=\"%1\">%2</a>")
                          .arg(url.toString().toHtmlEscaped(), tr("diff").toHtmlEscaped()));
        link->setToolTip(tr("What the %1 would change for %2 - opens the settings diff page focused on its section. Nothing is applied by the preview.")
                             .arg(baseline.name, SecuritySettingsPorter::toolDisplayName(toolKey)));

        // The label never opens anything itself: the click hands the
        // tool's stable key to openToolDiff(), which builds the
        // address in the one place the URL shape exists - so the
        // visible link and where it lands cannot drift apart.
        connect(link, &QLabel::linkActivated, this, [this, toolKey](const QString &) {
            openToolDiff(toolKey);
        });

        layout->addWidget(link);
    }

    return row;
}

QString SecuritySideBar::currentHost() const
{
    if (!m_window) {
        return QString();
    }

    WebView *view = m_window->weView();

    if (!view) {
        return QString();
    }

    const QUrl url = view->url();

    return url.isValid() ? url.host() : QString();
}

QString SecuritySideBar::formatCount(quint64 count) const
{
    return QString::number(count);
}

void SecuritySideBar::refresh()
{
    updateToggles();
    updateStatus();

    SecurityManager *security = SecurityManager::instance();

    m_adsValue->setText(formatCount(security->adsBlocked()));
    m_trackersValue->setText(formatCount(security->trackersStripped()));
    m_upgradesValue->setText(formatCount(security->httpsUpgrades()));
    m_threatsValue->setText(formatCount(security->threatsBlocked()));

    const QString host = currentHost();
    m_siteLabel->setText(host.isEmpty() ? tr("No site is open.") : tr("<b>%1</b>").arg(host.toHtmlEscaped()));

    m_siteAdsValue->setText(formatCount(security->adsBlockedForHost(host)));
    m_siteTrackersValue->setText(formatCount(security->trackersStrippedForHost(host)));
    m_siteUpgradesValue->setText(formatCount(security->httpsUpgradesForHost(host)));
    m_siteThreatsValue->setText(formatCount(security->threatsBlockedForHost(host)));
}

void SecuritySideBar::updateStatus()
{
    const bool adBlock = AdBlockManager::instance()->isEnabled();
    const bool httpsOnly = mApp->networkManager()->httpsOnlyInterceptor()->isEnabled();
    const auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    const auto *threatBlock = mApp->networkManager()->threatBlockManager();
    const bool fingerprint = FingerprintManager::instance()->isEnabled();
    const bool gpc = GpcManager::instance()->isEnabled();

    const bool anyOn = adBlock || httpsOnly || m_stripTrackingToggle->isChecked()
        || doh->mode() != DnsOverHttpsManager::Disabled
        || threatBlock->isEnabled()
        || fingerprint
        || gpc;

    if (anyOn) {
        m_statusIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/safe.svg")).scaled(16, 16, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        m_statusLabel->setText(tr("Protections are active on this browser."));
    } else {
        m_statusIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/unsafe.svg")).scaled(16, 16, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        m_statusLabel->setText(tr("No protections are enabled."));
    }

    const bool dohSupported = DnsOverHttpsManager::isSupported();

    switch (doh->mode()) {
    case DnsOverHttpsManager::SecureOnly:
        m_secureDnsState->setText(tr("DoH only, no fallback (%1)").arg(doh->serverTemplates().value(0, tr("custom"))));
        break;
    case DnsOverHttpsManager::SecureWithFallback:
        m_secureDnsState->setText(tr("DoH with system fallback (%1)").arg(doh->serverTemplates().value(0, tr("custom"))));
        break;
    case DnsOverHttpsManager::Disabled:
    default:
        m_secureDnsState->setText(dohSupported ? tr("Secure DNS is off.") : tr("Secure DNS requires QtWebEngine 6.6+."));
        break;
    }

    // Fingerprint protection state, honest about the current site.
    if (!fingerprint) {
        m_fingerprintState->setText(tr("Fingerprint protection is off."));
    } else {
        const QString host = currentHost();
        if (!host.isEmpty() && FingerprintManager::instance()->isExcluded(host)) {
            m_fingerprintState->setText(tr("Randomized everywhere except %1 (excluded from the padlock menu).").arg(host.toHtmlEscaped()));
        } else {
            m_fingerprintState->setText(tr("Canvas, WebGL and audio readouts are randomized per site."));
        }
    }

    // Global Privacy Control state, honest about what leaves the browser.
    if (!gpc) {
        m_gpcState->setText(tr("The Global Privacy Control signal is off."));
    } else {
        const QString host = currentHost();
        if (!host.isEmpty() && GpcManager::instance()->isExcluded(host)) {
            m_gpcState->setText(tr("The opt-out is sent everywhere except to %1 (excluded from the padlock menu).").arg(host.toHtmlEscaped()));
        } else {
            m_gpcState->setText(tr("Every request carries the Sec-GPC: 1 opt-out, and pages see navigator.globalPrivacyControl = true."));
        }
    }

    // Malicious-site protection state, honest about the list and
    // about the one per-site state the tool has. The list's age is
    // spoken in relative terms (the same describeListAge() the
    // interstitial and the padlock row use) with the movement the
    // last refresh brought riding beside it (the same listMovement()
    // both of them append): this row refreshes every second, so
    // "updated 3 hours ago" ticks live, and a
    // failed refresh is named alongside the list it left behind.
    if (!threatBlock->isEnabled()) {
        m_threatBlockState->setText(tr("Malicious site protection is off."));
    } else {
        const QString host = currentHost();
        if (!host.isEmpty() && threatBlock->isSessionAllowed(host)) {
            m_threatBlockState->setText(tr("Paused for %1 in this session (\"proceed anyway\" from the warning page).").arg(host.toHtmlEscaped()));
        } else if (threatBlock->isUpdating()) {
            m_threatBlockState->setText(tr("Updating the blocklist..."));
        } else if (threatBlock->hostCount() == 0) {
            if (!threatBlock->lastUpdateError().isEmpty()) {
                m_threatBlockState->setText(tr("The blocklist download failed: %1").arg(threatBlock->lastUpdateError().toHtmlEscaped()));
            } else {
                m_threatBlockState->setText(tr("Blocklist not downloaded yet. It is fetched from the configured source."));
            }
        } else {
            const QString count = QLocale().toString(threatBlock->hostCount());
            const QString updated = ThreatBlockManager::describeListAge(threatBlock->lastUpdate());
            QString text = tr("%1 hosts, updated %2", "blocklist size and last update").arg(count, updated);

            // The movement the last refresh brought rides beside the
            // age, before the failure tail - the same composed
            // string the interstitial's evidence row and the
            // padlock menu's coverage row append next to their own
            // age phrasing, so the surfaces that speak the list's
            // age speak one movement, not three.
            text += threatBlock->listMovement();

            if (!threatBlock->lastUpdateError().isEmpty()) {
                text += QSL(" - ") + tr("the last update failed: %1").arg(threatBlock->lastUpdateError().toHtmlEscaped());
            }

            m_threatBlockState->setText(text);
        }
    }
}

void SecuritySideBar::updateToggles()
{
    const QSignalBlocker adBlockBlocker(m_adBlockToggle);
    const QSignalBlocker httpsOnlyBlocker(m_httpsOnlyToggle);
    const QSignalBlocker stripTrackingBlocker(m_stripTrackingToggle);
    const QSignalBlocker secureDnsBlocker(m_secureDnsToggle);
    const QSignalBlocker threatBlockBlocker(m_threatBlockToggle);
    const QSignalBlocker fingerprintBlocker(m_fingerprintToggle);
    const QSignalBlocker gpcBlocker(m_gpcToggle);

    m_adBlockToggle->setChecked(AdBlockManager::instance()->isEnabled());
    m_httpsOnlyToggle->setChecked(mApp->networkManager()->httpsOnlyInterceptor()->isEnabled());

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    m_stripTrackingToggle->setChecked(settings.value(QSL("StripTrackingQuery"), true).toBool());
    settings.endGroup();

    const auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    m_secureDnsToggle->setChecked(doh->mode() != DnsOverHttpsManager::Disabled);
    m_secureDnsToggle->setEnabled(DnsOverHttpsManager::isSupported());

    m_threatBlockToggle->setChecked(mApp->networkManager()->threatBlockManager()->isEnabled());
    m_fingerprintToggle->setChecked(FingerprintManager::instance()->isEnabled());
    m_gpcToggle->setChecked(GpcManager::instance()->isEnabled());
}

void SecuritySideBar::resetCounters()
{
    SecurityManager::instance()->resetCounters();
    refresh();
}

void SecuritySideBar::openSelfTest()
{
    if (!m_window) {
        return;
    }

    m_window->tabWidget()->addView(LoadRequest(QUrl(QSL("osza:selftest"))), Qz::NT_SelectedTab);
}

void SecuritySideBar::previewSecurityBaselines()
{
    // The baselines overview: one card per baseline with the number
    // of settings it would change here right now, linking to its
    // full diff. A preview only - the page applies nothing.
    if (!m_window) {
        return;
    }

    m_window->tabWidget()->addView(LoadRequest(SettingsDiffPage::pageUrl()), Qz::NT_SelectedTab);
}

void SecuritySideBar::openToolDiff(const QString &toolKey)
{
    // A tool row's deep link lands in SettingsDiffPage::openToolDiff()
    // - the one place the "what would the recommended setting for
    // this tool be?" answer lives, shared with the padlock menu's
    // per-site entries, so every affordance lands the same way: the
    // recommended baseline's diff, focused on the row's tool, or the
    // baselines overview when the request cannot be answered
    // honestly - never an error page.
    SettingsDiffPage::openToolDiff(m_window, toolKey);
}

void SecuritySideBar::exportSecuritySettings()
{
    const QString path = QzTools::getSaveFileName(QSL("SecuritySettings-Export"), this, tr("Export Security Settings"),
                                                  QDir::homePath() + QSL("/osza-security-settings.json"),
                                                  tr("JSON files (*.json);;All files (*)"));

    if (path.isEmpty()) {
        return;
    }

    QString error;
    if (SecuritySettingsPorter::exportToFile(path, &error)) {
        QMessageBox::information(this, tr("Export Security Settings"),
                                 tr("The security tools configuration was saved to %1.").arg(QDir::toNativeSeparators(path)));
    } else {
        QMessageBox::warning(this, tr("Export Security Settings"),
                             tr("The security tools configuration could not be saved:\n%1").arg(error));
    }
}

void SecuritySideBar::importSecuritySettings()
{
    const QString path = QzTools::getOpenFileName(QSL("SecuritySettings-Import"), this, tr("Import Security Settings"),
                                                   QDir::homePath(), tr("JSON files (*.json);;All files (*)"));

    if (path.isEmpty()) {
        return;
    }

    // Load first, preview next, apply last - the user decides on the
    // very same document object that would be applied.
    QJsonObject document;
    QString error;

    if (!SecuritySettingsPorter::loadDocument(path, &document, &error)) {
        QMessageBox::warning(this, tr("Import Security Settings"),
                             tr("The file could not be read:\n%1").arg(error));
        return;
    }

    // What the import would change, per tool and per field, computed
    // without touching anything - and before the checksum question,
    // so a changed file can be judged on its content.
    const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(document);

    if (!preview.ok) {
        QMessageBox::warning(this, tr("Import Security Settings"),
                             tr("The file cannot be imported:\n%1").arg(preview.error));
        return;
    }

    // Window-modal, not application-modal: the dialog keeps this
    // window - and with it, the profile it previews - input-blocked
    // while the decision is pending, but the diff page a baseline
    // file can link to opens in a window of its own and can be read
    // beside the decision. The import itself still runs only on
    // acceptance, on the very same document the preview showed.
    auto *dialog = new SecurityImportPreviewDialog(preview, QFileInfo(path).fileName(), this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &SecurityImportPreviewDialog::diffPageRequested,
            this, [](const QUrl &url) {
        // A page of the browser belongs to the browser: a window of
        // its own, loaded straight from the deep link the dialog
        // computed - per-tool focused when the selection asked for
        // exactly that.
        mApp->createWindow(Qz::BW_NewWindow, url);
    });

    connect(dialog, &QDialog::accepted, this, [this, dialog, document]() {
        // The dialog says "Import anyway" for a checksum mismatch and
        // records that explicit decision; the import is allowed for
        // exactly this case and refused otherwise.
        const SecuritySettingsPorter::ChecksumPolicy policy = dialog->importDespiteChecksum()
            ? SecuritySettingsPorter::ChecksumPolicy::Allow
            : SecuritySettingsPorter::ChecksumPolicy::Reject;
        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::applyDocument(document, policy);

        if (!result.ok) {
            QMessageBox::warning(this, tr("Import Security Settings"),
                                 tr("The file could not be imported:\n%1").arg(result.error));
            return;
        }

        refresh();

        QString summary = tr("Imported the settings of %n security tool(s).", nullptr, result.appliedTools);

        if (result.checksumMismatch) {
            summary += QSL("\n\n") + tr("The file's checksum did not match; it was imported anyway.");
        }

        if (!result.skippedTools.isEmpty()) {
            summary += QSL("\n\n") + tr("Skipped:\n%1").arg(result.skippedTools.join(QSL("\n")));
        }

        QMessageBox::information(this, tr("Import Security Settings"), summary);
    });

    dialog->open();
}

void SecuritySideBar::saveSecurityPresetToFile(const QString &id)
{
    const SecurityPresets::Preset preset = SecurityPresets::presetById(id);

    if (preset.id.isEmpty()) {
        return;
    }

    const QString suggested = QDir::homePath() + QSL("/osza-security-%1.json").arg(preset.id);
    const QString path = QzTools::getSaveFileName(QSL("SecuritySettings-Export"), this, tr("Save Security Preset"),
                                                  suggested, tr("JSON files (*.json);;All files (*)"));

    if (path.isEmpty()) {
        return;
    }

    // A preset saved to a file is a regular export of the preset's
    // document: stamped, checksummed, tamper-evident - so it imports
    // on any profile or machine without the mismatch warning.
    QString error;
    if (SecuritySettingsPorter::exportDocumentToFile(preset.document, path, &error)) {
        QMessageBox::information(this, tr("Save Security Preset"),
                                 tr("The preset \"%1\" was saved to %2.\n\nIt is a regular security settings file and can be imported on any Osza profile or machine.")
                                     .arg(preset.name, QDir::toNativeSeparators(path)));
    } else {
        QMessageBox::warning(this, tr("Save Security Preset"),
                             tr("The preset could not be saved:\n%1").arg(error));
    }
}

void SecuritySideBar::applySecurityPreset(const QString &id)
{
    const SecurityPresets::Preset preset = SecurityPresets::presetById(id);

    if (preset.id.isEmpty()) {
        return;
    }

    // A preset replaces the configuration of every tool; that is its
    // point, so it never happens without the user seeing it coming.
    const QMessageBox::StandardButton answer = QMessageBox::question(
        this, tr("Apply Security Preset"),
        tr("The preset \"%1\" replaces the current configuration of every security tool:\n%2\n\nApply it now?").arg(preset.name, preset.description),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (answer != QMessageBox::Yes) {
        return;
    }

    // The same validation and the same live manager APIs as an
    // imported file - there is no second, weaker code path.
    const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::applyDocument(preset.document);

    if (!result.ok) {
        QMessageBox::warning(this, tr("Apply Security Preset"),
                             tr("The preset could not be applied:\n%1").arg(result.error));
        return;
    }

    refresh();

    QString summary = tr("Applied \"%1\" to %n security tool(s).", nullptr, result.appliedTools).arg(preset.name);

    if (!result.skippedTools.isEmpty()) {
        summary += QSL("\n\n") + tr("Skipped:\n%1").arg(result.skippedTools.join(QSL("\n")));
    }

    QMessageBox::information(this, tr("Apply Security Preset"), summary);
}

void SecuritySideBar::toggleAdBlock(bool enabled)
{
    AdBlockManager::instance()->setEnabled(enabled);
    refresh();
}

void SecuritySideBar::toggleHttpsOnly(bool enabled)
{
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), enabled);
        settings.endGroup();
    }

    mApp->networkManager()->httpsOnlyInterceptor()->loadSettings();
    refresh();
}

void SecuritySideBar::toggleStripTracking(bool enabled)
{
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("StripTrackingQuery"), enabled);
        settings.endGroup();
    }

    mApp->networkManager()->loadSettings();
    refresh();
}

void SecuritySideBar::toggleSecureDns(bool enabled)
{
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();

    if (!enabled) {
        // Switching secure DNS off must not cost the configuration it
        // switches off: setConfiguration() persists the mode, and a
        // plain "off" would leave Disabled as the saved mode - so the
        // off->on round trip through this switch would come back as
        // the default (fallback mode, default server) instead of the
        // mode and servers the user had chosen. The secure mode being
        // switched off is remembered beside its servers (which
        // setConfiguration() keeps); the mode itself stays Disabled,
        // the state the checkbox reports.
        const DnsOverHttpsManager::Mode mode = doh->mode();

        if (mode != DnsOverHttpsManager::Disabled) {
            Settings settings;
            settings.beginGroup(QSL("Web-Browser-Settings"));
            settings.setValue(QSL("DnsOverHttpsSavedMode"), static_cast<int>(mode));
            settings.endGroup();
        }

        doh->setConfiguration(DnsOverHttpsManager::Disabled, doh->serverTemplates());
        refresh();
        return;
    }

    // Re-apply the saved configuration, or start with a sensible default.
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    const int savedMode = settings.value(QSL("DnsOverHttpsMode"), 0).toInt();
    const int rememberedMode = settings.value(QSL("DnsOverHttpsSavedMode"), 0).toInt();
    const QStringList savedServers = settings.value(QSL("DnsOverHttpsServers"), QStringList()).toStringList();
    settings.endGroup();

    // An off->on round trip restores the mode this switch turned off;
    // a profile that never had a secure mode configured (or was
    // disabled by Preferences, which leaves no remembered mode
    // behind) keeps falling back to the saved mode and then the
    // default.
    int mode = savedMode;

    if (mode == DnsOverHttpsManager::Disabled
        && rememberedMode >= DnsOverHttpsManager::SecureWithFallback
        && rememberedMode <= DnsOverHttpsManager::SecureOnly) {
        mode = rememberedMode;
    }

    QStringList servers;

    for (const QString &server : savedServers) {
        if (!server.trimmed().isEmpty()) {
            servers.append(server.trimmed());
        }
    }

    if (mode == DnsOverHttpsManager::Disabled || servers.isEmpty()) {
        doh->setConfiguration(DnsOverHttpsManager::SecureWithFallback,
                              {DnsOverHttpsManager::defaultServerTemplate()});
    } else {
        doh->setConfiguration(static_cast<DnsOverHttpsManager::Mode>(mode), servers);
    }

    refresh();
}

void SecuritySideBar::toggleThreatBlock(bool enabled)
{
    mApp->networkManager()->threatBlockManager()->setEnabled(enabled);
    refresh();
}

void SecuritySideBar::toggleFingerprintProtection(bool enabled)
{
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), enabled);
        settings.endGroup();
    }

    FingerprintManager::instance()->loadSettings();
    refresh();
}

void SecuritySideBar::toggleGpc(bool enabled)
{
    // setEnabled persists the preference and installs/removes the
    // DOM signal script; reloading the network stack makes the
    // Sec-GPC header follow immediately.
    GpcManager::instance()->setEnabled(enabled);
    mApp->networkManager()->loadSettings();
    refresh();
}
