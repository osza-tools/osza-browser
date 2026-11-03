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
#include "securitymanager.h"
#include "settings.h"
#include "tabwidget.h"
#include "tabbedwebview.h"
#include "threatblockmanager.h"

#include <QCheckBox>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

const int kRefreshIntervalMs = 1000;

const char kDefaultDohServer[] = "https://cloudflare-dns.com/dns-query{?dns}";

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
        connect(m_window->tabWidget(), &TabWidget::currentTabChanged, this, &SecuritySideBar::refresh);
    }

    connect(m_adBlockToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleAdBlock);
    connect(m_httpsOnlyToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleHttpsOnly);
    connect(m_stripTrackingToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleStripTracking);
    connect(m_secureDnsToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleSecureDns);
    connect(m_threatBlockToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleThreatBlock);
    connect(m_fingerprintToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleFingerprintProtection);
    connect(m_gpcToggle, &QCheckBox::toggled, this, &SecuritySideBar::toggleGpc);
    connect(m_resetButton, &QToolButton::clicked, this, &SecuritySideBar::resetCounters);

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
    m_threatBlockState->setContentsMargins(20, 0, 0, 0);
    m_threatBlockState->setWordWrap(true);
    m_fingerprintToggle = new QCheckBox(tr("Fingerprint protection"), this);
    m_fingerprintToggle->setToolTip(tr("Randomize canvas, WebGL, audio and hardware fingerprints per site. Sites can be excluded from the padlock menu."));
    m_fingerprintState = new QLabel(this);
    m_fingerprintState->setContentsMargins(20, 0, 0, 0);
    m_fingerprintState->setWordWrap(true);
    m_gpcToggle = new QCheckBox(tr("Global Privacy Control (Sec-GPC)"), this);
    m_gpcToggle->setToolTip(tr("Send the Global Privacy Control opt-out with every request and report it to page scripts. Where the law recognizes GPC, sites must honor it as an opt-out from the sale or sharing of personal data."));
    m_gpcState = new QLabel(this);
    m_gpcState->setContentsMargins(20, 0, 0, 0);
    m_gpcState->setWordWrap(true);

    mainLayout->addWidget(m_adBlockToggle);
    mainLayout->addWidget(m_httpsOnlyToggle);
    mainLayout->addWidget(m_stripTrackingToggle);
    mainLayout->addWidget(m_secureDnsToggle);
    mainLayout->addWidget(m_secureDnsState);
    mainLayout->addWidget(m_threatBlockToggle);
    mainLayout->addWidget(m_threatBlockState);
    mainLayout->addWidget(m_fingerprintToggle);
    mainLayout->addWidget(m_fingerprintState);
    mainLayout->addWidget(m_gpcToggle);
    mainLayout->addWidget(m_gpcState);

    mainLayout->addStretch(1);

    auto *footerLayout = new QHBoxLayout;
    m_resetButton = new QToolButton(this);
    m_resetButton->setText(tr("Reset counters"));
    m_resetButton->setAutoRaise(true);
    m_resetButton->setToolTip(tr("Reset the protection counters. Per-site values are cleared too."));
    footerLayout->addWidget(m_resetButton);
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
        m_gpcState->setText(tr("Every request carries the Sec-GPC: 1 opt-out, and pages see navigator.globalPrivacyControl = true."));
    }

    // Malicious-site protection state, honest about the list.
    if (!threatBlock->isEnabled()) {
        m_threatBlockState->setText(tr("Malicious site protection is off."));
    } else if (threatBlock->isUpdating()) {
        m_threatBlockState->setText(tr("Updating the blocklist..."));
    } else if (threatBlock->hostCount() == 0) {
        m_threatBlockState->setText(tr("Blocklist not downloaded yet. It is fetched from the configured source."));
    } else {
        const QString count = QLocale().toString(threatBlock->hostCount());
        const QString updated = threatBlock->lastUpdate().isValid()
            ? QLocale().toString(threatBlock->lastUpdate().toLocalTime(), QLocale::ShortFormat)
            : tr("unknown date");
        m_threatBlockState->setText(tr("%1 hosts, updated %2", "blocklist size and last update").arg(count, updated));
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
        doh->setConfiguration(DnsOverHttpsManager::Disabled, doh->serverTemplates());
        refresh();
        return;
    }

    // Re-apply the saved configuration, or start with a sensible default.
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    const int savedMode = settings.value(QSL("DnsOverHttpsMode"), 0).toInt();
    const QStringList savedServers = settings.value(QSL("DnsOverHttpsServers"), QStringList()).toStringList();
    settings.endGroup();

    const auto mode = static_cast<DnsOverHttpsManager::Mode>(savedMode);
    QStringList servers;

    for (const QString &server : savedServers) {
        if (!server.trimmed().isEmpty()) {
            servers.append(server.trimmed());
        }
    }

    if (mode == DnsOverHttpsManager::Disabled || servers.isEmpty()) {
        doh->setConfiguration(DnsOverHttpsManager::SecureWithFallback, {QLatin1String(kDefaultDohServer)});
    } else {
        doh->setConfiguration(mode, servers);
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
