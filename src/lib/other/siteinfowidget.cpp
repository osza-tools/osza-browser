/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2010-2017 David Rosca <nowrep@gmail.com>
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
#include "qztools.h"
#include "siteinfowidget.h"
#include "ui_siteinfowidget.h"
#include "browserwindow.h"
#include "mainapplication.h"
#include "webpage.h"
#include "tabbedwebview.h"
#include "sqldatabase.h"
#include "protocolhandlermanager.h"
#include "networkmanager.h"
#include "httpsonlyinterceptor.h"
#include "fingerprintmanager.h"
#include "gpcmanager.h"
#include "threatblockmanager.h"
#include "securitypresets.h"
#include "securitysettingsporter.h"
#include "settingsdiffpage.h"
#include "settings.h"

#include <QLabel>
#include <QToolTip>

SiteInfoWidget::SiteInfoWidget(BrowserWindow* window, QWidget* parent)
    : LocationBarPopup(parent)
    , ui(new Ui::SiteInfoWidget)
    , m_window(window)
{
    this->setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);

    setPopupAlignment(Qt::AlignLeft);

    WebView* view = m_window->weView();

    ui->titleLabel->setText(tr("<b>Site %1<b/>").arg(view->url().host()));

    bool secure = false;

    if (view->url().scheme() == QL1S("https")) {
        auto* nm = mApp->networkManager();
        QString host = view->url().host();

        if (nm->ignoredSslHosts().contains(host)) {
            ui->secureDescriptionLabel->setText(tr("Any certificate error is <b>permanently</b> ignored."));
        }
        else if (nm->ignoredSslErrors().contains(host)) {
            ui->secureDescriptionLabel->setText(tr("The certificate error is <b>temporarily</b> ignored."));
        }
        else if (nm->rejectedSslErrors().contains(host)) {
            ui->secureDescriptionLabel->setText(tr("Certificate was rejected."));
        }
        else {
            secure = true;
            ui->secureDescriptionLabel->hide();
        }
    }

    if (secure) {
        ui->secureLabel->setText(tr("Your connection to this site is <b>secured</b>."));
        ui->secureIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/safe.svg")));
    }
    else {
        ui->secureLabel->setText(tr("Your connection to this site is <b>unsecured</b>."));
        ui->secureIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/unsafe.svg")));
    }

    QString scheme = view->url().scheme();
    QString host = view->url().host();

    QSqlQuery query(SqlDatabase::instance()->database());
    query.prepare(QSL("SELECT sum(count) FROM history WHERE url LIKE ?"));
    query.addBindValue(QSL("%1://%2%").arg(scheme, host));
    query.exec();

    if (query.next()) {
        int count = query.value(0).toInt();
        if (count > 3) {
            ui->historyLabel->setText(tr("This is your <b>%1</b> visit of this site.").arg(QString::number(count) + QLatin1Char('.')));
            ui->historyIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/visit3.svg")));
        }
        else if (count == 0) {
            ui->historyLabel->setText(tr("You have <b>never</b> visited this site before."));
            ui->historyIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/visit1.svg")));
        }
        else {
            ui->historyIcon->setPixmap(QPixmap(QSL(":/icons/locationbar/visit2.svg")));
            QString text;
            if (count == 1) {
                text = tr("first");
            }
            else if (count == 2) {
                text = tr("second");
            }
            else if (count == 3) {
                text = tr("third");
            }
            ui->historyLabel->setText(tr("This is your <b>%1</b> visit of this site.").arg(text));
        }
    }

    updateProtocolHandler();
    updateHttpsOnlyState();
    updateFingerprintState();
    updateGpcState();
    updateThreatBlockState();

    // The per-site entries' "diff" links: the same deep links the
    // security dashboard's tool rows carry, beside the entries they
    // answer for.
    setupToolDiffLink(ui->httpsOnlyDiffLink, QSL("httpsOnly"));
    setupToolDiffLink(ui->fingerprintProtectionDiffLink, QSL("fingerprintProtection"));
    setupToolDiffLink(ui->globalPrivacyControlDiffLink, QSL("globalPrivacyControl"));
    setupToolDiffLink(ui->threatBlockDiffLink, QSL("threatBlock"));

    connect(ui->pushButton, &QAbstractButton::clicked, m_window->action(QSL("Tools/SiteInfo")), &QAction::trigger);
    connect(ui->protocolHandlerButton, &QPushButton::clicked, this, &SiteInfoWidget::protocolHandlerButtonClicked);
    connect(ui->httpsOnlyButton, &QPushButton::clicked, this, &SiteInfoWidget::httpsOnlyButtonClicked);
    connect(ui->fingerprintButton, &QPushButton::clicked, this, &SiteInfoWidget::fingerprintButtonClicked);
    connect(ui->gpcButton, &QPushButton::clicked, this, &SiteInfoWidget::gpcButtonClicked);
    connect(ui->threatBlockButton, &QPushButton::clicked, this, &SiteInfoWidget::threatBlockButtonClicked);
    connect(ui->threatBlockUpdateButton, &QPushButton::clicked, this, &SiteInfoWidget::threatBlockUpdateButtonClicked);

    // The blocklist can change while the menu is open: a refresh
    // landing or failing re-renders the threat-block row through the
    // manager's own signals, so the freshness it reports is never a
    // snapshot a popup outlived - the row says "updating now" until
    // it can honestly say "updated less than a minute ago", or name
    // the failure and offer the retry.
    auto *threatBlockManager = mApp->networkManager()->threatBlockManager();
    connect(threatBlockManager, &ThreatBlockManager::listUpdated, this, &SiteInfoWidget::updateThreatBlockState);
    connect(threatBlockManager, &ThreatBlockManager::updateFailed, this, &SiteInfoWidget::updateThreatBlockState);
}

SiteInfoWidget::~SiteInfoWidget()
{
    delete ui;
}

void SiteInfoWidget::updateProtocolHandler()
{
    WebPage *page = m_window->weView()->page();

    const QString scheme = page->registerProtocolHandlerRequestScheme();
    const QUrl registeredUrl = mApp->protocolHandlerManager()->protocolHandlers().value(scheme);

    if (!scheme.isEmpty() && registeredUrl != page->registerProtocolHandlerRequestUrl()) {
        ui->protocolHandlerLabel->setText(tr("Register as <b>%1</b> links handler").arg(page->registerProtocolHandlerRequestScheme()));
        ui->protocolHandlerButton->setText(tr("Register"));
    } else {
        ui->protocolHandlerLabel->hide();
        ui->protocolHandlerButton->hide();
        ui->protocolHandlerLine->hide();
    }
}

void SiteInfoWidget::protocolHandlerButtonClicked()
{
    WebPage *page = m_window->weView()->page();

    mApp->protocolHandlerManager()->addProtocolHandler(page->registerProtocolHandlerRequestScheme(), page->registerProtocolHandlerRequestUrl());
    close();
}

void SiteInfoWidget::updateHttpsOnlyState()
{
    const QString scheme = m_window->weView()->url().scheme();

    if (scheme != QL1S("http") && scheme != QL1S("https")) {
        ui->httpsOnlyLabel->hide();
        ui->httpsOnlyButton->hide();
        ui->httpsOnlyDiffLink->hide();
        return;
    }

    const QString host = m_window->weView()->url().host();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();

    if (!interceptor->isEnabled()) {
        ui->httpsOnlyLabel->setText(tr("HTTPS-Only mode is <b>off</b>."));
        ui->httpsOnlyButton->setText(tr("Enable HTTPS-Only mode"));
        return;
    }

    if (interceptor->hasExplicitExclusion(host)) {
        ui->httpsOnlyLabel->setText(tr("HTTP connections to this site are <b>never</b> upgraded."));
        ui->httpsOnlyButton->setText(tr("Always upgrade to HTTPS"));
    } else {
        ui->httpsOnlyLabel->setText(tr("HTTP connections to this site are <b>upgraded</b> to HTTPS."));
        ui->httpsOnlyButton->setText(tr("Never upgrade to HTTPS"));
    }
}

void SiteInfoWidget::httpsOnlyButtonClicked()
{
    const QUrl url = m_window->weView()->url();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();

    if (!interceptor->isEnabled()) {
        // The per-site shortcuts need the mode itself, turn it on.
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), true);
        settings.endGroup();

        interceptor->loadSettings();
    }
    else if (interceptor->hasExplicitExclusion(url.host())) {
        interceptor->removeExclusion(url.host());
    } else {
        interceptor->addExclusion(url.host());
    }

    // Reload so plain http connections are upgraded right away.
    if (url.scheme() == QL1S("http")) {
        m_window->weView()->reload();
    }

    close();
}

void SiteInfoWidget::setupToolDiffLink(QLabel *link, const QString &toolKey)
{
    // The same deep link the security dashboard's tool rows carry:
    // this tool's part of the recommended baseline's diff - the
    // answer to "what would the recommended setting for this tool
    // be?" one click away from the per-site entry. Built only when
    // it can be honest: the porter's key list must know the key
    // (the same judgment the diff page applies to a "tool" query
    // item) and the preset catalog must carry the recommended
    // baseline, so the padlock menu can never promise a section the
    // page has no answer for.
    link->setTextFormat(Qt::RichText);
    // osza: URLs belong to the browser, never the OS.
    link->setOpenExternalLinks(false);

    const SecurityPresets::Preset baseline = SettingsDiffPage::recommendedBaseline();

    if (!SecuritySettingsPorter::toolKeys().contains(toolKey) || baseline.id.isEmpty()) {
        link->hide();
        return;
    }

    const QUrl url = SettingsDiffPage::pageUrl(baseline.id, toolKey);
    link->setText(QSL("<a href=\"%1\">%2</a>")
                      .arg(url.toString().toHtmlEscaped(), tr("diff").toHtmlEscaped()));
    link->setToolTip(tr("What the %1 would change for %2 - opens the settings diff page focused on its section. Nothing is applied by the preview.")
                         .arg(baseline.name, SecuritySettingsPorter::toolDisplayName(toolKey)));

    // The label never opens anything itself: the click hands the
    // tool's stable key to the shared openToolDiff() - the one
    // place the landing is decided, the same one the dashboard's
    // rows use - so the visible link and where it lands cannot
    // drift apart.
    connect(link, &QLabel::linkActivated, this, [this, toolKey](const QString &) {
        SettingsDiffPage::openToolDiff(m_window, toolKey);
    });
}

void SiteInfoWidget::updateFingerprintState()
{
    const QString scheme = m_window->weView()->url().scheme();

    if (scheme != QL1S("http") && scheme != QL1S("https")) {
        ui->fingerprintLabel->hide();
        ui->fingerprintButton->hide();
        ui->fingerprintProtectionDiffLink->hide();
        return;
    }

    const QString host = m_window->weView()->url().host();
    auto *manager = FingerprintManager::instance();

    if (!manager->isEnabled()) {
        ui->fingerprintLabel->setText(tr("Fingerprint protection is <b>off</b>."));
        ui->fingerprintButton->setText(tr("Enable fingerprint protection"));
    }
    else if (manager->isExcluded(host)) {
        ui->fingerprintLabel->setText(tr("Canvas and audio readouts are <b>not</b> randomized on this site."));
        ui->fingerprintButton->setText(tr("Randomize fingerprints"));
    } else {
        ui->fingerprintLabel->setText(tr("Canvas and audio readouts are <b>randomized</b> on this site."));
        ui->fingerprintButton->setText(tr("Do not randomize fingerprints"));
    }
}

void SiteInfoWidget::fingerprintButtonClicked()
{
    const QUrl url = m_window->weView()->url();
    auto *manager = FingerprintManager::instance();

    if (!manager->isEnabled()) {
        // The per-site shortcut needs the protection itself, turn it on.
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();

        manager->loadSettings();
    }
    else if (manager->isExcluded(url.host())) {
        manager->removeExclusion(url.host());
    } else {
        manager->addExclusion(url.host());
    }

    // Reload so the changed protection applies to this page right away.
    if (url.scheme() == QL1S("http") || url.scheme() == QL1S("https")) {
        m_window->weView()->reload();
    }

    close();
}

void SiteInfoWidget::updateGpcState()
{
    const QString scheme = m_window->weView()->url().scheme();

    if (scheme != QL1S("http") && scheme != QL1S("https")) {
        ui->gpcLabel->hide();
        ui->gpcButton->hide();
        ui->globalPrivacyControlDiffLink->hide();
        return;
    }

    const QString host = m_window->weView()->url().host();
    auto *manager = GpcManager::instance();

    if (!manager->isEnabled()) {
        ui->gpcLabel->setText(tr("The Global Privacy Control signal is <b>off</b>."));
        ui->gpcButton->setText(tr("Enable GPC signal"));
    }
    else if (manager->isExcluded(host)) {
        ui->gpcLabel->setText(tr("The GPC opt-out is <b>not</b> sent to this site."));
        ui->gpcButton->setText(tr("Send the opt-out"));
    } else {
        ui->gpcLabel->setText(tr("The GPC opt-out is <b>sent</b> to this site."));
        ui->gpcButton->setText(tr("Do not send the opt-out"));
    }
}

void SiteInfoWidget::gpcButtonClicked()
{
    const QUrl url = m_window->weView()->url();
    auto *manager = GpcManager::instance();

    if (!manager->isEnabled()) {
        // The per-site shortcut needs the signal itself, turn it on.
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("GlobalPrivacyControl"), true);
        settings.endGroup();

        manager->loadSettings();
    }
    else if (manager->isExcluded(url.host())) {
        manager->removeExclusion(url.host());
    } else {
        manager->addExclusion(url.host());
    }

    // Both halves of the signal read the same persisted list: the
    // script half is rebuilt by the manager itself, the header half
    // follows the network stack's reload - and the page is reloaded
    // so the DOM property and the requests it makes agree at once.
    mApp->networkManager()->loadSettings();

    if (url.scheme() == QL1S("http") || url.scheme() == QL1S("https")) {
        m_window->weView()->reload();
    }

    close();
}

void SiteInfoWidget::updateThreatBlockState()
{
    const QString scheme = m_window->weView()->url().scheme();

    if (scheme != QL1S("http") && scheme != QL1S("https")) {
        ui->threatBlockLabel->hide();
        ui->threatBlockButton->hide();
        ui->threatBlockUpdateButton->hide();
        ui->threatBlockDiffLink->hide();
        return;
    }

    const QString host = m_window->weView()->url().host();
    auto *manager = mApp->networkManager()->threatBlockManager();

    // Both buttons start hidden; every state below shows exactly the
    // actions it carries - the per-site one, the list-lifecycle one,
    // or neither.
    ui->threatBlockButton->hide();
    ui->threatBlockUpdateButton->hide();

    if (!manager->isEnabled()) {
        ui->threatBlockLabel->setText(tr("Malicious site protection is <b>off</b>."));
        ui->threatBlockButton->setText(tr("Enable protection"));
        ui->threatBlockButton->show();
        return;
    }

    // First run, or a refresh with nothing cached yet: until the
    // blocklist arrives there is no coverage to report, and saying
    // "not on the blocklist" would be a reassurance the browser
    // cannot honestly make. The download in flight and its failure
    // are named - the failure with the retry that renews it.
    if (!manager->isListLoaded()) {
        if (manager->isUpdating()) {
            ui->threatBlockLabel->setText(tr("The malicious-site blocklist is being <b>downloaded</b> now."));
        } else if (!manager->lastUpdateError().isEmpty()) {
            ui->threatBlockLabel->setText(tr("The malicious-site blocklist could not be downloaded: %1").arg(manager->lastUpdateError().toHtmlEscaped()));
            ui->threatBlockUpdateButton->setText(tr("Try the update again"));
            ui->threatBlockUpdateButton->show();
        } else {
            ui->threatBlockLabel->setText(tr("The malicious-site blocklist is still <b>loading</b>."));
        }
        return;
    }

    // A session exception is the "proceed anyway" choice from the
    // interstitial - the one per-site state this tool has. It never
    // survives a restart, so the entry says so and offers to end it
    // early; there is no way to create one from here, because the
    // only path to an exception is the interstitial's explicit
    // warning-acknowledging choice.
    if (manager->isSessionAllowed(host)) {
        ui->threatBlockLabel->setText(tr("Malicious site protection is <b>paused</b> for this site (this session)."));
        ui->threatBlockButton->setText(tr("Block this site again"));
        ui->threatBlockButton->show();
        return;
    }

    // The coverage statement, with the freshness of the list behind
    // it: the age in relative terms (the same describeListAge() the
    // interstitial's evidence rows use), a refresh in flight, and -
    // when the list is due or its last refresh failed - the action
    // that renews it right here, the same staleness judgment the
    // manager's own timer refreshes through.
    const QString coverage = manager->isHostBlocked(host)
        ? tr("This site is on the malicious-site <b>blocklist</b>.")
        : tr("This site is <b>not</b> on the malicious-site blocklist.");

    if (manager->isUpdating()) {
        ui->threatBlockLabel->setText(tr("%1 The list is being refreshed now.").arg(coverage));
    } else if (!manager->lastUpdateError().isEmpty()) {
        ui->threatBlockLabel->setText(tr("%1 The last update failed: %2").arg(coverage, manager->lastUpdateError().toHtmlEscaped()));
        ui->threatBlockUpdateButton->setText(tr("Try the update again"));
        ui->threatBlockUpdateButton->show();
    } else {
        ui->threatBlockLabel->setText(tr("%1 (list updated %2)").arg(coverage, ThreatBlockManager::describeListAge(manager->lastUpdate())));

        if (manager->isListStale()) {
            ui->threatBlockUpdateButton->setText(tr("Update the blocklist now"));
            ui->threatBlockUpdateButton->show();
        }
    }
}

void SiteInfoWidget::threatBlockButtonClicked()
{
    const QUrl url = m_window->weView()->url();
    auto *manager = mApp->networkManager()->threatBlockManager();

    if (!manager->isEnabled()) {
        // The per-site shortcut needs the protection itself, turn it
        // on; the blocklist is already in place from the last update.
        manager->setEnabled(true);
    }
    else if (manager->isSessionAllowed(url.host())) {
        // End the "proceed anyway" exception now, not at the next
        // restart - the reload lands on the interstitial again if
        // the host is still listed. And resuming the protection
        // re-weighs the site, so the evidence is renewed on the
        // spot: the reload runs against the list in place while the
        // refresh runs beside it (the re-served warning names it in
        // flight, the location bar's badge breathing until it lands
        // or the failure is named), never in test mode - the rule
        // every update trigger follows.
        manager->removeSessionAllow(url.host());
        if (!mApp->isTestModeEnabled()) {
            manager->updateNow();
        }
        m_window->weView()->reload();
    }

    close();
}

void SiteInfoWidget::threatBlockUpdateButtonClicked()
{
    // The list-lifecycle action: start the refresh and stay open -
    // unlike the per-site choices, which take effect and close. The
    // row re-renders through the manager's own signals ("being
    // refreshed now", then either the fresh state or the failure
    // with the retry), so the update is witnessed in the place that
    // offered it.
    mApp->networkManager()->threatBlockManager()->updateNow();
    updateThreatBlockState();
}
