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
#include "selftestpage.h"
#include "adblockmanager.h"
#include "dnsoverhttpsmanager.h"
#include "fingerprintmanager.h"
#include "gpcmanager.h"
#include "httpsonlyinterceptor.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "qztools.h"
#include "settings.h"
#include "threatblockmanager.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>

namespace {

// Must match OSZA_TILE_SIZE in selftest.html.
const int kTileSize = 64;

// Example hosts for the demo tiles: reserved documentation domains,
// never routed anywhere.
const char kDemoHost1[] = "example.com";
const char kDemoHost2[] = "example.org";

} // namespace

QString SelfTestPage::buildPage()
{
    // The translated template is built once; the dynamic values
    // (statuses, demo patterns) are substituted on every request, the
    // same split as the speed dial page.
    static QString sPage;

    if (sPage.isEmpty()) {
        sPage.append(QzTools::readAllFileContents(QSL(":html/selftest.html")));

        sPage.replace(QLatin1String("%TITLE%"), tr("Security self-test"));
        sPage.replace(QLatin1String("%SUBTITLE%"), tr("Live checks of Osza's bundled protections, measured in this page exactly as a site would see them."));
        sPage.replace(QLatin1String("%SUMMARY-RUNNING%"), tr("Running the checks..."));
        sPage.replace(QLatin1String("%JAVASCRIPT-DISABLED%"), tr("The self-test requires enabled JavaScript."));

        sPage.replace(QLatin1String("%STATUS-HEADING%"), tr("Protections"));
        sPage.replace(QLatin1String("%STATUS-INTRO%"), tr("Snapshot of the moment this page was loaded \u2014 reload to refresh."));

        sPage.replace(QLatin1String("%FP-HEADING%"), tr("Fingerprint randomization \u2014 live"));
        sPage.replace(QLatin1String("%FP-INTRO%"), tr("Each check below measures a real readout of this very page, through the same hooks a fingerprinting site would use."));

        sPage.replace(QLatin1String("%NOISE-HEADING%"), tr("The invisible noise, made visible"));
        sPage.replace(QLatin1String("%NOISE-INTRO%"), tr("Fingerprint protection shifts every canvas pixel by at most \u00b11: invisible to the eye, fatal to fingerprinting. The shift is amplified below, so the per-site pattern becomes visible."));

        sPage.replace(QLatin1String("%VERIFY-HEADING%"), tr("Verify on a real site"));
        sPage.replace(QLatin1String("%VERIFY-INTRO%"), tr("Open a fingerprinting test site and check that the reported values differ from your real hardware, yet stay stable for the same site."));

        sPage.replace(QLatin1String("%RELOAD-LABEL%"), tr("Reload"));
        sPage.replace(QLatin1String("%FOOTER-NOTE%"), tr("The self-test runs entirely on this machine. Nothing is sent anywhere."));

        sPage.replace(QLatin1String("%I18N-JSON%"), i18nJson());
        sPage = QzTools::applyDirectionToPage(sPage);
    }

    QString page = sPage;
    page.replace(QLatin1String("%STATUS-JSON%"), statusesJson());
    page.replace(QLatin1String("%DEMO-PATTERNS%"), demoPatternsJson());
    return page;
}

QJsonObject SelfTestPage::toolStatus(const QString &id, const QString &label, bool on, const QString &detail)
{
    QJsonObject status;
    status.insert(QSL("id"), id);
    status.insert(QSL("label"), label);
    status.insert(QSL("on"), on);
    status.insert(QSL("detail"), detail);
    return status;
}

QJsonArray SelfTestPage::collectToolStatuses()
{
    QJsonArray statuses;

    // AdBlock
    const bool adBlock = AdBlockManager::instance()->isEnabled();
    statuses.append(toolStatus(QSL("adblock"), tr("AdBlock"), adBlock,
                               adBlock ? tr("Requests matching the filter lists are blocked.")
                                       : tr("No filter list is applied.")));

    // HTTPS-Only mode
    const bool httpsOnly = mApp->networkManager()->httpsOnlyInterceptor()->isEnabled();
    statuses.append(toolStatus(QSL("httpsonly"), tr("HTTPS-Only mode"), httpsOnly,
                               httpsOnly ? tr("Insecure http:// connections are upgraded to https://.")
                                         : tr("Insecure connections load as they are.")));

    // Tracking-parameter stripping
    bool stripTracking = false;
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        stripTracking = settings.value(QSL("StripTrackingQuery"), true).toBool();
        settings.endGroup();
    }
    statuses.append(toolStatus(QSL("striptracking"), tr("Strip tracking parameters"), stripTracking,
                               tr("utm_*, fbclid, gclid and friends are removed from links before they load.")));

    // Secure DNS
    const auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    QString dohDetail;
    if (doh->mode() == DnsOverHttpsManager::Disabled && !DnsOverHttpsManager::isSupported()) {
        dohDetail = tr("Requires QtWebEngine 6.6 or newer.");
    } else {
        switch (doh->mode()) {
        case DnsOverHttpsManager::SecureOnly:
            dohDetail = tr("DoH only, no fallback (%1).").arg(doh->serverTemplates().value(0, tr("custom")));
            break;
        case DnsOverHttpsManager::SecureWithFallback:
            dohDetail = tr("DoH with system fallback (%1).").arg(doh->serverTemplates().value(0, tr("custom")));
            break;
        case DnsOverHttpsManager::Disabled:
        default:
            dohDetail = tr("Hostname resolution goes through the system resolver.");
            break;
        }
    }
    statuses.append(toolStatus(QSL("doh"), tr("Secure DNS (DNS-over-HTTPS)"),
                               doh->mode() != DnsOverHttpsManager::Disabled, dohDetail));

    // Malicious-site protection
    const auto *threatBlock = mApp->networkManager()->threatBlockManager();
    QString threatDetail;
    if (!threatBlock->isEnabled()) {
        threatDetail = tr("Navigations to blocklisted sites are not stopped.");
    } else if (threatBlock->isUpdating()) {
        threatDetail = tr("Updating the blocklist...");
    } else if (threatBlock->hostCount() == 0) {
        threatDetail = tr("Blocklist not downloaded yet.");
    } else {
        const QString updated = threatBlock->lastUpdate().isValid()
            ? QLocale().toString(threatBlock->lastUpdate().toLocalTime(), QLocale::ShortFormat)
            : tr("unknown date");
        threatDetail = tr("%1 hosts, updated %2.").arg(QLocale().toString(threatBlock->hostCount()), updated);
    }
    statuses.append(toolStatus(QSL("threatblock"), tr("Malicious site protection"),
                               threatBlock->isEnabled(), threatDetail));

    // Fingerprint protection
    QStringList fingerprintExclusions;
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        fingerprintExclusions = settings.value(QSL("FingerprintExclusions"), QStringList()).toStringList();
        settings.endGroup();
    }
    const bool fingerprint = FingerprintManager::instance()->isEnabled();
    QString fingerprintDetail;
    if (!fingerprint) {
        fingerprintDetail = tr("Canvas, WebGL, audio and hardware readouts report your real system.");
    } else if (fingerprintExclusions.isEmpty()) {
        fingerprintDetail = tr("Canvas, WebGL, audio and hardware readouts are randomized everywhere.");
    } else {
        fingerprintDetail = tr("Randomized everywhere except %n excluded host(s).", nullptr, fingerprintExclusions.size());
    }
    statuses.append(toolStatus(QSL("fingerprint"), tr("Fingerprint protection"), fingerprint, fingerprintDetail));

    // Global Privacy Control
    const bool gpc = GpcManager::instance()->isEnabled();
    statuses.append(toolStatus(QSL("gpc"), tr("Global Privacy Control"), gpc,
                               gpc ? tr("Every request carries the Sec-GPC: 1 opt-out; pages see navigator.globalPrivacyControl = true.")
                                   : tr("No opt-out signal is sent.")));

    return statuses;
}

QString SelfTestPage::statusesJson()
{
    return jsonToScriptLiteral(QJsonDocument(collectToolStatuses()));
}

QString SelfTestPage::demoPatternsJson()
{
    QJsonArray demo;

    const quint32 seed = FingerprintManager::instance()->masterSeed();

    // A missing seed (fresh profile before loadSettings) has nothing
    // to show yet; the page handles the empty list.
    if (seed != 0) {
        const QStringList hosts = {QLatin1String(kDemoHost1), QLatin1String(kDemoHost2)};

        for (const QString &host : hosts) {
            const QVector<int> pattern = FingerprintManager::siteNoisePattern(seed, host, kTileSize);
            QString digits;
            digits.reserve(pattern.size());

            for (int deviation : pattern) {
                // -1/0/+1 becomes the digit 0/1/2, compact and ASCII.
                digits.append(QChar::fromLatin1(char('0' + deviation + 1)));
            }

            QJsonObject entry;
            entry.insert(QSL("host"), host);
            entry.insert(QSL("data"), digits);
            demo.append(entry);
        }
    }

    return jsonToScriptLiteral(QJsonDocument(demo));
}

QString SelfTestPage::i18nJson()
{
    QJsonObject strings;

    // Pills and badges
    strings.insert(QSL("pill_on"), tr("on"));
    strings.insert(QSL("pill_off"), tr("off"));
    strings.insert(QSL("badge_pass"), tr("passed"));
    strings.insert(QSL("badge_warn"), tr("attention"));
    strings.insert(QSL("badge_fail"), tr("failed"));
    strings.insert(QSL("badge_off"), tr("off"));
    strings.insert(QSL("badge_first"), tr("no baseline"));
    strings.insert(QSL("badge_na"), tr("unavailable"));

    // Test names
    strings.insert(QSL("test_guard"), tr("Guard on this page"));
    strings.insert(QSL("test_canvas"), tr("Canvas 2D readout"));
    strings.insert(QSL("test_stability"), tr("Stable across reloads"));
    strings.insert(QSL("test_webgl"), tr("WebGL GPU strings"));
    strings.insert(QSL("test_webglpixels"), tr("WebGL pixel readout"));
    strings.insert(QSL("test_audio"), tr("Audio fingerprint"));
    strings.insert(QSL("test_hardware"), tr("Hardware hints"));
    strings.insert(QSL("test_gpc"), tr("Global Privacy Control"));

    // Test notes
    strings.insert(QSL("note_guard"), tr("The randomization script must be present and must have run before this page's own scripts."));
    strings.insert(QSL("note_canvas"), tr("Digest of a canvas readout of this page \u2014 what a site would harvest. Stable for this site, different everywhere else."));
    strings.insert(QSL("note_stability"), tr("Compared with the previous load of this page in this browser window."));
    strings.insert(QSL("note_webgl"), tr("Sites read the GPU through WebGL. Generic values are chosen per site; your real hardware is not reported."));
    strings.insert(QSL("note_webglpixels"), tr("Digest of a WebGL frame readback of this page."));
    strings.insert(QSL("note_audio"), tr("The classic OfflineAudioContext value. The noise it carries is far below the threshold of hearing."));
    strings.insert(QSL("note_hardware"), tr("Two cheap high-entropy hints; both report common values instead of your real machine."));
    strings.insert(QSL("note_gpc"), tr("The opt-out signal pages see in navigator.globalPrivacyControl."));

    // Measured values
    strings.insert(QSL("value_guard_active"), tr("active on this page"));
    strings.insert(QSL("value_guard_missing"), tr("not active \u2014 the protection is on, please report this"));
    strings.insert(QSL("value_guard_off"), tr("not active"));
    strings.insert(QSL("value_stability_first"), tr("first measured load"));
    strings.insert(QSL("value_stability_same"), tr("unchanged since the previous load"));
    strings.insert(QSL("value_stability_changed"), tr("changed between loads \u2014 that should not happen"));
    strings.insert(QSL("value_gpc_true"), tr("true"));
    strings.insert(QSL("value_gpc_missing"), tr("not reported \u2014 the signal is on, please report this"));
    strings.insert(QSL("value_gpc_undefined"), tr("undefined"));

    // Summary banner
    strings.insert(QSL("summary_off"), tr("Fingerprint protection is off. Turn it on from the security sidebar to run the full suite."));
    strings.insert(QSL("summary_verified"), tr("Fingerprint randomization verified \u2014 %1 of %2 checks passed."));
    strings.insert(QSL("summary_partial"), tr("%1 of %2 checks passed \u2014 review the marked results."));

    // Tiles
    strings.insert(QSL("caption_live"), tr("This page"));
    strings.insert(QSL("sub_live"), tr("measured now"));
    strings.insert(QSL("sub_live_flat"), tr("no noise \u2014 protection is off"));
    strings.insert(QSL("sub_demo"), tr("computed for comparison"));

    return jsonToScriptLiteral(QJsonDocument(strings));
}

QString SelfTestPage::jsonToScriptLiteral(const QJsonDocument &document)
{
    // Compact JSON, embedded as a JavaScript literal. "<" is escaped
    // so no translated string can ever close the <script> element.
    return QString::fromUtf8(document.toJson(QJsonDocument::Compact))
        .replace(QChar::fromLatin1('<'), QSL("\\u003c"));
}
