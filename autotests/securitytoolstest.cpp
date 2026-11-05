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
#include "autotests.h"
#include "securitytoolstest.h"
#include "adblockmanager.h"
#include "dnsoverhttpsmanager.h"
#include "fingerprintexceptionsdialog.h"
#include "fingerprintmanager.h"
#include "gpcmanager.h"
#include "httpsonlyinterceptor.h"
#include "networkmanager.h"
#include "mainapplication.h"
#include "qzcommon.h"
#include "securitymanager.h"
#include "securityimportpreviewdialog.h"
#include "securitypresets.h"
#include "securitysettingsporter.h"
#include "securitysidebar.h"
#include "selftestpage.h"
#include "settingsdiffpage.h"
#include "settings.h"
#include "threatblockmanager.h"
#include "webpage.h"

#include <QtTest/QtTest>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QTemporaryDir>
#include <QToolButton>
#include <QTreeWidget>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>
#include <QTcpServer>
#include <QTcpSocket>

void SecurityToolsTest::securityManagerCountersTest()
{
    SecurityManager *security = SecurityManager::instance();
    QVERIFY(security);

    security->resetCounters();

    const quint64 ads = security->adsBlocked();
    const quint64 trackers = security->trackersStripped();
    const quint64 upgrades = security->httpsUpgrades();

    security->reportAdBlocked(QSL("Example.COM"));
    security->reportAdBlocked(QSL("example.com"));
    security->reportTrackerStripped(QSL("news.example.com"));
    security->reportHttpsUpgrade(QSL("http-only.example"));

    QCOMPARE(security->adsBlocked(), ads + 2);
    QCOMPARE(security->trackersStripped(), trackers + 1);
    QCOMPARE(security->httpsUpgrades(), upgrades + 1);

    // Host counters are normalized, both reports hit the same host.
    QCOMPARE(security->adsBlockedForHost(QSL("example.com")), quint64(2));
    QCOMPARE(security->adsBlockedForHost(QSL("EXAMPLE.com")), quint64(2));
    QCOMPARE(security->trackersStrippedForHost(QSL("news.example.com")), quint64(1));
    QCOMPARE(security->httpsUpgradesForHost(QSL("http-only.example")), quint64(1));

    security->resetCounters();

    QCOMPARE(security->adsBlocked(), quint64(0));
    QCOMPARE(security->trackersStripped(), quint64(0));
    QCOMPARE(security->httpsUpgrades(), quint64(0));
    QCOMPARE(security->adsBlockedForHost(QSL("example.com")), quint64(0));
}

void SecurityToolsTest::securityManagerPersistenceTest()
{
    SecurityManager *security = SecurityManager::instance();

    security->resetCounters();
    security->reportHttpsUpgrade(QSL("persist.example"));

    const quint64 expected = security->httpsUpgrades();
    QVERIFY(expected > 0);

    security->saveCounters();
    security->loadCounters();

    QCOMPARE(security->httpsUpgrades(), expected);

    security->resetCounters();
}

void SecurityToolsTest::httpsOnlyExclusionTest()
{
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    QVERIFY(interceptor);

    // isolate from other tests / user settings
    interceptor->removeExclusion(QSL("add.example"));
    interceptor->removeExclusion(QSL("sub.add.example"));

    QVERIFY(!interceptor->hasExplicitExclusion(QSL("add.example")));
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("sub.add.example")));

    interceptor->addExclusion(QSL("add.example"));

    QVERIFY(interceptor->hasExplicitExclusion(QSL("add.example")));
    // exclusion covers subdomains too
    QVERIFY(interceptor->hasExplicitExclusion(QSL("sub.add.example")));
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("other.example")));

    // the full check also treats loopback and private ranges as excluded
    QVERIFY(interceptor->isExcluded(QSL("localhost")));
    QVERIFY(interceptor->isExcluded(QSL("192.168.1.1")));
    QVERIFY(interceptor->isExcluded(QSL("add.example")));

    interceptor->removeExclusion(QSL("add.example"));

    QVERIFY(!interceptor->hasExplicitExclusion(QSL("add.example")));

    // persisting was part of the API
    QCOMPARE(mApp->networkManager()->httpsOnlyInterceptor()->hasExplicitExclusion(QSL("add.example")), false);
}

void SecurityToolsTest::httpsOnlyHostMatchingTest()
{
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();

    interceptor->addExclusion(QSL("*.wild.example"));

    // wildcard patterns match subdomains only, not the bare domain
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("wild.example")));
    QVERIFY(interceptor->hasExplicitExclusion(QSL("deep.wild.example")));
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("wild.example.evil.com")));
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("evilwild.example")));

    interceptor->removeExclusion(QSL("*.wild.example"));

    QVERIFY(!interceptor->hasExplicitExclusion(QSL("wild.example")));
}

void SecurityToolsTest::dnsOverHttpsConfigurationTest()
{
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    QVERIFY(doh);

    // restore whatever the profile had configured
    const auto restoreMode = doh->mode();
    const auto restoreServers = doh->serverTemplates();

    if (!DnsOverHttpsManager::isSupported()) {
        QSKIP("DNS-over-HTTPS requires QtWebEngine 6.6+");
    }

    // an empty server list is invalid for a secure mode
    QVERIFY(!doh->setConfiguration(DnsOverHttpsManager::SecureWithFallback, QStringList()));

    // a garbage template is rejected by the engine
    QVERIFY(!doh->setConfiguration(DnsOverHttpsManager::SecureOnly, {QSL("not-a-template")}));

    // disabling always works
    QVERIFY(doh->setConfiguration(DnsOverHttpsManager::Disabled, {}));

    QCOMPARE(doh->mode(), DnsOverHttpsManager::Disabled);
    QCOMPARE(doh->isApplied(), true);

    // a valid template is accepted
    QVERIFY(doh->setConfiguration(DnsOverHttpsManager::SecureWithFallback, {QSL("https://dns.google/dns-query{?dns}")}));
    QCOMPARE(doh->mode(), DnsOverHttpsManager::SecureWithFallback);
    QCOMPARE(doh->serverTemplates(), QStringList{QSL("https://dns.google/dns-query{?dns}")});

    doh->setConfiguration(restoreMode, restoreServers);
}

void SecurityToolsTest::dnsOverHttpsProvidersTest()
{
    const auto providers = DnsOverHttpsManager::knownProviders();

    QVERIFY(!providers.isEmpty());

    for (const auto &provider : providers) {
        QVERIFY(!provider.name.isEmpty());
        QVERIFY(provider.template_.startsWith(QSL("https://")));
        QVERIFY(provider.template_.contains(QSL("dns-query")));
        QVERIFY(provider.template_.endsWith(QSL("{?dns}")));
    }
}

void SecurityToolsTest::securityDashboardWidgetTest()
{
    // The dashboard must build and refresh without a browser window.
    SecuritySideBar sidebar(nullptr);
    sidebar.refresh();
    sidebar.show();
    QVERIFY(QTest::qWaitForWindowExposed(&sidebar));

    // The self-test shortcut exists and is a no-op without a window
    // (it must not crash the sidebar-less dashboard).
    auto *selfTestButton = sidebar.findChild<QToolButton*>(QSL("selftestButton"));
    QVERIFY(selfTestButton);
    QVERIFY(selfTestButton->isVisible());
    sidebar.openSelfTest();

    // The HTTPS-Only quick switch must apply through the interceptor.
    const bool httpsOnlyBefore = mApp->networkManager()->httpsOnlyInterceptor()->isEnabled();

    sidebar.toggleHttpsOnly(!httpsOnlyBefore);
    QCOMPARE(mApp->networkManager()->httpsOnlyInterceptor()->isEnabled(), !httpsOnlyBefore);

    // The per-site exclusion shortcuts must work through the same API.
    mApp->networkManager()->httpsOnlyInterceptor()->addExclusion(QSL("dashboard.example"));
    QVERIFY(mApp->networkManager()->httpsOnlyInterceptor()->hasExplicitExclusion(QSL("dashboard.example")));
    mApp->networkManager()->httpsOnlyInterceptor()->removeExclusion(QSL("dashboard.example"));

    // The DoH quick switch must apply a real engine configuration.
    if (DnsOverHttpsManager::isSupported()) {
        sidebar.toggleSecureDns(true);
        auto *doh = mApp->networkManager()->dnsOverHttpsManager();
        QCOMPARE(doh->mode() != DnsOverHttpsManager::Disabled, true);
        QVERIFY(doh->isApplied());

        sidebar.toggleSecureDns(false);
        QCOMPARE(doh->mode(), DnsOverHttpsManager::Disabled);
    }

    // The threat block quick switch must apply through the manager.
    const bool threatBlockBefore = mApp->networkManager()->threatBlockManager()->isEnabled();

    sidebar.toggleThreatBlock(!threatBlockBefore);
    QCOMPARE(mApp->networkManager()->threatBlockManager()->isEnabled(), !threatBlockBefore);

    // The fingerprint protection quick switch must apply through the manager.
    const bool fingerprintBefore = FingerprintManager::instance()->isEnabled();

    sidebar.toggleFingerprintProtection(!fingerprintBefore);
    QCOMPARE(FingerprintManager::instance()->isEnabled(), !fingerprintBefore);

    // The GPC quick switch must apply through the manager.
    const bool gpcBefore = GpcManager::instance()->isEnabled();

    sidebar.toggleGpc(!gpcBefore);
    QCOMPARE(GpcManager::instance()->isEnabled(), !gpcBefore);

    // restore the original state
    sidebar.toggleHttpsOnly(httpsOnlyBefore);
    sidebar.toggleThreatBlock(threatBlockBefore);
    sidebar.toggleFingerprintProtection(fingerprintBefore);
    sidebar.toggleGpc(gpcBefore);
}

void SecurityToolsTest::threatBlockListParsingTest()
{
    // URL-per-line feeds (comments and full URLs, like the classic
    // URLhaus export or an OpenPhish-style feed).
    const QByteArray urlLines =
        "# URLhaus - the largest repository of malware URLs\n"
        "# Last modified: 2026-11-03 00:00:00 UTC\n"
        "\n"
        "http://malware.example.com/payload.exe\n"
        "http://Tracker.EXAMPLE.ru/download?id=1\n"
        "https://phish.example.org/login?next=%2Fadmin\n";

    QSet<QString> hosts;
    QCOMPARE(ThreatBlockManager::parseListData(urlLines, &hosts), 3);
    QCOMPARE(hosts.size(), 3);
    QVERIFY(hosts.contains(QSL("malware.example.com")));
    QVERIFY(hosts.contains(QSL("tracker.example.ru")));
    QVERIFY(hosts.contains(QSL("phish.example.org")));

    // Hosts-file format: IP, whitespace (spaces or tabs) and several
    // names per line.
    const QByteArray hostsFile =
        "# blocklist\n"
        "0.0.0.0 ads.example\n"
        "127.0.0.1\ttracker.example\tbeacon.example\n";

    QSet<QString> hostsFileHosts;
    QCOMPARE(ThreatBlockManager::parseListData(hostsFile, &hostsFileHosts), 3);
    QVERIFY(hostsFileHosts.contains(QSL("ads.example")));
    QVERIFY(hostsFileHosts.contains(QSL("tracker.example")));
    QVERIFY(hostsFileHosts.contains(QSL("beacon.example")));

    // Bare hosts, normalization and garbage rejection.
    const QByteArray mixed =
        "Bare.Example.\n"                       // trailing dot + case
        "xn--bser-5qa.example\n"                 // already ASCII
        "http://m\xc3\xbcnchen.example/x\n"     // IDN URL -> punycode host
        "localhost\n"                            // never listed
        "this is not a host\n"                   // multiple non-IP tokens
        "path/with/slashes\n"                    // not a bare host
        "\n";

    QSet<QString> mixedHosts;
    QCOMPARE(ThreatBlockManager::parseListData(mixed, &mixedHosts), 3);
    QVERIFY(mixedHosts.contains(QSL("bare.example")));
    QVERIFY(mixedHosts.contains(QSL("xn--bser-5qa.example")));
    QVERIFY(mixedHosts.contains(QSL("xn--mnchen-3ya.example")));
    QVERIFY(!mixedHosts.contains(QString::fromUtf8("münchen.example"))); // stored as ACE

    // The IDN name must be stored exactly like the engine reports it.
    const QString ace = ThreatBlockManager::normalizeHost(QString::fromUtf8("MÜNCHEN.Example"));
    QVERIFY(mixedHosts.contains(ace));
    QCOMPARE(ace, QSL("xn--mnchen-3ya.example"));

    // Empty data adds nothing.
    QSet<QString> empty;
    QCOMPARE(ThreatBlockManager::parseListData(QByteArray(), &empty), 0);
    QVERIFY(empty.isEmpty());
}

void SecurityToolsTest::threatBlockHostMatchingTest()
{
    auto *manager = mApp->networkManager()->threatBlockManager();

    // isolate from other tests
    manager->applyListData(QByteArray("http://bad.example/x\nhttp://worse.example.org/y\n"));
    QCOMPARE(manager->hostCount(), 2);
    QVERIFY(manager->isListLoaded());

    // exact matches
    QVERIFY(manager->isHostBlocked(QSL("bad.example")));
    QVERIFY(manager->isHostBlocked(QSL("BAD.Example")));
    QVERIFY(manager->isHostBlocked(QSL("bad.example.")));

    // subdomains of a listed host are blocked too
    QVERIFY(manager->isHostBlocked(QSL("www.bad.example")));
    QVERIFY(manager->isHostBlocked(QSL("deep.www.bad.example")));

    // suffix spoofing must not match
    QVERIFY(!manager->isHostBlocked(QSL("evilbad.example")));
    QVERIFY(!manager->isHostBlocked(QSL("bad.example.evil.org")));
    QVERIFY(!manager->isHostBlocked(QSL("notbad.example")));

    // unrelated hosts
    QVERIFY(!manager->isHostBlocked(QSL("good.example")));
    QVERIFY(!manager->isHostBlocked(QSL("example.org")));
    QVERIFY(!manager->isHostBlocked(QString()));

    // the full decision honors the enabled state
    const bool enabledBefore = manager->isEnabled();
    manager->setEnabled(false);
    QVERIFY(!manager->shouldBlock(QSL("bad.example")));
    manager->setEnabled(true);
    QVERIFY(manager->shouldBlock(QSL("bad.example")));
    manager->setEnabled(enabledBefore);

    // an empty list blocks nothing
    manager->applyListData(QByteArray());
    QCOMPARE(manager->hostCount(), 0);
    QVERIFY(!manager->isHostBlocked(QSL("bad.example")));
    QVERIFY(!manager->shouldBlock(QSL("bad.example")));
}

void SecurityToolsTest::threatBlockSessionAllowTest()
{
    auto *manager = mApp->networkManager()->threatBlockManager();

    manager->applyListData(QByteArray("http://proceed.example/x\n"));
    QVERIFY(manager->shouldBlock(QSL("proceed.example")));

    // the interstitial's "proceed anyway" grants a session exception
    manager->allowForSession(QSL("PROCEED.example"));
    QVERIFY(manager->isSessionAllowed(QSL("proceed.example")));
    QVERIFY(!manager->shouldBlock(QSL("proceed.example")));
    QVERIFY(!manager->shouldBlock(QSL("www.proceed.example")));

    // other listed hosts keep being blocked
    QVERIFY(manager->shouldBlock(QSL("proceed.example.org")) == false); // not listed at all
    manager->applyListData(QByteArray("http://proceed.example/x\nhttp://other.example/y\n"));
    QVERIFY(manager->isSessionAllowed(QSL("proceed.example")));
    QVERIFY(!manager->shouldBlock(QSL("proceed.example")));
    QVERIFY(manager->shouldBlock(QSL("other.example")));
}

void SecurityToolsTest::threatBlockPageUrlTest()
{
    const QList<QUrl> urls = {
        QUrl(QSL("http://bad.example/path?q=a%20b&x=1")),
        QUrl(QSL("https://user@host.example:8443/a/b/c#frag")),
        QUrl(QSL("http://böser.example/x")),
        QUrl(QSL("http://bad.example/?url=http%3A%2F%2Fspoof.example%2F")),
    };

    for (const QUrl &url : urls) {
        const QUrl page = ThreatBlockManager::blockPageUrl(url);
        QCOMPARE(page.scheme(), QSL("osza"));
        QCOMPARE(page.path(), QSL("threatblocked"));
        QVERIFY(!ThreatBlockManager::isProceedPageUrl(page));

        const QUrl decoded = ThreatBlockManager::blockedUrlFromPageUrl(page);
        QVERIFY(decoded.isValid());
        QCOMPARE(decoded, url);
    }

    // the proceed variant round-trips as well
    const QUrl url(QSL("http://proceed.example/p?a=1&b=2"));
    const QUrl proceed = ThreatBlockManager::blockPageUrl(url, true);
    QVERIFY(ThreatBlockManager::isProceedPageUrl(proceed));
    QCOMPARE(ThreatBlockManager::blockedUrlFromPageUrl(proceed), url);

    // the URL of an interstitial holding an encoded '&'
    const QUrl amp(QSL("http://amp.example/x?a=1&b=2"));
    QCOMPARE(ThreatBlockManager::blockedUrlFromPageUrl(ThreatBlockManager::blockPageUrl(amp, true)), amp);

    // unrelated URLs are rejected
    QVERIFY(!ThreatBlockManager::blockedUrlFromPageUrl(QUrl(QSL("osza:start"))).isValid());
    QVERIFY(!ThreatBlockManager::blockedUrlFromPageUrl(QUrl(QSL("osza:threatblocked"))).isValid());
    QVERIFY(!ThreatBlockManager::blockedUrlFromPageUrl(QUrl(QSL("http://bad.example/"))).isValid());
    QVERIFY(!ThreatBlockManager::isProceedPageUrl(QUrl(QSL("osza:threatblocked?url=http%3A%2F%2Fx.example%2F"))));
}

void SecurityToolsTest::threatBlockInterstitialTest()
{
    auto *manager = mApp->networkManager()->threatBlockManager();

    manager->applyListData(QByteArray("http://bad.example/x\n"));

    const QUrl blocked(QSL("http://bad.example/payload.exe?x=<script>&q=1"));
    const QString page = manager->interstitialPage(blocked);

    // the page states what happened and for whom
    QVERIFY(page.contains(QSL("Dangerous site blocked")));
    QVERIFY(page.contains(QSL("bad.example")));

    // the URL is escaped by the URL encoding and HTML escaping - an
    // injection via the URL must not reach the document unescaped
    QVERIFY(page.contains(QSL("payload.exe?x=%3Cscript%3E&amp;q=1")));
    QVERIFY(!page.contains(QSL("?x=<script>")));

    // both ways out are wired to the scheme handler (the '&' of the
    // proceed URL is HTML-escaped inside the href attribute)
    const QString proceedHref = QSL("osza:threatblocked?url=")
        + QString::fromLatin1(QUrl::toPercentEncoding(blocked.toString()))
        + QSL("&amp;proceed=1");
    QVERIFY(page.contains(proceedHref));
    QVERIFY(page.contains(QSL("osza:start")));

    // the blocklist state is honest before the first download
    manager->applyListData(QByteArray());
    const QString emptyPage = manager->interstitialPage(blocked);
    QVERIFY(emptyPage.contains(QSL("not downloaded yet")));
}

void SecurityToolsTest::threatBlockManagerStateTest()
{
    auto *manager = mApp->networkManager()->threatBlockManager();

    // restore whatever the profile had configured
    const bool enabledBefore = manager->isEnabled();
    const QString sourceBefore = manager->sourceUrl();

    // toggling persists through Settings
    manager->setEnabled(!enabledBefore);
    QCOMPARE(manager->isEnabled(), !enabledBefore);

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        QCOMPARE(settings.value(QSL("ThreatBlockEnabled")).toBool(), !enabledBefore);
        settings.endGroup();
    }

    manager->setEnabled(enabledBefore);

    // a fresh manager picks up the persisted list and state
    manager->applyListData(QByteArray("http://persist.example/x\n"));
    QVERIFY(manager->lastUpdate().isValid());

    ThreatBlockManager fresh;
    fresh.loadSettings();
    QCOMPARE(fresh.isEnabled(), enabledBefore);
    QCOMPARE(fresh.hostCount(), 1);
    QVERIFY(fresh.isHostBlocked(QSL("persist.example")));
    QCOMPARE(fresh.sourceUrl(), manager->sourceUrl());

    // the source is validated before a refresh is attempted
    manager->setSourceUrl(QSL("ftp://blocklists.example/list.txt"));
    QSignalSpy failedSpy(manager, &ThreatBlockManager::updateFailed);
    manager->updateNow();
    QCOMPARE(failedSpy.count(), 1);

    manager->setSourceUrl(sourceBefore);

    // leave the shared manager clean for the other tests
    manager->applyListData(QByteArray());
    manager->loadSettings();
}

void SecurityToolsTest::threatBlockIntegrationTest()
{
    // Full end-to-end check through the real WebEngine interception:
    // a navigation to a listed host must land on the osza:threatblocked
    // interstitial, and the "proceed anyway" link must load the site.
    // Interception happens before any connection is made, so the
    // non-existent example hosts never touch the network.
    auto *manager = mApp->networkManager()->threatBlockManager();

    const bool enabledBefore = manager->isEnabled();
    manager->setEnabled(true);
    manager->applyListData(QByteArray("http://blocked-integration.example/x\n"));
    QVERIFY(manager->shouldBlock(QSL("blocked-integration.example")));

    SecurityManager::instance()->resetCounters();

    // WebPage runs on the application profile, where the security
    // tools interceptors and the osza: scheme handler are installed.
    WebPage page;

    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    page.load(QUrl(QSL("http://blocked-integration.example/payload?q=1")));
    QVERIFY(loadFinishedSpy.wait(20000));
    QVERIFY(loadFinishedSpy.takeFirst().at(0).toBool());

    // The navigation was redirected to the interstitial.
    QCOMPARE(page.url().scheme(), QSL("osza"));
    QCOMPARE(page.url().path(), QSL("threatblocked"));
    QCOMPARE(ThreatBlockManager::blockedUrlFromPageUrl(page.url()), QUrl(QSL("http://blocked-integration.example/payload?q=1")));

    // And the counter recorded the block.
    QCOMPARE(SecurityManager::instance()->threatsBlocked(), quint64(1));

    // The rendered page is the interstitial for this host.
    QString title;
    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    page.runJavaScript(QSL("document.title + '|' + (document.body.innerText.indexOf('blocked-integration.example') >= 0)"), [&title, &loop](const QVariant &result) {
        title = result.toString();
        loop.quit();
    });
    loop.exec();
    QVERIFY(title.startsWith(QSL("Dangerous site blocked")));
    QVERIFY(title.endsWith(QSL("|true")));

    // "Proceed anyway": loading the proceed URL adds the session
    // exception and navigates to the blocked site. The site does not
    // exist, so the load fails - but with the original URL, not with
    // another interstitial.
    loadFinishedSpy.clear();
    page.load(ThreatBlockManager::blockPageUrl(QUrl(QSL("http://blocked-integration.example/payload?q=1")), true));
    QVERIFY(loadFinishedSpy.wait(20000));

    QVERIFY(!manager->isSessionAllowed(QSL("some-other.example")));
    QVERIFY(manager->isSessionAllowed(QSL("blocked-integration.example")));
    QCOMPARE(page.url().host(), QSL("blocked-integration.example"));
    QCOMPARE(page.url().path(), QSL("/payload"));

    // The exception is scoped to the session and the listed host.
    QVERIFY(!manager->shouldBlock(QSL("blocked-integration.example")));
    QVERIFY(manager->shouldBlock(QSL("sub.blocked-integration.example")) == false);

    // restore
    manager->applyListData(QByteArray());
    manager->setEnabled(enabledBefore);
    SecurityManager::instance()->resetCounters();
}

OSZATEST_MAIN(SecurityToolsTest)

void SecurityToolsTest::fingerprintScriptSourceTest()
{
    // An empty exclusion list embeds an empty JSON array, the master
    // seed is embedded verbatim and as an unsigned normalization.
    QString source = FingerprintManager::buildScriptSource(1234567890, QStringList());
    QVERIFY(source.contains(QLatin1String("var EXCLUSIONS = [];")));
    QVERIFY(source.contains(QLatin1String("var MASTER_SEED = 1234567890 >>> 0;")));

    // Exclusions are embedded as JSON, blank entries are dropped.
    source = FingerprintManager::buildScriptSource(42, {QSL(" Example.COM "), QString(), QSL("*.wild.example")});
    QVERIFY(source.contains(QLatin1String("var EXCLUSIONS = [\"Example.COM\",\"*.wild.example\"];")));
    QVERIFY(source.contains(QLatin1String("var MASTER_SEED = 42 >>> 0;")));

    // Every classic fingerprinting readout is covered.
    QVERIFY(source.contains(QLatin1String("getImageData")));
    QVERIFY(source.contains(QLatin1String("toDataURL")));
    QVERIFY(source.contains(QLatin1String("toBlob")));
    QVERIFY(source.contains(QLatin1String("convertToBlob")));
    QVERIFY(source.contains(QLatin1String("readPixels")));
    QVERIFY(source.contains(QLatin1String("getChannelData")));
    QVERIFY(source.contains(QLatin1String("copyFromChannel")));
    QVERIFY(source.contains(QLatin1String("getFloatFrequencyData")));
    QVERIFY(source.contains(QLatin1String("hardwareConcurrency")));

    // The placeholders are always substituted, whatever the input.
    QVERIFY(!source.contains(QLatin1String("%EXCLUSIONS%")));
    QVERIFY(!source.contains(QLatin1String("%MASTER_SEED%")));

    // A different master seed (another browser profile) changes the guard.
    QVERIFY(FingerprintManager::buildScriptSource(1, QStringList()) != FingerprintManager::buildScriptSource(2, QStringList()));
    QVERIFY(FingerprintManager::buildScriptSource(7, {QSL("a.example")}) != FingerprintManager::buildScriptSource(7, {QSL("b.example")}));
}

void SecurityToolsTest::fingerprintExclusionTest()
{
    auto *manager = FingerprintManager::instance();
    QVERIFY(manager);

    // isolate from other tests / user settings
    manager->removeExclusion(QSL("fp.example"));
    manager->removeExclusion(QSL("*.fp-wild.example"));

    QVERIFY(!manager->isExcluded(QSL("fp.example")));

    // addExclusion normalizes the host
    manager->addExclusion(QSL("  FP.Example  "));

    // exact and subdomain matches, case-insensitive
    QVERIFY(manager->isExcluded(QSL("fp.example")));
    QVERIFY(manager->isExcluded(QSL("www.fp.example")));
    QVERIFY(manager->isExcluded(QSL("DEEP.FP.example")));

    // suffix spoofing and unrelated hosts never match
    QVERIFY(!manager->isExcluded(QSL("evilfp.example")));
    QVERIFY(!manager->isExcluded(QSL("fp.example.evil.org")));
    QVERIFY(!manager->isExcluded(QSL("other.example")));
    QVERIFY(!manager->isExcluded(QString()));

    // wildcard entries match subdomains only, not the bare domain
    manager->addExclusion(QSL("*.fp-wild.example"));
    QVERIFY(manager->isExcluded(QSL("deep.fp-wild.example")));
    QVERIFY(!manager->isExcluded(QSL("fp-wild.example")));
    QVERIFY(!manager->isExcluded(QSL("evilfp-wild.example")));

    manager->removeExclusion(QSL("fp.example"));
    manager->removeExclusion(QSL("*.fp-wild.example"));

    QVERIFY(!manager->isExcluded(QSL("fp.example")));
    QVERIFY(!manager->isExcluded(QSL("www.fp.example")));
    QVERIFY(!manager->isExcluded(QSL("deep.fp-wild.example")));
}

void SecurityToolsTest::fingerprintExceptionsDialogTest()
{
    // The management dialog round-trips the exclusion list: blank
    // entries are dropped and the rest is handed back verbatim.
    FingerprintExceptionsDialog dialog({QSL("  FP.Example  "), QString(), QSL("*.wild.example")});

    const QStringList exclusions = dialog.exclusions();
    QCOMPARE(exclusions.size(), 2);
    QVERIFY(exclusions.contains(QSL("FP.Example")));
    QVERIFY(exclusions.contains(QSL("*.wild.example")));

    // The dialog's result flows through the same settings path the
    // preferences window uses, and the manager picks it up: entries
    // cover their subdomains, wildcards cover subdomains only.
    Settings::globalSettings()->setValue(QSL("Web-Browser-Settings/FingerprintExclusions"), exclusions);
    FingerprintManager::instance()->loadSettings();

    QVERIFY(FingerprintManager::instance()->isExcluded(QSL("fp.example")));
    QVERIFY(FingerprintManager::instance()->isExcluded(QSL("www.fp.example")));
    QVERIFY(FingerprintManager::instance()->isExcluded(QSL("deep.wild.example")));
    QVERIFY(!FingerprintManager::instance()->isExcluded(QSL("wild.example")));
    QVERIFY(!FingerprintManager::instance()->isExcluded(QSL("other.example")));

    // restore the empty list the other tests expect
    Settings::globalSettings()->setValue(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList());
    FingerprintManager::instance()->loadSettings();
    QVERIFY(!FingerprintManager::instance()->isExcluded(QSL("fp.example")));
}

void SecurityToolsTest::fingerprintScriptLifecycleTest()
{
    auto *manager = FingerprintManager::instance();
    auto *profile = mApp->webProfile();
    QVERIFY(profile);

    // Protection on -> exactly one guard script is in the profile.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    manager->loadSettings();

    const QString name = QSL("_osza_fingerprint_guard");
    QCOMPARE(profile->scripts()->find(name).count(), 1);
    const QString source = profile->scripts()->find(name).value(0).sourceCode();
    QVERIFY(source.contains(QLatin1String("fingerprint guard")));
    QVERIFY(!source.contains(QLatin1String("%EXCLUSIONS%")));
    QVERIFY(!source.contains(QLatin1String("%MASTER_SEED%")));

    // The script runs in the main world before the page, on subframes too.
    const QWebEngineScript script = profile->scripts()->find(name).value(0);
    QCOMPARE(script.worldId(), quint32(QWebEngineScript::MainWorld));
    QCOMPARE(script.injectionPoint(), QWebEngineScript::DocumentCreation);
    QVERIFY(script.runsOnSubFrames());

    // Refreshing never duplicates the script.
    manager->updateScript();
    manager->updateScript();
    QCOMPARE(profile->scripts()->find(name).count(), 1);

    // An exclusion is baked into the regenerated script.
    manager->addExclusion(QSL("fp-lifecycle.example"));
    QCOMPARE(profile->scripts()->find(name).count(), 1);
    QVERIFY(profile->scripts()->find(name).value(0).sourceCode().contains(QLatin1String("fp-lifecycle.example")));
    manager->removeExclusion(QSL("fp-lifecycle.example"));
    QCOMPARE(profile->scripts()->find(name).count(), 1);
    QVERIFY(!profile->scripts()->find(name).value(0).sourceCode().contains(QLatin1String("fp-lifecycle.example")));

    // Protection off -> the script is gone.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), false);
        settings.endGroup();
    }
    manager->loadSettings();
    QCOMPARE(manager->isEnabled(), false);
    QCOMPARE(profile->scripts()->find(name).count(), 0);

    // Restore the protection-on default for the other tests.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    manager->loadSettings();
    QCOMPARE(manager->isEnabled(), true);
    QCOMPARE(profile->scripts()->find(name).count(), 1);
}

void SecurityToolsTest::fingerprintIntegrationTest()
{
    // Full end-to-end check through the real script injection: the
    // guard must run in the main world, canvas readouts must be
    // stable for one host, differ between hosts, and stay original
    // on excluded hosts. Everything runs against synthetic hosts, so
    // no request ever leaves the machine.
    auto *manager = FingerprintManager::instance();

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    manager->removeExclusion(QSL("fp-excluded.example"));
    manager->removeExclusion(QSL("fp-excluded2.example"));
    manager->loadSettings();

    const QString html = QSL("<html><body><canvas id='c' width='120' height='40'></canvas></body></html>");
    const QString probe = QSL(
        "(function() {"
        "  var c = document.getElementById('c');"
        "  var ctx = c.getContext('2d');"
        "  for (var x = 0; x < c.width; x++) {"
        "    ctx.fillStyle = 'rgb(' + (x * 2) + ', 60, ' + (255 - x * 2) + ')';"
        "    ctx.fillRect(x, 0, 1, c.height);"
        "  }"
        "  return c.toDataURL();"
        "})()");

    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    auto loadAndProbe = [&page, &loadFinishedSpy, &html, &probe](const QString &host) {
        loadFinishedSpy.clear();
        page.setHtml(html, QUrl(QSL("https://%1/fp-test").arg(host)));
        if (!loadFinishedSpy.wait(20000)) {
            return QString();
        }

        QString result;
        QEventLoop loop;
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        page.runJavaScript(probe, [&result, &loop](const QVariant &value) {
            result = value.toString();
            loop.quit();
        });
        loop.exec();
        return result;
    };

    // The guard ran in the main world and left no enumerable marker.
    {
        loadFinishedSpy.clear();
        page.setHtml(html, QUrl(QSL("https://fp-a.example/fp-test")));
        QVERIFY(loadFinishedSpy.wait(20000));

        QString marker;
        QEventLoop loop;
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        page.runJavaScript(QSL("window.__oszaFingerprintGuard + '|' + Object.keys(window).indexOf('__oszaFingerprintGuard')"), [&marker, &loop](const QVariant &value) {
            marker = value.toString();
            loop.quit();
        });
        loop.exec();
        QCOMPARE(marker, QSL("1|-1"));
    }

    const QString hostA1 = loadAndProbe(QSL("fp-a.example"));
    const QString hostA2 = loadAndProbe(QSL("fp-a.example"));
    const QString hostB = loadAndProbe(QSL("fp-b.example"));

    QVERIFY(!hostA1.isEmpty());
    QVERIFY(hostA1.startsWith(QSL("data:image/png;base64,")));

    // Same host: the readout is stable across loads (not itself
    // fingerprintable).
    QCOMPARE(hostA1, hostA2);

    // Different host: the readout differs.
    QVERIFY(hostA1 != hostB);

    // Excluded hosts keep the original, unperturbed readout: two
    // excluded hosts must produce identical (pristine) strings, and
    // that string must differ from the perturbed host A readout.
    manager->addExclusion(QSL("fp-excluded.example"));
    manager->addExclusion(QSL("fp-excluded2.example"));

    const QString excluded1 = loadAndProbe(QSL("fp-excluded.example"));
    const QString excluded2 = loadAndProbe(QSL("fp-excluded2.example"));

    QVERIFY(excluded1.startsWith(QSL("data:image/png;base64,")));
    QCOMPARE(excluded1, excluded2);
    QVERIFY(excluded1 != hostA1);

    // restore the state the other tests expect
    manager->removeExclusion(QSL("fp-excluded.example"));
    manager->removeExclusion(QSL("fp-excluded2.example"));
    manager->loadSettings();
}

namespace {

// Write the GPC preference and make both halves of the signal follow
// it: the DOM script through GpcManager, the Sec-GPC header through
// the network stack.
void applyGpcSetting(bool enabled)
{
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("GlobalPrivacyControl"), enabled);
    settings.endGroup();

    GpcManager::instance()->loadSettings();
    mApp->networkManager()->loadSettings();
}

} // namespace

void SecurityToolsTest::gpcScriptSourceTest()
{
    const QString source = GpcManager::signalScriptSource();

    // The signal property is defined on the Navigator prototype.
    QVERIFY(source.contains(QLatin1String("globalPrivacyControl")));
    QVERIFY(source.contains(QLatin1String("window.Navigator.prototype")));

    // The marker keeps the script idempotent and non-enumerable.
    QVERIFY(source.contains(QLatin1String("__oszaGpcSignal")));
    QVERIFY(source.contains(QLatin1String("enumerable: false")));

    // It reports true, the value the GPC specification requires.
    QVERIFY(source.contains(QLatin1String("return true;")));

    // Every hook fails closed to the unmodified environment.
    QVERIFY(source.contains(QLatin1String("catch (e)")));

    // The source is a constant: there is nothing left to substitute.
    QVERIFY(!source.contains(QLatin1String("%")));
}

void SecurityToolsTest::gpcScriptLifecycleTest()
{
    auto *manager = GpcManager::instance();
    auto *profile = mApp->webProfile();
    QVERIFY(profile);

    // Signal on -> exactly one signal script is in the profile.
    applyGpcSetting(true);
    QCOMPARE(manager->isEnabled(), true);

    const QString name = QSL("_osza_gpc_signal");
    QCOMPARE(profile->scripts()->find(name).count(), 1);

    // The script runs in the main world before the page, on subframes too.
    const QWebEngineScript script = profile->scripts()->find(name).value(0);
    QCOMPARE(script.worldId(), quint32(QWebEngineScript::MainWorld));
    QCOMPARE(script.injectionPoint(), QWebEngineScript::DocumentCreation);
    QVERIFY(script.runsOnSubFrames());
    QVERIFY(script.sourceCode().contains(QLatin1String("globalPrivacyControl")));

    // Refreshing never duplicates the script.
    manager->updateScript();
    manager->updateScript();
    QCOMPARE(profile->scripts()->find(name).count(), 1);

    // Signal off -> the script is gone (and the property with it).
    applyGpcSetting(false);
    QCOMPARE(manager->isEnabled(), false);
    QCOMPARE(profile->scripts()->find(name).count(), 0);

    // setEnabled is the API the dashboard uses; it must persist too.
    manager->setEnabled(true);
    QCOMPARE(manager->isEnabled(), true);
    QCOMPARE(profile->scripts()->find(name).count(), 1);
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        QCOMPARE(settings.value(QSL("GlobalPrivacyControl")).toBool(), true);
        settings.endGroup();
    }
    manager->setEnabled(false);
    QCOMPARE(profile->scripts()->find(name).count(), 0);

    // Restore the signal-on default for the other tests.
    applyGpcSetting(true);
    QCOMPARE(profile->scripts()->find(name).count(), 1);
}

void SecurityToolsTest::gpcDomSignalIntegrationTest()
{
    // Full end-to-end check through the real script injection: pages
    // must see navigator.globalPrivacyControl === true while the
    // signal is on, and the plain browser behaviour (no property at
    // all) while it is off. The synthetic host never leaves the machine.
    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    const QString html = QSL("<html><head><link rel='icon' href='data:,'></head><body></body></html>");
    const QString probe = QSL(
        "(function() {"
        "  var marker = Object.keys(window).indexOf('__oszaGpcSignal');"
        "  return typeof navigator.globalPrivacyControl + '|' + navigator.globalPrivacyControl + '|' + marker;"
        "})()");

    auto loadAndProbe = [&page, &loadFinishedSpy, &html, &probe](const QString &host) {
        loadFinishedSpy.clear();
        page.setHtml(html, QUrl(QSL("https://%1/gpc-test").arg(host)));
        if (!loadFinishedSpy.wait(20000)) {
            return QString();
        }

        QString result;
        QEventLoop loop;
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        page.runJavaScript(probe, [&result, &loop](const QVariant &value) {
            result = value.toString();
            loop.quit();
        });
        loop.exec();
        return result;
    };

    // Signal on: the property is a boolean true, set before any page
    // script runs, and the marker leaves no enumerable key behind.
    applyGpcSetting(true);
    QCOMPARE(loadAndProbe(QSL("gpc-on.example")), QSL("boolean|true|-1"));

    // Signal off: the property is gone, exactly like a browser
    // without GPC support.
    applyGpcSetting(false);
    QCOMPARE(loadAndProbe(QSL("gpc-off.example")), QSL("undefined|undefined|-1"));

    // restore the signal-on default for the other tests
    applyGpcSetting(true);
}

void SecurityToolsTest::gpcHeaderIntegrationTest()
{
    // Full end-to-end check of the network half: a one-shot HTTP
    // server on loopback captures the raw request, proving the
    // Sec-GPC opt-out really leaves the browser with the navigation.
    // Loopback is never HTTPS-upgraded, so plain HTTP works.

    // The capture must not depend on the machine the test runs on: a
    // system proxy configuration could swallow the loopback request
    // before it ever reaches the server. Force a direct connection
    // for the duration of the test, like the proxy-off preference.
    QNetworkProxyFactory::setUseSystemConfiguration(false);
    QNetworkProxy noProxy;
    noProxy.setType(QNetworkProxy::NoProxy);
    QNetworkProxy::setApplicationProxy(noProxy);

    QTcpServer server;
    QVERIFY(server.listen(QHostAddress(QHostAddress::LocalHost), 0));
    const quint16 port = server.serverPort();

    // Serve exactly one page; the data: favicon keeps Chromium from
    // issuing a second request that could race the navigation.
    const QByteArray body = "<html><head><link rel='icon' href='data:,'></head><body>ok</body></html>";
    const QByteArray response = QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: ")
        + QByteArray::number(body.size()) + QByteArrayLiteral("\r\n\r\n") + body;

    // Accept connections until the one asking for the given path
    // shows up; anything else is answered and dropped. The wait spins
    // the event loop in short slices: the navigation only progresses
    // while events are processed, so a plain blocking wait would
    // deadlock the request that is supposed to arrive.
    auto captureRequest = [&server, &response](const QString &path, QString *captured) -> bool {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < 20000) {
            QEventLoop loop;
            QTimer::singleShot(200, &loop, &QEventLoop::quit);
            QObject::connect(&server, &QTcpServer::newConnection, &loop, &QEventLoop::quit);
            loop.exec();
            while (server.hasPendingConnections()) {
                QTcpSocket *socket = server.nextPendingConnection();
                QByteArray raw;
                QElapsedTimer readTimer;
                readTimer.start();
                while (!raw.contains("\r\n\r\n") && readTimer.elapsed() < 5000) {
                    socket->waitForReadyRead(200);
                    raw += socket->readAll();
                }
                socket->write(response);
                socket->flush();
                socket->disconnectFromHost();
                if (socket->state() == QAbstractSocket::ConnectedState) {
                    socket->waitForDisconnected(2000);
                }
                const QByteArray requestLine = QByteArrayLiteral("GET ") + path.toLatin1() + QByteArrayLiteral(" HTTP");
                if (raw.startsWith(requestLine)) {
                    *captured = QString::fromLatin1(raw);
                    return true;
                }
            }
        }
        return false;
    };

    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    // Signal on -> the navigation carries Sec-GPC: 1.
    applyGpcSetting(true);

    page.load(QUrl(QSL("http://127.0.0.1:%1/gpc-on").arg(port)));
    QString rawOn;
    QVERIFY(captureRequest(QSL("/gpc-on"), &rawOn));
    if (loadFinishedSpy.count() == 0) {
        QVERIFY(loadFinishedSpy.wait(20000));
    }
    QVERIFY(loadFinishedSpy.last().at(0).toBool());

    QVERIFY(rawOn.contains(QSL("Host: 127.0.0.1")));
    QVERIFY(rawOn.contains(QLatin1String("sec-gpc: 1"), Qt::CaseInsensitive));

    // Signal off -> no trace of the header at all.
    applyGpcSetting(false);

    page.load(QUrl(QSL("http://127.0.0.1:%1/gpc-off").arg(port)));
    QString rawOff;
    QVERIFY(captureRequest(QSL("/gpc-off"), &rawOff));
    if (loadFinishedSpy.count() == 0) {
        QVERIFY(loadFinishedSpy.wait(20000));
    }

    QVERIFY(rawOff.contains(QSL("Host: 127.0.0.1")));
    QVERIFY(!rawOff.contains(QLatin1String("sec-gpc"), Qt::CaseInsensitive));

    // restore the signal-on default for the other tests, and the
    // system proxy resolution the app would use
    applyGpcSetting(true);
    QNetworkProxy::setApplicationProxy(QNetworkProxy());
    QNetworkProxyFactory::setUseSystemConfiguration(true);
}

void SecurityToolsTest::selfTestNoisePatternTest()
{
    // The C++ mirror of the guard's perturbation: deterministic,
    // in range, and different per host and per profile seed.
    const QVector<int> a = FingerprintManager::siteNoisePattern(1234567890u, QSL("SelfTest.Example"), 64);
    const QVector<int> aLower = FingerprintManager::siteNoisePattern(1234567890u, QSL("selftest.example"), 64);

    QCOMPARE(a.size(), 64 * 64);

    // Hosts are case-folded, exactly like the guard's siteKey().
    QVERIFY(a == aLower);

    QSet<int> values;
    for (int deviation : a) {
        QVERIFY(deviation >= -1);
        QVERIFY(deviation <= 1);
        values.insert(deviation);
    }

    // A real noise pattern, not a flat buffer.
    QVERIFY(values.size() >= 2);

    // Same seed, different host -> a different pattern.
    const QVector<int> otherHost = FingerprintManager::siteNoisePattern(1234567890u, QSL("other.example"), 64);
    QVERIFY(a != otherHost);

    // Same host, different seed (another browser profile) -> a different pattern.
    const QVector<int> otherSeed = FingerprintManager::siteNoisePattern(987654321u, QSL("selftest.example"), 64);
    QVERIFY(a != otherSeed);

    // The empty host (what osza: pages have) is a valid key too.
    const QVector<int> emptyHost = FingerprintManager::siteNoisePattern(1234567890u, QString(), 64);
    QCOMPARE(emptyHost.size(), 64 * 64);
    QVERIFY(a != emptyHost);

    // Degenerate sizes are rejected, a 1x1 pattern still works.
    QVERIFY(FingerprintManager::siteNoisePattern(1, QSL("x.example"), 0).isEmpty());
    QVERIFY(FingerprintManager::siteNoisePattern(1, QSL("x.example"), -3).isEmpty());
    QCOMPARE(FingerprintManager::siteNoisePattern(7, QSL("x.example"), 1).size(), 1);
}

void SecurityToolsTest::selfTestNoiseEquivalenceTest()
{
    // THE cross-implementation check: the pixel deviations a real
    // page measures through the injected guard script must be exactly
    // the values FingerprintManager::siteNoisePattern() computes for
    // the same seed and host. The seed is pinned on both sides.
    auto *manager = FingerprintManager::instance();

    const quint32 originalSeed = manager->masterSeed();
    const quint32 pinnedSeed = 305419896u; // 0x12345678

    {
        Settings settings;
        settings.beginGroup(QSL("Security-Tools"));
        settings.setValue(QSL("FingerprintSeed"), pinnedSeed);
        settings.endGroup();
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    manager->loadSettings();
    QCOMPARE(manager->masterSeed(), pinnedSeed);

    // A 64x64 canvas filled with solid middle gray; the guard shifts
    // each RGB channel by -1/0/+1, so the red channel of every pixel
    // is 128 + deviation. Reported as digits 0/1/2 (deviation + 1).
    const QString html = QSL("<html><body><canvas id='c' width='64' height='64'></canvas></body></html>");
    const QString probe = QSL(
        "(function() {"
        "  var c = document.getElementById('c');"
        "  var ctx = c.getContext('2d');"
        "  ctx.fillStyle = 'rgb(128, 128, 128)';"
        "  ctx.fillRect(0, 0, c.width, c.height);"
        "  var data = ctx.getImageData(0, 0, c.width, c.height).data;"
        "  var out = '';"
        "  for (var p = 0; p < c.width * c.height; p++) {"
        "    out += String.fromCharCode(48 + (data[p * 4] - 128 + 1));"
        "  }"
        "  return out;"
        "})()");

    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    page.setHtml(html, QUrl(QSL("https://fp-noise.example/equivalence")));
    QVERIFY(loadFinishedSpy.wait(20000));

    QString digits;
    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    page.runJavaScript(probe, [&digits, &loop](const QVariant &value) {
        digits = value.toString();
        loop.quit();
    });
    loop.exec();

    QCOMPARE(digits.size(), 64 * 64);

    const QVector<int> expected = FingerprintManager::siteNoisePattern(pinnedSeed, QSL("fp-noise.example"), 64);
    QCOMPARE(expected.size(), 64 * 64);

    for (int i = 0; i < expected.size(); ++i) {
        QCOMPARE(digits.at(i).toLatin1() - '0', expected.at(i) + 1);
    }

    // restore the seed the profile had (a missing one is removed
    // again so the next start regenerates it)
    {
        Settings settings;
        settings.beginGroup(QSL("Security-Tools"));
        if (originalSeed != 0) {
            settings.setValue(QSL("FingerprintSeed"), originalSeed);
        } else {
            settings.remove(QSL("FingerprintSeed"));
        }
        settings.endGroup();
    }
    manager->loadSettings();
}

void SecurityToolsTest::selfTestPageBuildTest()
{
    // The page builds with every placeholder substituted and carries
    // the statuses of all seven bundled tools.
    const QString page = SelfTestPage::buildPage();

    QVERIFY(page.contains(QLatin1String("osza-selftest")));
    QVERIFY(page.contains(QSL("Security self-test")));
    QVERIFY(!page.contains(QLatin1String("%TITLE%")));
    QVERIFY(!page.contains(QLatin1String("%STATUS-JSON%")));
    QVERIFY(!page.contains(QLatin1String("%DEMO-PATTERNS%")));
    QVERIFY(!page.contains(QLatin1String("%I18N-JSON%")));
    QVERIFY(!page.contains(QLatin1String("%DIRECTION%")));

    const QJsonArray statuses = SelfTestPage::collectToolStatuses();
    QCOMPARE(statuses.size(), 7);

    QStringList ids;
    for (const QJsonValue &value : statuses) {
        const QJsonObject status = value.toObject();
        QVERIFY(status.contains(QSL("id")));
        QVERIFY(status.contains(QSL("label")));
        QVERIFY(status.contains(QSL("on")));
        QVERIFY(status.contains(QSL("detail")));
        QVERIFY(!status.value(QSL("label")).toString().isEmpty());
        QVERIFY(!status.value(QSL("detail")).toString().isEmpty());
        ids << status.value(QSL("id")).toString();
    }

    const QStringList expectedIds = {QSL("adblock"), QSL("httpsonly"), QSL("striptracking"),
                                     QSL("doh"), QSL("threatblock"), QSL("fingerprint"), QSL("gpc")};
    for (const QString &id : expectedIds) {
        QVERIFY(ids.contains(id));
    }

    // The statuses follow the settings: toggling fingerprint
    // protection flips its entry.
    auto *manager = FingerprintManager::instance();
    const bool enabledBefore = manager->isEnabled();

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), !enabledBefore);
        settings.endGroup();
    }
    manager->loadSettings();

    bool reflected = false;
    for (const QJsonValue &value : SelfTestPage::collectToolStatuses()) {
        const QJsonObject status = value.toObject();
        if (status.value(QSL("id")).toString() == QSL("fingerprint")) {
            reflected = status.value(QSL("on")).toBool() == !enabledBefore;
        }
    }
    QVERIFY(reflected);

    // The demo patterns are embedded once a seed exists.
    if (manager->masterSeed() != 0) {
        QVERIFY(page.contains(QSL("example.com")));
        QVERIFY(page.contains(QSL("example.org")));
    }

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), enabledBefore);
        settings.endGroup();
    }
    manager->loadSettings();
}

void SecurityToolsTest::selfTestPageIntegrationTest()
{
    // The real page through the real osza: scheme handler: it must
    // load, render the seven statuses, run every live check, expose a
    // correct SHA-256, and measure a canvas digest that is stable
    // across reloads of the same page.
    auto *manager = FingerprintManager::instance();
    const bool enabledBefore = manager->isEnabled();

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    manager->loadSettings();
    QVERIFY(manager->masterSeed() != 0);

    auto runScript = [](WebPage *page, const QString &script) {
        QString result;
        QEventLoop loop;
        QTimer::singleShot(8000, &loop, &QEventLoop::quit);
        page->runJavaScript(script, [&result, &loop](const QVariant &value) {
            result = value.toString();
            loop.quit();
        });
        loop.exec();
        return result;
    };

    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    auto loadAndSettle = [&]() -> bool {
        loadFinishedSpy.clear();
        page.load(QUrl(QSL("osza:selftest")));
        if (!loadFinishedSpy.wait(20000)) {
            return false;
        }

        // Wait until the asynchronous checks (audio) settled too.
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < 20000) {
            if (runScript(&page, QSL("window.__oszaSelfTest && window.__oszaSelfTest.done ? 'done' : 'busy'")) == QSL("done")) {
                return true;
            }
        }
        return false;
    };

    QVERIFY(loadAndSettle());

    // The page rendered: seven status rows, the test cards, the
    // tiles (live page + two demo hosts).
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('#st-statuses li.st-row').length")).toInt(), 7);
    QVERIFY(runScript(&page, QSL("document.querySelectorAll('.st-test').length")).toInt() >= 8);
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.st-tile').length")).toInt(), 3);

    // The statuses the page carries match the settings.
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.statuses.filter(function(s) { return s.id === 'fingerprint'; })[0].on")),
             QSL("true"));
    QCOMPARE(runScript(&page, QSL("document.querySelector('li[data-id=fingerprint] .st-pill--on') === null ? 'missing' : 'shown'")),
             QSL("shown"));

    // The self-contained SHA-256 matches the published test vectors.
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.sha256('abc')")),
             QSL("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.sha256('')")),
             QSL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    // The guard is live on the page and the canvas check passed.
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.results.guard.verdict")), QSL("pass"));
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.results.canvas.verdict")), QSL("pass"));

    // A 64 hex character digest, stable across reloads of the page.
    const QString firstDigest = runScript(&page, QSL("window.__oszaSelfTest.canvasHash"));
    QCOMPARE(firstDigest.size(), 64);
    QVERIFY(QRegularExpression(QSL("^[0-9a-f]{64}$")).match(firstDigest).hasMatch());

    QVERIFY(loadAndSettle());
    QCOMPARE(runScript(&page, QSL("window.__oszaSelfTest.canvasHash")), firstDigest);

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), enabledBefore);
        settings.endGroup();
    }
    manager->loadSettings();
}

void SecurityToolsTest::settingsPorterDocumentTest()
{
    // The identity of the format is a stable contract with every
    // settings file ever written.
    QCOMPARE(SecuritySettingsPorter::formatIdentifier(), QSL("osza-security-settings"));
    QCOMPARE(SecuritySettingsPorter::formatVersion(), 1);

    const QJsonObject document = SecuritySettingsPorter::buildDocument();

    QCOMPARE(document.value(QSL("format")).toString(), QSL("osza-security-settings"));
    QCOMPARE(document.value(QSL("version")).toInt(), 1);
    QVERIFY(QDateTime::fromString(document.value(QSL("exportedAt")).toString(), Qt::ISODate).isValid());

    // All seven bundled tools are covered, each with an enabled state.
    const QJsonObject tools = document.value(QSL("tools")).toObject();
    const QStringList expectedTools = {QSL("adblock"), QSL("httpsOnly"), QSL("trackingParameters"),
                                       QSL("secureDns"), QSL("threatBlock"), QSL("fingerprintProtection"),
                                       QSL("globalPrivacyControl")};
    QCOMPARE(tools.size(), expectedTools.size());

    for (const QString &id : expectedTools) {
        QVERIFY(tools.value(id).isObject());
        QVERIFY(tools.value(id).toObject().contains(QSL("enabled")));
    }

    // The exported state follows the live managers, not stale keys:
    // flipping the interceptor is reflected in the next document.
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    const bool httpsOnlyBefore = interceptor->isEnabled();
    const QStringList exclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/HttpsOnlyExclusions"), QStringList()).toStringList();

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), !httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), QStringList{QSL("document.porter.example")});
        settings.endGroup();
    }
    interceptor->loadSettings();

    const QJsonObject updated = SecuritySettingsPorter::buildDocument();
    const QJsonObject httpsOnly = updated.value(QSL("tools")).toObject().value(QSL("httpsOnly")).toObject();
    QCOMPARE(httpsOnly.value(QSL("enabled")).toBool(), !httpsOnlyBefore);
    QCOMPARE(httpsOnly.value(QSL("exclusions")).toArray().size(), 1);
    QCOMPARE(httpsOnly.value(QSL("exclusions")).toArray().at(0).toString(), QSL("document.porter.example"));

    // The per-profile secrets and the usage history never leave the
    // profile: neither the fingerprint master seed nor any protection
    // counter appears anywhere in the serialized document.
    const QByteArray serialized = QJsonDocument(updated).toJson(QJsonDocument::Compact);
    QVERIFY(!serialized.contains("seed"));
    QVERIFY(!serialized.contains("Seed"));
    QVERIFY(!serialized.contains("AdsBlocked"));
    QVERIFY(!serialized.contains("TrackersStripped"));
    QVERIFY(!serialized.contains("HttpsUpgrades"));
    QVERIFY(!serialized.contains("ThreatsBlocked"));

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), exclusionsBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
}

void SecurityToolsTest::settingsPorterRoundTripTest()
{
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    auto *threatBlock = mApp->networkManager()->threatBlockManager();
    auto *fingerprint = FingerprintManager::instance();
    auto *gpc = GpcManager::instance();
    auto *adblock = AdBlockManager::instance();

    const bool dohSupported = DnsOverHttpsManager::isSupported();

    // Snapshot every piece of state the porter touches.
    const bool httpsOnlyBefore = interceptor->isEnabled();
    const bool stripTrackingBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool();
    const bool fingerprintBefore = fingerprint->isEnabled();
    const bool gpcBefore = gpc->isEnabled();
    const bool adblockBefore = adblock->isEnabled();
    const bool threatEnabledBefore = threatBlock->isEnabled();
    const QString threatSourceBefore = threatBlock->sourceUrl();
    const QStringList httpsExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/HttpsOnlyExclusions"), QStringList()).toStringList();
    const QStringList fingerprintExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList()).toStringList();
    const auto dohModeBefore = doh->mode();
    const QStringList dohServersBefore = doh->serverTemplates();

    // A distinctive target configuration, deliberately different from
    // the current state of every tool.
    const bool adblockTarget = !adblockBefore;
    const bool httpsOnlyTarget = !httpsOnlyBefore;
    const bool stripTrackingTarget = !stripTrackingBefore;
    const bool fingerprintTarget = !fingerprintBefore;
    const bool gpcTarget = !gpcBefore;
    const bool threatEnabledTarget = !threatEnabledBefore;
    const QString threatSourceTarget = QSL("https://porter.example/hosts");
    const QStringList httpsExclusionsTarget = {QSL("legacy.porter.example"), QSL("*.wild.porter.example")};
    const QStringList fingerprintExclusionsTarget = {QSL("bank.porter.example")};
    const QStringList dohServersTarget = {QSL("https://dns.porter.example/dns-query{?dns}")};
    const auto dohModeTarget = DnsOverHttpsManager::SecureWithFallback;

    // Phase 1: apply the target state through the normal manager APIs.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyTarget);
        settings.setValue(QSL("HttpsOnlyExclusions"), httpsExclusionsTarget);
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingTarget);
        settings.setValue(QSL("FingerprintProtection"), fingerprintTarget);
        settings.setValue(QSL("FingerprintExclusions"), fingerprintExclusionsTarget);
        settings.setValue(QSL("GlobalPrivacyControl"), gpcTarget);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcTarget);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockTarget);
    threatBlock->setEnabled(threatEnabledTarget);
    threatBlock->setSourceUrl(threatSourceTarget);
    if (dohSupported) {
        doh->setConfiguration(dohModeTarget, dohServersTarget);
    }

    // Phase 2: export through the file path, exactly like the UI does.
    const QJsonObject expectedTools = SecuritySettingsPorter::buildDocument().value(QSL("tools")).toObject();

    QTemporaryDir dir;
    const QString path = dir.filePath(QSL("porter-roundtrip.json"));

    QString error;
    QVERIFY(SecuritySettingsPorter::exportToFile(path, &error));

    // The written file is indented, non-empty JSON with the live
    // configuration, and the tools section matches the snapshot.
    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
    const QByteArray raw = file.readAll();
    file.close();
    QVERIFY(!raw.isEmpty());
    QVERIFY(raw.contains('\n'));

    QJsonParseError parseError;
    const QJsonDocument written = QJsonDocument::fromJson(raw, &parseError);
    QCOMPARE(parseError.error, QJsonParseError::NoError);
    QCOMPARE(written.object().value(QSL("format")).toString(), QSL("osza-security-settings"));
    QCOMPARE(written.object().value(QSL("tools")).toObject(), expectedTools);

    // Phase 3: move every tool away from the target state, so the
    // import has live state to change, not just written keys.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), QStringList{QSL("old.porter.example")});
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingBefore);
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.setValue(QSL("FingerprintExclusions"), QStringList{QSL("old.porter.example")});
        settings.setValue(QSL("GlobalPrivacyControl"), gpcBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcBefore);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockBefore);
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }

    QCOMPARE(interceptor->isEnabled(), httpsOnlyBefore);
    QVERIFY(interceptor->hasExplicitExclusion(QSL("old.porter.example")));
    QCOMPARE(adblock->isEnabled(), adblockBefore);
    QCOMPARE(threatBlock->isEnabled(), threatEnabledBefore);
    QCOMPARE(fingerprint->isEnabled(), fingerprintBefore);
    QCOMPARE(gpc->isEnabled(), gpcBefore);

    // Phase 4: import through the file path.
    const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);

    QVERIFY(result.ok);
    QVERIFY(result.error.isEmpty());
    if (dohSupported) {
        QCOMPARE(result.appliedTools, 7);
        QCOMPARE(result.skippedTools.size(), 0);
    } else {
        QCOMPARE(result.appliedTools, 6);
        QCOMPARE(result.skippedTools.size(), 1);
        QVERIFY(result.skippedTools.constFirst().startsWith(QSL("secureDns")));
    }

    // Phase 5: every tool arrived, through the same APIs the
    // dashboard uses.
    QCOMPARE(adblock->isEnabled(), adblockTarget);
    QCOMPARE(interceptor->isEnabled(), httpsOnlyTarget);
    QVERIFY(interceptor->hasExplicitExclusion(QSL("legacy.porter.example")));
    QVERIFY(interceptor->hasExplicitExclusion(QSL("deep.wild.porter.example")));
    QVERIFY(!interceptor->hasExplicitExclusion(QSL("old.porter.example")));

    QCOMPARE(Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool(), stripTrackingTarget);

    if (dohSupported) {
        QCOMPARE(doh->mode(), dohModeTarget);
        QCOMPARE(doh->serverTemplates(), dohServersTarget);
    }

    QCOMPARE(threatBlock->isEnabled(), threatEnabledTarget);
    QCOMPARE(threatBlock->sourceUrl(), threatSourceTarget);

    QCOMPARE(fingerprint->isEnabled(), fingerprintTarget);
    QVERIFY(fingerprint->isExcluded(QSL("bank.porter.example")));
    QVERIFY(!fingerprint->isExcluded(QSL("old.porter.example")));
    QCOMPARE(Settings::globalSettings()->value(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList()).toStringList(),
             fingerprintExclusionsTarget);

    QCOMPARE(gpc->isEnabled(), gpcTarget);

    // The guard script follows the imported fingerprint state.
    if (fingerprintTarget) {
        QVERIFY(!mApp->webProfile()->scripts()->find(QSL("_osza_fingerprint_guard")).isEmpty());
    } else {
        QVERIFY(mApp->webProfile()->scripts()->find(QSL("_osza_fingerprint_guard")).isEmpty());
    }

    // Phase 6: the format round-trips without loss - exporting the
    // imported state yields the same tools section again.
    QCOMPARE(SecuritySettingsPorter::buildDocument().value(QSL("tools")).toObject(), expectedTools);

    // Phase 7: restore the profile exactly as it was found.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), httpsExclusionsBefore);
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingBefore);
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.setValue(QSL("FingerprintExclusions"), fingerprintExclusionsBefore);
        settings.setValue(QSL("GlobalPrivacyControl"), gpcBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcBefore);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockBefore);
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }

    QCOMPARE(interceptor->isEnabled(), httpsOnlyBefore);
    QCOMPARE(fingerprint->isEnabled(), fingerprintBefore);
    QCOMPARE(gpc->isEnabled(), gpcBefore);
    QCOMPARE(adblock->isEnabled(), adblockBefore);
    QCOMPARE(threatBlock->isEnabled(), threatEnabledBefore);
    QCOMPARE(threatBlock->sourceUrl(), threatSourceBefore);
    QCOMPARE(doh->mode(), dohModeBefore);
    QCOMPARE(doh->serverTemplates(), dohServersBefore);
}

void SecurityToolsTest::settingsPorterValidationTest()
{
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    auto *threatBlock = mApp->networkManager()->threatBlockManager();
    auto *fingerprint = FingerprintManager::instance();

    const bool dohSupported = DnsOverHttpsManager::isSupported();
    const auto dohModeBefore = doh->mode();
    const QStringList dohServersBefore = doh->serverTemplates();
    const bool threatEnabledBefore = threatBlock->isEnabled();
    const QString threatSourceBefore = threatBlock->sourceUrl();
    const bool fingerprintBefore = fingerprint->isEnabled();

    QTemporaryDir dir;

    auto writeDocument = [&dir](const QByteArray &data) {
        const QString path = dir.filePath(QSL("document.json"));
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            return QString();
        }
        file.write(data);
        file.close();
        return path;
    };

    auto makeDocument = [](const QJsonObject &tools) {
        QJsonObject document;
        document.insert(QSL("format"), QSL("osza-security-settings"));
        document.insert(QSL("version"), 1);
        document.insert(QSL("tools"), tools);
        return document;
    };

    // A file that does not exist is a fatal error.
    SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(dir.filePath(QSL("missing.json")));
    QVERIFY(!result.ok);
    QVERIFY(!result.error.isEmpty());
    QCOMPARE(result.appliedTools, 0);
    QCOMPARE(result.skippedTools.size(), 0);

    // Not JSON at all.
    result = SecuritySettingsPorter::importFromFile(writeDocument(QByteArrayLiteral("this is not json")));
    QVERIFY(!result.ok);
    QCOMPARE(result.appliedTools, 0);

    // JSON, but not an object.
    result = SecuritySettingsPorter::importFromFile(writeDocument(QByteArrayLiteral("[1, 2, 3]")));
    QVERIFY(!result.ok);

    // A different format identifier.
    {
        QJsonObject document;
        document.insert(QSL("format"), QSL("something-else"));
        document.insert(QSL("version"), 1);
        result = SecuritySettingsPorter::importFromFile(writeDocument(QJsonDocument(document).toJson()));
        QVERIFY(!result.ok);
    }

    // A newer format version is refused instead of guessed.
    {
        QJsonObject document;
        document.insert(QSL("format"), QSL("osza-security-settings"));
        document.insert(QSL("version"), 2);
        document.insert(QSL("tools"), QJsonObject());
        result = SecuritySettingsPorter::importFromFile(writeDocument(QJsonDocument(document).toJson()));
        QVERIFY(!result.ok);
        QVERIFY(result.error.contains(QSL("newer")));
    }

    // The header validation helper agrees on all of the above.
    {
        QJsonObject good;
        good.insert(QSL("format"), QSL("osza-security-settings"));
        good.insert(QSL("version"), 1);
        QVERIFY(SecuritySettingsPorter::validateDocumentHeader(good, nullptr));

        QJsonObject badFormat;
        badFormat.insert(QSL("format"), QSL("other"));
        badFormat.insert(QSL("version"), 1);
        QString error;
        QVERIFY(!SecuritySettingsPorter::validateDocumentHeader(badFormat, &error));
        QVERIFY(!error.isEmpty());

        QJsonObject noVersion;
        noVersion.insert(QSL("format"), QSL("osza-security-settings"));
        QVERIFY(!SecuritySettingsPorter::validateDocumentHeader(noVersion, nullptr));
    }

    // "tools" must be an object when present.
    {
        QJsonObject document;
        document.insert(QSL("format"), QSL("osza-security-settings"));
        document.insert(QSL("version"), 1);
        document.insert(QSL("tools"), 42);
        result = SecuritySettingsPorter::applyDocument(document);
        QVERIFY(!result.ok);
    }

    // A document without any tool section is valid, but does nothing.
    {
        QJsonObject document;
        document.insert(QSL("format"), QSL("osza-security-settings"));
        document.insert(QSL("version"), 1);
        result = SecuritySettingsPorter::applyDocument(document);
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 0);
        QCOMPARE(result.skippedTools.size(), 0);
    }

    // Empty tools is valid too.
    result = SecuritySettingsPorter::applyDocument(makeDocument(QJsonObject()));
    QVERIFY(result.ok);
    QCOMPARE(result.appliedTools, 0);

    // One malformed section does not stop the others, and unknown
    // tools are ignored instead of rejected.
    {
        QJsonObject tools;
        tools.insert(QSL("adblock"), QJsonObject{{QSL("enabled"), QSL("yes")}});
        tools.insert(QSL("httpsOnly"), QJsonObject{{QSL("enabled"), true}, {QSL("exclusions"), QSL("not-an-array")}});
        tools.insert(QSL("fingerprintProtection"), QJsonObject{{QSL("enabled"), true}});
        tools.insert(QSL("timeMachine"), QJsonObject{{QSL("enabled"), false}});

        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 1);
        QCOMPARE(result.skippedTools.size(), 2);

        bool adblockSkipped = false;
        bool httpsOnlySkipped = false;
        for (const QString &entry : std::as_const(result.skippedTools)) {
            if (entry.startsWith(QSL("adblock"))) {
                adblockSkipped = true;
            }
            if (entry.startsWith(QSL("httpsOnly"))) {
                httpsOnlySkipped = true;
            }
        }
        QVERIFY(adblockSkipped);
        QVERIFY(httpsOnlySkipped);

        // the healthy section was applied for real
        QCOMPARE(fingerprint->isEnabled(), true);
    }

    // The blocklist source must be a URL the downloader accepts.
    {
        QJsonObject tools;
        tools.insert(QSL("threatBlock"), QJsonObject{{QSL("enabled"), true}, {QSL("sourceUrl"), QSL("not a url at all")}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 0);
        QCOMPARE(result.skippedTools.size(), 1);
        QVERIFY(result.skippedTools.constFirst().startsWith(QSL("threatBlock")));
        QCOMPARE(threatBlock->isEnabled(), threatEnabledBefore);
    }
    {
        QJsonObject tools;
        tools.insert(QSL("threatBlock"), QJsonObject{{QSL("enabled"), true}, {QSL("sourceUrl"), QSL("ftp://porter.example/hosts")}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 0);
    }
    {
        QJsonObject tools;
        tools.insert(QSL("threatBlock"), QJsonObject{{QSL("enabled"), true}, {QSL("sourceUrl"), QSL("https://porter.example/hosts")}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 1);
        QCOMPARE(threatBlock->isEnabled(), true);
        QCOMPARE(threatBlock->sourceUrl(), QSL("https://porter.example/hosts"));
    }

    // A secure DNS mode without servers cannot work.
    {
        QJsonObject tools;
        tools.insert(QSL("secureDns"), QJsonObject{{QSL("mode"), 1}, {QSL("servers"), QJsonArray{}}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 0);
        QCOMPARE(result.skippedTools.size(), 1);
        QVERIFY(result.skippedTools.constFirst().startsWith(QSL("secureDns")));
        if (dohSupported) {
            QVERIFY(result.skippedTools.constFirst().contains(QSL("server")));
        }
    }

    // A mode outside the enum is a type error.
    {
        QJsonObject tools;
        tools.insert(QSL("secureDns"), QJsonObject{{QSL("mode"), 9}, {QSL("servers"), QJsonArray{QSL("https://dns.porter.example/dns-query{?dns}")}}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 0);
        QVERIFY(result.skippedTools.constFirst().startsWith(QSL("secureDns")));
    }

    // A valid secure DNS section applies through the engine.
    if (dohSupported) {
        QJsonObject tools;
        tools.insert(QSL("secureDns"), QJsonObject{{QSL("mode"), 2},
                                                   {QSL("servers"), QJsonArray{QSL("https://dns.porter.example/dns-query{?dns}")}}});
        result = SecuritySettingsPorter::applyDocument(makeDocument(tools));
        QVERIFY(result.ok);
        QCOMPARE(result.appliedTools, 1);
        QCOMPARE(doh->mode(), DnsOverHttpsManager::SecureOnly);
        QCOMPARE(doh->serverTemplates(), QStringList{QSL("https://dns.porter.example/dns-query{?dns}")});
    }

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.endGroup();
    }
    fingerprint->loadSettings();
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }

    QCOMPARE(fingerprint->isEnabled(), fingerprintBefore);
    QCOMPARE(threatBlock->isEnabled(), threatEnabledBefore);
    QCOMPARE(threatBlock->sourceUrl(), threatSourceBefore);
    QCOMPARE(doh->mode(), dohModeBefore);
    QCOMPARE(doh->serverTemplates(), dohServersBefore);
}

void SecurityToolsTest::settingsPorterChecksumTest()
{
    auto *adblock = AdBlockManager::instance();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();

    const bool adblockBefore = adblock->isEnabled();
    const bool httpsOnlyBefore = interceptor->isEnabled();

    QTemporaryDir dir;
    const QString path = dir.filePath(QSL("checksum.json"));

    // A document without a checksum field - an export of an older
    // version, or a deliberate hand edit - has nothing to verify.
    {
        QJsonObject document;
        document.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        document.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        document.insert(QSL("tools"), QJsonObject());

        QCOMPARE(SecuritySettingsPorter::checkChecksum(document),
                 SecuritySettingsPorter::ChecksumState::NoChecksum);
    }

    // The live document carries a checksum over its tools section,
    // computed exactly the documented way.
    const QJsonObject document = SecuritySettingsPorter::buildDocument();

    QCOMPARE(SecuritySettingsPorter::checksumAlgorithm(), QSL("sha256"));
    QCOMPARE(SecuritySettingsPorter::checkChecksum(document),
             SecuritySettingsPorter::ChecksumState::Valid);

    {
        const QJsonObject checksum = document.value(QSL("checksum")).toObject();
        QCOMPARE(checksum.value(QSL("algorithm")).toString(), QSL("sha256"));

        // The documented mechanism, recomputed here: the SHA-256 of
        // the compact serialization of the tools object.
        const QByteArray canonical = QJsonDocument(document.value(QSL("tools")).toObject())
                                         .toJson(QJsonDocument::Compact);
        const QByteArray digest = QCryptographicHash::hash(canonical, QCryptographicHash::Sha256);
        QCOMPARE(checksum.value(QSL("tools")).toString(), QString::fromLatin1(digest.toHex()));
    }

    // A genuine export imports through the file path without warnings.
    QString error;
    QVERIFY(SecuritySettingsPorter::exportToFile(path, &error));

    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
        const QJsonDocument written = QJsonDocument::fromJson(file.readAll());
        file.close();

        QCOMPARE(SecuritySettingsPorter::checkChecksum(written.object()),
                 SecuritySettingsPorter::ChecksumState::Valid);
    }

    {
        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);
        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
        QVERIFY(result.error.isEmpty());
    }

    // Reformatting the file keeps the checksum valid: it pins the
    // parsed content, never the raw bytes.
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
        QJsonDocument written = QJsonDocument::fromJson(file.readAll());
        file.close();

        const QByteArray reformatted = QJsonDocument(written.object()).toJson(QJsonDocument::Compact);
        QVERIFY(reformatted != QJsonDocument(written.object()).toJson(QJsonDocument::Indented));

        QFile rewritten(path);
        QVERIFY(rewritten.open(QIODevice::WriteOnly | QIODevice::Truncate));
        rewritten.write(reformatted);
        rewritten.close();

        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);
        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
    }

    // Tampering with a setting breaks the checksum; the import is
    // refused, nothing is applied, and the result says why.
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
        QJsonDocument tampered = QJsonDocument::fromJson(file.readAll());
        file.close();

        QJsonObject tools = tampered.object().value(QSL("tools")).toObject();
        QJsonObject adblockTool = tools.value(QSL("adblock")).toObject();
        adblockTool.insert(QSL("enabled"), !adblockTool.value(QSL("enabled")).toBool());
        tools.insert(QSL("adblock"), adblockTool);
        QJsonObject root = tampered.object();
        root.insert(QSL("tools"), tools);
        tampered.setObject(root);

        QFile rewrite(path);
        QVERIFY(rewrite.open(QIODevice::WriteOnly | QIODevice::Truncate));
        rewrite.write(QJsonDocument(tampered.object()).toJson(QJsonDocument::Indented));
        rewrite.close();

        QCOMPARE(SecuritySettingsPorter::checkChecksum(tampered.object()),
                 SecuritySettingsPorter::ChecksumState::Mismatch);

        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);
        QVERIFY(!result.ok);
        QVERIFY(result.checksumMismatch);
        QVERIFY(!result.error.isEmpty());
        QCOMPARE(result.appliedTools, 0);
        QCOMPARE(result.skippedTools.size(), 0);

        // the tampered AdBlock state was really not applied
        QCOMPARE(adblock->isEnabled(), adblockBefore);

        // with the explicit override the import goes through, and
        // reports that the checksum was overridden
        const SecuritySettingsPorter::ImportResult forced =
            SecuritySettingsPorter::importFromFile(path, SecuritySettingsPorter::ChecksumPolicy::Allow);
        QVERIFY(forced.ok);
        QVERIFY(forced.checksumMismatch);
        QCOMPARE(adblock->isEnabled(), !adblockBefore);

        // restore for the following checks
        adblock->setEnabled(adblockBefore);
    }

    // A malformed checksum field is a mismatch, never an acceptance:
    // not an object, an unknown algorithm, a non-string value, or a
    // digest of the wrong length.
    {
        QJsonObject base = SecuritySettingsPorter::buildDocument();

        auto check = [&](const QJsonValue &checksumValue) {
            QJsonObject document2 = base;
            document2.insert(QSL("checksum"), checksumValue);
            return SecuritySettingsPorter::checkChecksum(document2);
        };

        QCOMPARE(check(QSL("not-an-object")), SecuritySettingsPorter::ChecksumState::Mismatch);
        QCOMPARE(check(QJsonObject{{QSL("algorithm"), QSL("md5")},
                                   {QSL("tools"), SecuritySettingsPorter::checksumForTools(base.value(QSL("tools")).toObject())}}),
                 SecuritySettingsPorter::ChecksumState::Mismatch);
        QCOMPARE(check(QJsonObject{{QSL("algorithm"), QSL("sha256")},
                                   {QSL("tools"), 12345}}),
                 SecuritySettingsPorter::ChecksumState::Mismatch);
        QCOMPARE(check(QJsonObject{{QSL("algorithm"), QSL("sha256")},
                                   {QSL("tools"), QSL("tooshort")}}),
                 SecuritySettingsPorter::ChecksumState::Mismatch);

        // the real one still validates
        QCOMPARE(check(document.value(QSL("checksum")).toObject()),
                 SecuritySettingsPorter::ChecksumState::Valid);
    }

    // A file whose checksum was removed - the older-format case -
    // imports as before, without the mismatch dance. The content on
    // disk at this point is still the tampered one; without a
    // checksum there is nothing to refuse, and the values apply.
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
        QJsonDocument stripped = QJsonDocument::fromJson(file.readAll());
        file.close();

        QJsonObject root = stripped.object();
        root.remove(QSL("checksum"));
        stripped.setObject(root);

        QFile rewrite(path);
        QVERIFY(rewrite.open(QIODevice::WriteOnly | QIODevice::Truncate));
        rewrite.write(QJsonDocument(stripped.object()).toJson(QJsonDocument::Indented));
        rewrite.close();

        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);
        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
        QCOMPARE(adblock->isEnabled(), !adblockBefore);
    }

    // restore the state the other tests expect
    adblock->setEnabled(adblockBefore);
    QCOMPARE(adblock->isEnabled(), adblockBefore);
    QCOMPARE(interceptor->isEnabled(), httpsOnlyBefore);
}

void SecurityToolsTest::settingsPorterPreviewTest()
{
    auto *adblock = AdBlockManager::instance();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    auto *threatBlock = mApp->networkManager()->threatBlockManager();
    auto *fingerprint = FingerprintManager::instance();
    auto *gpc = GpcManager::instance();

    const bool dohSupported = DnsOverHttpsManager::isSupported();

    // Snapshot every piece of state the preview must leave untouched.
    const bool adblockBefore = adblock->isEnabled();
    const bool httpsOnlyBefore = interceptor->isEnabled();
    const bool stripTrackingBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool();
    const bool fingerprintBefore = fingerprint->isEnabled();
    const bool gpcBefore = gpc->isEnabled();
    const bool threatEnabledBefore = threatBlock->isEnabled();
    const QString threatSourceBefore = threatBlock->sourceUrl();
    const QStringList httpsExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/HttpsOnlyExclusions"), QStringList()).toStringList();
    const QStringList fingerprintExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList()).toStringList();
    const auto dohModeBefore = doh->mode();
    const QStringList dohServersBefore = doh->serverTemplates();

    // Pin a known state the diff is computed against.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), true);
        settings.setValue(QSL("HttpsOnlyExclusions"), QStringList{QSL("preview.example")});
        settings.setValue(QSL("StripTrackingQuery"), true);
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.setValue(QSL("FingerprintExclusions"), QStringList{QSL("preview.example")});
        settings.setValue(QSL("GlobalPrivacyControl"), true);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(true);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(true);
    threatBlock->setEnabled(true);
    threatBlock->setSourceUrl(QSL("https://preview.example/hosts"));
    if (dohSupported) {
        doh->setConfiguration(DnsOverHttpsManager::SecureWithFallback,
                              {DnsOverHttpsManager::defaultServerTemplate()});
    }

    // The document under preview: some changes, one absent tool, one
    // malformed section, one field the file does not state.
    QJsonObject tools;
    tools.insert(QSL("adblock"), QJsonObject{{QSL("enabled"), false}});
    tools.insert(QSL("httpsOnly"), QJsonObject{{QSL("enabled"), true}, {QSL("exclusions"), QJsonArray{}}});
    tools.insert(QSL("secureDns"), QJsonObject{{QSL("mode"), 0}, {QSL("servers"), QJsonArray{}}});
    tools.insert(QSL("threatBlock"), QJsonObject{{QSL("enabled"), true},
                                                 {QSL("sourceUrl"), QSL("https://after.example/hosts")}});
    tools.insert(QSL("fingerprintProtection"), QJsonObject{{QSL("enabled"), QSL("yes")}});
    tools.insert(QSL("globalPrivacyControl"), QJsonObject{{QSL("enabled"), true}});

    QJsonObject document;
    document.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
    document.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
    document.insert(QSL("tools"), tools);

    auto hasChange = [](const SecuritySettingsPorter::Preview &preview,
                        const QString &tool, const QString &field,
                        const QString &currentValue, const QString &nextValue) {
        for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
            if (change.tool == tool && change.field == field) {
                return change.currentValue == currentValue && change.nextValue == nextValue;
            }
        }
        return false;
    };

    // The change of one field, for pinning its structured payload.
    auto findChange = [](const SecuritySettingsPorter::Preview &preview,
                         const QString &tool, const QString &field) -> const SecuritySettingsPorter::PreviewChange * {
        for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
            if (change.tool == tool && change.field == field) {
                return &change;
            }
        }
        return nullptr;
    };

    auto changeCount = [](const SecuritySettingsPorter::Preview &preview, const QString &tool) {
        int count = 0;
        for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
            if (change.tool == tool) {
                ++count;
            }
        }
        return count;
    };

    const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(document);

    QVERIFY(preview.ok);
    QVERIFY(preview.error.isEmpty());
    QCOMPARE(preview.checksum, SecuritySettingsPorter::ChecksumState::NoChecksum);

    // The absent tool is reported as unchanged, not as skipped.
    QCOMPARE(preview.configuredTools, 6);
    QCOMPARE(preview.unchangedTools, QStringList{QSL("trackingParameters")});

    // The malformed section is reported with the reason the import
    // would give (and the build limitation, when it applies).
    if (dohSupported) {
        QCOMPARE(preview.skippedTools.size(), 1);
        QVERIFY(preview.skippedTools.constFirst().startsWith(QSL("fingerprintProtection")));
    } else {
        QCOMPARE(preview.skippedTools.size(), 2);
        QVERIFY(preview.skippedTools.constFirst().startsWith(QSL("secureDns")));
    }

    // The diff: exactly the fields whose effective value changes.
    QVERIFY(hasChange(preview, QSL("adblock"), QSL("enabled"), QSL("on"), QSL("off")));
    // httpsOnly stays on; its exception list is reset by the empty one.
    QVERIFY(hasChange(preview, QSL("httpsOnly"), QSL("exclusions"), QSL("preview.example"), QSL("none")));
    QCOMPARE(changeCount(preview, QSL("httpsOnly")), 1);
    if (dohSupported) {
        QVERIFY(hasChange(preview, QSL("secureDns"), QSL("mode"),
                          QSL("on, with fallback to the system resolver"), QSL("off")));
        QVERIFY(hasChange(preview, QSL("secureDns"), QSL("servers"),
                          DnsOverHttpsManager::defaultServerTemplate(), QSL("none")));
    }
    // threatBlock stays on; only the stated source changes.
    QVERIFY(hasChange(preview, QSL("threatBlock"), QSL("sourceUrl"),
                      QSL("https://preview.example/hosts"), QSL("https://after.example/hosts")));
    QCOMPARE(changeCount(preview, QSL("threatBlock")), 1);
    // gpc stays on - no change, no row.
    QCOMPARE(changeCount(preview, QSL("globalPrivacyControl")), 0);
    // The skipped tool contributes no diff rows.
    QCOMPARE(changeCount(preview, QSL("fingerprintProtection")), 0);

    // A site-exception change names the sites whose treatment
    // changes: the httpsOnly row clears preview.example, and the
    // summary line says so in one line.
    {
        const SecuritySettingsPorter::PreviewChange *exclusions = findChange(preview, QSL("httpsOnly"), QSL("exclusions"));
        QVERIFY(exclusions);
        QCOMPARE(exclusions->clearedEntries, QStringList{QSL("preview.example")});
        QVERIFY(exclusions->addedEntries.isEmpty());
        QCOMPARE(SecuritySettingsPorter::exceptionSummaryLines(*exclusions),
                 QStringList{QSL("Clears the exception for: preview.example")});
    }

    // A change that is not a site-exception list carries no entries
    // and no summary lines.
    {
        const SecuritySettingsPorter::PreviewChange *enabled = findChange(preview, QSL("adblock"), QSL("enabled"));
        QVERIFY(enabled);
        QVERIFY(enabled->clearedEntries.isEmpty());
        QVERIFY(enabled->addedEntries.isEmpty());
        QVERIFY(SecuritySettingsPorter::exceptionSummaryLines(*enabled).isEmpty());
    }

    // The preview touched nothing: every manager still holds the
    // pinned state.
    QCOMPARE(adblock->isEnabled(), true);
    QCOMPARE(interceptor->isEnabled(), true);
    QVERIFY(interceptor->hasExplicitExclusion(QSL("preview.example")));
    QCOMPARE(threatBlock->sourceUrl(), QSL("https://preview.example/hosts"));
    QCOMPARE(fingerprint->isEnabled(), true);
    QVERIFY(fingerprint->isExcluded(QSL("preview.example")));
    QCOMPARE(gpc->isEnabled(), true);
    if (dohSupported) {
        QCOMPARE(doh->mode(), DnsOverHttpsManager::SecureWithFallback);
        QCOMPARE(doh->serverTemplates(), QStringList{DnsOverHttpsManager::defaultServerTemplate()});
    }

    // A missing threatBlock sourceUrl field keeps the current source:
    // no sourceUrl row appears in the diff.
    {
        QJsonObject single;
        single.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        single.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        single.insert(QSL("tools"), QJsonObject{
            {QSL("threatBlock"), QJsonObject{{QSL("enabled"), true}}}
        });

        const SecuritySettingsPorter::Preview sourcePreview = SecuritySettingsPorter::previewDocument(single);

        QVERIFY(sourcePreview.ok);
        QCOMPARE(sourcePreview.changes.size(), 0);
    }

    // A list that keeps some sites and gains others: one line per
    // direction, cleared before added. The comparison is the
    // case-insensitive one the tools match hosts with, so an entry
    // that only changes case is neither cleared nor added - though
    // the stored list does change, and the row does appear.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyExclusions"),
                          QStringList{QSL("a.example"), QSL("keep.example")});
        settings.endGroup();
        interceptor->loadSettings();

        QJsonObject partial;
        partial.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        partial.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        partial.insert(QSL("tools"), QJsonObject{
            {QSL("httpsOnly"), QJsonObject{{QSL("enabled"), true},
                                           {QSL("exclusions"), QJsonArray{QSL("keep.example"), QSL("new.example")}}}}
        });

        const SecuritySettingsPorter::Preview partialPreview = SecuritySettingsPorter::previewDocument(partial);
        QVERIFY(partialPreview.ok);

        const SecuritySettingsPorter::PreviewChange *partialChange = findChange(partialPreview, QSL("httpsOnly"), QSL("exclusions"));
        QVERIFY(partialChange);
        QCOMPARE(partialChange->clearedEntries, QStringList{QSL("a.example")});
        QCOMPARE(partialChange->addedEntries, QStringList{QSL("new.example")});
        QCOMPARE(SecuritySettingsPorter::exceptionSummaryLines(*partialChange),
                 QStringList{QSL("Clears the exception for: a.example"),
                             QSL("Adds an exception for: new.example")});

        QJsonObject recased;
        recased.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        recased.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        recased.insert(QSL("tools"), QJsonObject{
            {QSL("httpsOnly"), QJsonObject{{QSL("enabled"), true},
                                           {QSL("exclusions"), QJsonArray{QSL("Keep.Example"), QSL("A.Example")}}}}
        });

        const SecuritySettingsPorter::Preview recasedPreview = SecuritySettingsPorter::previewDocument(recased);
        QVERIFY(recasedPreview.ok);

        const SecuritySettingsPorter::PreviewChange *recasedChange = findChange(recasedPreview, QSL("httpsOnly"), QSL("exclusions"));
        QVERIFY(recasedChange);
        QVERIFY(recasedChange->clearedEntries.isEmpty());
        QVERIFY(recasedChange->addedEntries.isEmpty());
        QVERIFY(SecuritySettingsPorter::exceptionSummaryLines(*recasedChange).isEmpty());

        // Back to the pinned state for the blocks below.
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyExclusions"), QStringList{QSL("preview.example")});
        settings.endGroup();
        interceptor->loadSettings();
    }

    // The preview and the import agree: the same document, applied,
    // reports the same skips the preview announced.
    {
        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::applyDocument(document);

        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
        QCOMPARE(result.skippedTools, preview.skippedTools);

        if (dohSupported) {
            QCOMPARE(result.appliedTools, 5);
        } else {
            QCOMPARE(result.appliedTools, 4);
        }

        // The announced diff was the truth: the changed values hold.
        QCOMPARE(adblock->isEnabled(), false);
        QVERIFY(!interceptor->hasExplicitExclusion(QSL("preview.example")));
        QCOMPARE(threatBlock->sourceUrl(), QSL("https://after.example/hosts"));
        if (dohSupported) {
            QCOMPARE(doh->mode(), DnsOverHttpsManager::Disabled);
        }
    }

    // A mismatching checksum does not stop the preview: the diff is
    // shown so the changed file can be judged on its content.
    {
        QJsonObject mismatching;
        mismatching.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        mismatching.insert(QSL("version"), SecuritySettingsPorter::formatVersion());

        QJsonObject checksum;
        checksum.insert(QSL("algorithm"), SecuritySettingsPorter::checksumAlgorithm());
        checksum.insert(QSL("tools"), QSL("0000000000000000000000000000000000000000000000000000000000000000"));
        mismatching.insert(QSL("checksum"), checksum);
        mismatching.insert(QSL("tools"), QJsonObject{
            {QSL("adblock"), QJsonObject{{QSL("enabled"), false}}}
        });

        const SecuritySettingsPorter::Preview mismatchPreview = SecuritySettingsPorter::previewDocument(mismatching);

        QVERIFY(mismatchPreview.ok);
        QCOMPARE(mismatchPreview.checksum, SecuritySettingsPorter::ChecksumState::Mismatch);
        QCOMPARE(mismatchPreview.changes.size(), adblock->isEnabled() == false ? 0 : 1);
    }

    // A document that cannot be imported has no preview either.
    {
        QJsonObject broken;
        broken.insert(QSL("format"), QSL("something-else"));
        broken.insert(QSL("version"), 1);

        const SecuritySettingsPorter::Preview brokenPreview = SecuritySettingsPorter::previewDocument(broken);

        QVERIFY(!brokenPreview.ok);
        QVERIFY(!brokenPreview.error.isEmpty());
        QCOMPARE(brokenPreview.changes.size(), 0);
        QCOMPARE(brokenPreview.skippedTools.size(), 0);
    }
    {
        QJsonObject broken;
        broken.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        broken.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        broken.insert(QSL("tools"), 42);

        QVERIFY(!SecuritySettingsPorter::previewDocument(broken).ok);
    }

    // The shared names: every known tool has one, they are distinct,
    // and unknown keys pass through untouched.
    {
        const QStringList keys{QSL("adblock"), QSL("httpsOnly"), QSL("trackingParameters"),
                               QSL("secureDns"), QSL("threatBlock"),
                               QSL("fingerprintProtection"), QSL("globalPrivacyControl")};
        QSet<QString> names;

        for (const QString &key : keys) {
            const QString name = SecuritySettingsPorter::toolDisplayName(key);
            QVERIFY(!name.isEmpty());
            QVERIFY(!names.contains(name));
            names.insert(name);

            QVERIFY(!SecuritySettingsPorter::fieldDisplayName(key, QSL("enabled")).isEmpty());
        }

        QCOMPARE(SecuritySettingsPorter::toolDisplayName(QSL("unknownTool")), QSL("unknownTool"));
        QCOMPARE(SecuritySettingsPorter::fieldDisplayName(QSL("adblock"), QSL("unknownField")), QSL("unknownField"));
        QVERIFY(!SecuritySettingsPorter::fieldDisplayName(QSL("threatBlock"), QSL("sourceUrl")).isEmpty());
    }

    // Provenance: a document that names a preset carries its id into
    // the preview verbatim, known or not; a document without the
    // field (or with one of the wrong type) previews with an empty
    // one. The document under test carries none.
    QCOMPARE(preview.presetId, QString());

    QJsonObject withPreset = document;
    withPreset.insert(QSL("preset"), QSL("recommended-baseline"));
    QCOMPARE(SecuritySettingsPorter::previewDocument(withPreset).presetId, QSL("recommended-baseline"));

    withPreset.insert(QSL("preset"), QSL("not-a-baseline"));
    QCOMPARE(SecuritySettingsPorter::previewDocument(withPreset).presetId, QSL("not-a-baseline"));

    withPreset.insert(QSL("preset"), 42);
    QCOMPARE(SecuritySettingsPorter::previewDocument(withPreset).presetId, QString());

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), httpsExclusionsBefore);
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingBefore);
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.setValue(QSL("FingerprintExclusions"), fingerprintExclusionsBefore);
        settings.setValue(QSL("GlobalPrivacyControl"), gpcBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcBefore);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockBefore);
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }
}

void SecurityToolsTest::settingsPorterPresetExportTest()
{
    auto *adblock = AdBlockManager::instance();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    auto *threatBlock = mApp->networkManager()->threatBlockManager();
    auto *fingerprint = FingerprintManager::instance();
    auto *gpc = GpcManager::instance();

    const bool dohSupported = DnsOverHttpsManager::isSupported();

    // Snapshot every piece of state the exports touch.
    const bool adblockBefore = adblock->isEnabled();
    const bool httpsOnlyBefore = interceptor->isEnabled();
    const bool stripTrackingBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool();
    const bool fingerprintBefore = fingerprint->isEnabled();
    const bool gpcBefore = gpc->isEnabled();
    const bool threatEnabledBefore = threatBlock->isEnabled();
    const QString threatSourceBefore = threatBlock->sourceUrl();
    const QStringList httpsExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/HttpsOnlyExclusions"), QStringList()).toStringList();
    const QStringList fingerprintExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList()).toStringList();
    const auto dohModeBefore = doh->mode();
    const QStringList dohServersBefore = doh->serverTemplates();

    QTemporaryDir dir;

    // Each preset exports as a regular, checksum-verified settings
    // file that keeps its provenance and imports without warnings.
    for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
        const QString path = dir.filePath(QSL("preset-%1.json").arg(preset.id));

        QString error;
        QVERIFY(SecuritySettingsPorter::exportDocumentToFile(preset.document, path, &error));

        QJsonObject written;
        QVERIFY(SecuritySettingsPorter::loadDocument(path, &written, &error));

        QCOMPARE(written.value(QSL("format")).toString(), SecuritySettingsPorter::formatIdentifier());
        QCOMPARE(written.value(QSL("version")).toInt(), SecuritySettingsPorter::formatVersion());
        QCOMPARE(written.value(QSL("preset")).toString(), preset.id);
        QVERIFY(!written.value(QSL("exportedAt")).toString().isEmpty());
        QCOMPARE(SecuritySettingsPorter::checkChecksum(written),
                 SecuritySettingsPorter::ChecksumState::Valid);

        // The tools section is the preset's, byte for byte, and no
        // seed travels with the file.
        QCOMPARE(QJsonDocument(written.value(QSL("tools")).toObject()).toJson(QJsonDocument::Compact),
                 QJsonDocument(preset.document.value(QSL("tools")).toObject()).toJson(QJsonDocument::Compact));
        QVERIFY(!QJsonDocument(written).toJson(QJsonDocument::Compact).contains("seed"));

        // The saved preset imports cleanly through the regular path.
        const SecuritySettingsPorter::ImportResult result = SecuritySettingsPorter::importFromFile(path);

        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
        QCOMPARE(result.skippedTools.size(), dohSupported ? 0 : 1);
    }

    // Exporting again to the same path overwrites atomically.
    {
        const QString path = dir.filePath(QSL("preset-recommended-baseline.json"));
        const SecurityPresets::Preset preset = SecurityPresets::presetById(QSL("maximum-protection"));

        QString error;
        QVERIFY(SecuritySettingsPorter::exportDocumentToFile(preset.document, path, &error));

        QJsonObject written;
        QVERIFY(SecuritySettingsPorter::loadDocument(path, &written, &error));
        QCOMPARE(written.value(QSL("preset")).toString(), QSL("maximum-protection"));
        QCOMPARE(SecuritySettingsPorter::checkChecksum(written), SecuritySettingsPorter::ChecksumState::Valid);
    }

    // Refusal cases: no path, a document that is not Osza security
    // settings, a malformed tools container.
    {
        QString error;
        QVERIFY(!SecuritySettingsPorter::exportDocumentToFile(SecurityPresets::presetById(QSL("essentials")).document,
                                                              QString(), &error));
        QVERIFY(!error.isEmpty());

        QJsonObject wrongFormat;
        wrongFormat.insert(QSL("format"), QSL("something-else"));
        wrongFormat.insert(QSL("version"), 1);
        QVERIFY(!SecuritySettingsPorter::exportDocumentToFile(wrongFormat, dir.filePath(QSL("no.json")), &error));

        QJsonObject brokenTools;
        brokenTools.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
        brokenTools.insert(QSL("version"), SecuritySettingsPorter::formatVersion());
        brokenTools.insert(QSL("tools"), 42);
        QVERIFY(!SecuritySettingsPorter::exportDocumentToFile(brokenTools, dir.filePath(QSL("no.json")), &error));
    }

    // A refused export never destroys an existing file: the valid
    // export from before is still there, checksum and all.
    {
        const QString path = dir.filePath(QSL("preset-essentials.json"));

        QJsonObject wrongFormat;
        wrongFormat.insert(QSL("format"), QSL("something-else"));
        wrongFormat.insert(QSL("version"), 1);

        QString error;
        QVERIFY(!SecuritySettingsPorter::exportDocumentToFile(wrongFormat, path, &error));

        QJsonObject written;
        QVERIFY(SecuritySettingsPorter::loadDocument(path, &written, &error));
        QCOMPARE(written.value(QSL("preset")).toString(), QSL("essentials"));
        QCOMPARE(SecuritySettingsPorter::checkChecksum(written), SecuritySettingsPorter::ChecksumState::Valid);
    }

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), httpsExclusionsBefore);
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingBefore);
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.setValue(QSL("FingerprintExclusions"), fingerprintExclusionsBefore);
        settings.setValue(QSL("GlobalPrivacyControl"), gpcBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcBefore);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockBefore);
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }
}

void SecurityToolsTest::securityImportPreviewDialogTest()
{
    // A preview with a diff, a skip and an absent tool.
    SecuritySettingsPorter::Preview preview;
    preview.ok = true;
    preview.checksum = SecuritySettingsPorter::ChecksumState::Valid;
    preview.configuredTools = 5;

    SecuritySettingsPorter::PreviewChange adblock;
    adblock.tool = QSL("adblock");
    adblock.field = QSL("enabled");
    adblock.currentValue = QSL("on");
    adblock.nextValue = QSL("off");
    preview.changes.append(adblock);

    SecuritySettingsPorter::PreviewChange dns;
    dns.tool = QSL("secureDns");
    dns.field = QSL("mode");
    dns.currentValue = QSL("off");
    dns.nextValue = QSL("on, secure DNS only");
    preview.changes.append(dns);

    preview.skippedTools.append(QSL("fingerprintProtection: a field is missing or has the wrong type"));
    preview.unchangedTools.append(QSL("globalPrivacyControl"));

    SecurityImportPreviewDialog dialog(preview, QSL("settings.json"));
    dialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&dialog));

    // The tree shows one row per changed tool, one child per field,
    // current value against the value after the import. A change
    // without entries carries no rows below its field row.
    auto *tree = dialog.findChild<QTreeWidget*>();
    QVERIFY(tree);
    QCOMPARE(tree->topLevelItemCount(), 2);
    QCOMPARE(tree->topLevelItem(0)->text(0), SecuritySettingsPorter::toolDisplayName(QSL("adblock")));
    QCOMPARE(tree->topLevelItem(0)->childCount(), 1);
    QCOMPARE(tree->topLevelItem(0)->child(0)->text(1), QSL("on"));
    QCOMPARE(tree->topLevelItem(0)->child(0)->text(2), QSL("off"));
    QCOMPARE(tree->topLevelItem(0)->child(0)->childCount(), 0);
    QCOMPARE(tree->topLevelItem(1)->childCount(), 1);
    QCOMPARE(tree->topLevelItem(1)->child(0)->childCount(), 0);

    // A matching checksum means a plain "Import" and no exception.
    auto *box = dialog.findChild<QDialogButtonBox*>();
    QVERIFY(box);
    QCOMPARE(box->button(QDialogButtonBox::Ok)->text(), QSL("Import"));
    QVERIFY(!dialog.importDespiteChecksum());

    box->button(QDialogButtonBox::Ok)->click();
    QCOMPARE(dialog.result(), static_cast<int>(QDialog::Accepted));
    QVERIFY(!dialog.importDespiteChecksum());

    // A mismatching checksum turns the confirmation into the
    // explicit "import anyway" the ChecksumPolicy::Allow needs.
    SecuritySettingsPorter::Preview mismatched = preview;
    mismatched.checksum = SecuritySettingsPorter::ChecksumState::Mismatch;

    SecurityImportPreviewDialog warningDialog(mismatched, QSL("changed.json"));
    warningDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&warningDialog));

    auto *warningBox = warningDialog.findChild<QDialogButtonBox*>();
    QVERIFY(warningBox);
    QCOMPARE(warningBox->button(QDialogButtonBox::Ok)->text(), QSL("Import anyway"));
    QVERIFY(!warningDialog.importDespiteChecksum());

    warningBox->button(QDialogButtonBox::Ok)->click();
    QCOMPARE(warningDialog.result(), static_cast<int>(QDialog::Accepted));
    QVERIFY(warningDialog.importDespiteChecksum());

    // Cancelling is no import, whatever the checksum says.
    SecurityImportPreviewDialog cancelled(mismatched, QSL("changed.json"));
    cancelled.show();
    QVERIFY(QTest::qWaitForWindowExposed(&cancelled));

    auto *cancelBox = cancelled.findChild<QDialogButtonBox*>();
    QVERIFY(cancelBox);
    cancelBox->button(QDialogButtonBox::Cancel)->click();
    QCOMPARE(cancelled.result(), static_cast<int>(QDialog::Rejected));
    QVERIFY(!cancelled.importDespiteChecksum());

    // A site-exception change carries its one-line summaries as rows
    // under the field row: which sites lose their exception, which
    // gain one. The lines are the porter's, translated - the dialog
    // does not re-derive them from the value columns.
    SecuritySettingsPorter::Preview exceptions;
    exceptions.ok = true;
    exceptions.checksum = SecuritySettingsPorter::ChecksumState::Valid;
    exceptions.configuredTools = 1;

    SecuritySettingsPorter::PreviewChange exclusions;
    exclusions.tool = QSL("httpsOnly");
    exclusions.field = QSL("exclusions");
    exclusions.currentValue = QSL("bank.example, keep.example");
    exclusions.nextValue = QSL("keep.example, legacy.example");
    exclusions.clearedEntries = QStringList{QSL("bank.example")};
    exclusions.addedEntries = QStringList{QSL("legacy.example")};
    exceptions.changes.append(exclusions);

    SecurityImportPreviewDialog exceptionDialog(exceptions, QSL("settings.json"));
    exceptionDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&exceptionDialog));

    auto *exceptionTree = exceptionDialog.findChild<QTreeWidget*>();
    QVERIFY(exceptionTree);
    QCOMPARE(exceptionTree->topLevelItemCount(), 1);

    QTreeWidgetItem *exceptionToolRow = exceptionTree->topLevelItem(0);
    QCOMPARE(exceptionToolRow->text(0), SecuritySettingsPorter::toolDisplayName(QSL("httpsOnly")));
    QCOMPARE(exceptionToolRow->childCount(), 1);

    QTreeWidgetItem *exceptionFieldRow = exceptionToolRow->child(0);
    QCOMPARE(exceptionFieldRow->text(0),
             SecuritySettingsPorter::fieldDisplayName(QSL("httpsOnly"), QSL("exclusions")));
    QCOMPARE(exceptionFieldRow->childCount(), 2);
    QCOMPARE(exceptionFieldRow->child(0)->text(0), QSL("Clears the exception for: bank.example"));
    QCOMPARE(exceptionFieldRow->child(1)->text(0), QSL("Adds an exception for: legacy.example"));

    // The summary rows are set apart from the values they explain.
    QCOMPARE(exceptionFieldRow->child(0)->font(0).italic(), true);
    QCOMPARE(exceptionFieldRow->child(1)->font(0).italic(), true);

    // The preset provenance a file carries: named when the file
    // states it, resolved to the built-in's name when it is one of
    // them, and shown as the plain text it is when it is not.
    // Without the field there is nothing to say and nothing shown.
    SecuritySettingsPorter::Preview fromPreset = exceptions;
    fromPreset.presetId = QSL("recommended-baseline");

    SecurityImportPreviewDialog presetDialog(fromPreset, QSL("baseline.json"));
    presetDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&presetDialog));

    auto *presetLabel = presetDialog.findChild<QLabel*>(QSL("presetLabel"));
    QVERIFY(presetLabel);
    QVERIFY(presetLabel->isVisible());
    QCOMPARE(presetLabel->text(),
             QSL("The file was saved from the built-in preset \"%1\".")
                 .arg(SecurityPresets::presetById(QSL("recommended-baseline")).name));
    QCOMPARE(presetLabel->textFormat(), Qt::PlainText);
    QVERIFY(!presetLabel->toolTip().isEmpty());

    // An id that is not one of the built-ins is reported as the raw
    // id, never dropped and never resolved to something else.
    fromPreset.presetId = QSL("someone-elses-baseline");

    SecurityImportPreviewDialog unknownDialog(fromPreset, QSL("strange.json"));
    unknownDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&unknownDialog));

    auto *unknownLabel = unknownDialog.findChild<QLabel*>(QSL("presetLabel"));
    QVERIFY(unknownLabel);
    QCOMPARE(unknownLabel->text(),
             QSL("The file names the preset \"someone-elses-baseline\", which is not one of the built-ins. Its contents are previewed the same way."));
    QCOMPARE(unknownLabel->textFormat(), Qt::PlainText);

    // No provenance, no line: the first dialog of this test carried
    // no preset id, so its provenance label is hidden.
    QVERIFY(dialog.findChild<QLabel*>(QSL("presetLabel"))->isHidden());

    // The "view as page" link, for exactly the files a page can
    // honestly show: a known preset plus a matching checksum is that
    // preset's document, so the osza:settings-diff page for the
    // preset shows this very diff. Anything else - a tampered file,
    // an unstamped hand edit, an unknown preset, no preset at all -
    // gets no link, because the page would promise a diff it cannot
    // show. The link is rich text with external links off: osza:
    // URLs belong to the browser, never to the OS.
    auto *viewPageLabel = presetDialog.findChild<QLabel*>(QSL("viewPageLabel"));
    QVERIFY(viewPageLabel);
    QVERIFY(viewPageLabel->isVisible());
    QCOMPARE(viewPageLabel->textFormat(), Qt::RichText);
    QVERIFY(!viewPageLabel->openExternalLinks());
    QVERIFY(viewPageLabel->text().contains(QSL("osza:settings-diff?preset=recommended-baseline")));
    QVERIFY(!viewPageLabel->text().contains(QSL("tool=")));
    QVERIFY(viewPageLabel->text().contains(QSL("View this diff as a page")));

    // Selecting a tool's row retargets the link to that tool's
    // section, and says so: the deep link is visible in the label,
    // not only in where it lands.
    auto *presetTree = presetDialog.findChild<QTreeWidget*>();
    QVERIFY(presetTree);
    presetTree->setCurrentItem(presetTree->topLevelItem(0));
    QVERIFY(viewPageLabel->text().contains(QSL("osza:settings-diff?preset=recommended-baseline&tool=httpsOnly")));
    QVERIFY(viewPageLabel->text().contains(SecuritySettingsPorter::toolDisplayName(QSL("httpsOnly"))));

    // Selecting a field row under the tool focuses the same tool.
    presetTree->setCurrentItem(presetTree->topLevelItem(0)->child(0));
    QVERIFY(viewPageLabel->text().contains(QSL("tool=httpsOnly")));

    // Using the link hands the URL to the caller - the dialog never
    // opens anything itself.
    QSignalSpy pageSpy(&presetDialog, &SecurityImportPreviewDialog::diffPageRequested);
    QTest::mouseClick(viewPageLabel, Qt::LeftButton, Qt::NoModifier,
                      QPoint(10, viewPageLabel->height() / 2));
    QCOMPARE(pageSpy.count(), 1);
    QCOMPARE(pageSpy.takeFirst().at(0).toUrl(),
             SettingsDiffPage::pageUrl(QSL("recommended-baseline"), QSL("httpsOnly")));

    // A mismatching checksum breaks the guarantee the link rests on:
    // the file claims the preset but no longer verifiably is it.
    SecuritySettingsPorter::Preview tampered = fromPreset;
    tampered.checksum = SecuritySettingsPorter::ChecksumState::Mismatch;

    SecurityImportPreviewDialog tamperedDialog(tampered, QSL("changed.json"));
    tamperedDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&tamperedDialog));
    QVERIFY(tamperedDialog.findChild<QLabel*>(QSL("viewPageLabel"))->isHidden());

    // So does a missing checksum: a hand edit or an older export
    // could be anything behind the preset's name.
    SecuritySettingsPorter::Preview unstamped = fromPreset;
    unstamped.checksum = SecuritySettingsPorter::ChecksumState::NoChecksum;

    SecurityImportPreviewDialog unstampedDialog(unstamped, QSL("old.json"));
    unstampedDialog.show();
    QVERIFY(QTest::qWaitForWindowExposed(&unstampedDialog));
    QVERIFY(unstampedDialog.findChild<QLabel*>(QSL("viewPageLabel"))->isHidden());

    // An id that is not one of the built-ins has no page at all.
    QVERIFY(unknownDialog.findChild<QLabel*>(QSL("viewPageLabel"))->isHidden());

    // And a file that states no origin never had one.
    QVERIFY(dialog.findChild<QLabel*>(QSL("viewPageLabel"))->isHidden());
}

void SecurityToolsTest::securityPresetsTest()
{
    auto *adblock = AdBlockManager::instance();
    auto *interceptor = mApp->networkManager()->httpsOnlyInterceptor();
    auto *doh = mApp->networkManager()->dnsOverHttpsManager();
    auto *threatBlock = mApp->networkManager()->threatBlockManager();
    auto *fingerprint = FingerprintManager::instance();
    auto *gpc = GpcManager::instance();

    const bool dohSupported = DnsOverHttpsManager::isSupported();

    // Snapshot every piece of state the presets touch.
    const bool adblockBefore = adblock->isEnabled();
    const bool httpsOnlyBefore = interceptor->isEnabled();
    const bool stripTrackingBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool();
    const bool fingerprintBefore = fingerprint->isEnabled();
    const bool gpcBefore = gpc->isEnabled();
    const bool threatEnabledBefore = threatBlock->isEnabled();
    const QString threatSourceBefore = threatBlock->sourceUrl();
    const QStringList httpsExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/HttpsOnlyExclusions"), QStringList()).toStringList();
    const QStringList fingerprintExclusionsBefore = Settings::globalSettings()->value(QSL("Web-Browser-Settings/FingerprintExclusions"), QStringList()).toStringList();
    const auto dohModeBefore = doh->mode();
    const QStringList dohServersBefore = doh->serverTemplates();

    const QList<SecurityPresets::Preset> presets = SecurityPresets::presets();

    // Three built-ins, from lightest to strictest, each identified,
    // named and described.
    QCOMPARE(presets.size(), 3);
    QCOMPARE(presets.at(0).id, QSL("essentials"));
    QCOMPARE(presets.at(1).id, QSL("recommended-baseline"));
    QCOMPARE(presets.at(2).id, QSL("maximum-protection"));

    QSet<QString> ids;
    for (const SecurityPresets::Preset &preset : std::as_const(presets)) {
        QVERIFY(!preset.name.isEmpty());
        QVERIFY(!preset.description.isEmpty());
        QVERIFY(!ids.contains(preset.id));
        ids.insert(preset.id);

        // Every preset is a well-formed document in the import format
        // that states all seven tools explicitly - the ones it turns
        // off included - and carries neither a seed nor a checksum.
        QVERIFY(SecuritySettingsPorter::validateDocumentHeader(preset.document, nullptr));

        const QJsonObject tools = preset.document.value(QSL("tools")).toObject();
        QCOMPARE(tools.size(), 7);
        QVERIFY(tools.value(QSL("adblock")).isObject());
        QVERIFY(tools.value(QSL("httpsOnly")).isObject());
        QVERIFY(tools.value(QSL("trackingParameters")).isObject());
        QVERIFY(tools.value(QSL("secureDns")).isObject());
        QVERIFY(tools.value(QSL("threatBlock")).isObject());
        QVERIFY(tools.value(QSL("fingerprintProtection")).isObject());
        QVERIFY(tools.value(QSL("globalPrivacyControl")).isObject());

        QCOMPARE(SecuritySettingsPorter::checkChecksum(preset.document),
                 SecuritySettingsPorter::ChecksumState::NoChecksum);

        const QByteArray serialized = QJsonDocument(preset.document).toJson(QJsonDocument::Compact);
        QVERIFY(!serialized.contains("seed"));
        QVERIFY(!serialized.contains("Seed"));

        // The provenance field names the preset.
        QCOMPARE(preset.document.value(QSL("preset")).toString(), preset.id);
    }

    // The content of each preset is pinned: changing what
    // "recommended" means is a decision that shows up in this diff.
    {
        const QJsonObject tools = presets.at(0).document.value(QSL("tools")).toObject();
        QCOMPARE(tools.value(QSL("adblock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("httpsOnly")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("httpsOnly")).toObject().value(QSL("exclusions")).toArray().size(), 0);
        QCOMPARE(tools.value(QSL("trackingParameters")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("mode")).toInt(),
                 static_cast<int>(DnsOverHttpsManager::Disabled));
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("servers")).toArray().size(), 0);
        QCOMPARE(tools.value(QSL("threatBlock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("threatBlock")).toObject().value(QSL("sourceUrl")).toString(),
                 ThreatBlockManager::defaultSourceUrl());
        QCOMPARE(tools.value(QSL("fingerprintProtection")).toObject().value(QSL("enabled")).toBool(), false);
        QCOMPARE(tools.value(QSL("fingerprintProtection")).toObject().value(QSL("exclusions")).toArray().size(), 0);
        QCOMPARE(tools.value(QSL("globalPrivacyControl")).toObject().value(QSL("enabled")).toBool(), false);
    }

    {
        const QJsonObject tools = presets.at(1).document.value(QSL("tools")).toObject();
        QCOMPARE(tools.value(QSL("adblock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("httpsOnly")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("trackingParameters")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("mode")).toInt(),
                 static_cast<int>(DnsOverHttpsManager::SecureWithFallback));
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("servers")).toArray().size(), 1);
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("servers")).toArray().at(0).toString(),
                 DnsOverHttpsManager::defaultServerTemplate());
        QCOMPARE(tools.value(QSL("threatBlock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("threatBlock")).toObject().value(QSL("sourceUrl")).toString(),
                 ThreatBlockManager::defaultSourceUrl());
        QCOMPARE(tools.value(QSL("fingerprintProtection")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("fingerprintProtection")).toObject().value(QSL("exclusions")).toArray().size(), 0);
        QCOMPARE(tools.value(QSL("globalPrivacyControl")).toObject().value(QSL("enabled")).toBool(), true);
    }

    {
        const QJsonObject tools = presets.at(2).document.value(QSL("tools")).toObject();
        QCOMPARE(tools.value(QSL("adblock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("httpsOnly")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("trackingParameters")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("mode")).toInt(),
                 static_cast<int>(DnsOverHttpsManager::SecureOnly));
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("servers")).toArray().size(), 1);
        QCOMPARE(tools.value(QSL("secureDns")).toObject().value(QSL("servers")).toArray().at(0).toString(),
                 DnsOverHttpsManager::defaultServerTemplate());
        QCOMPARE(tools.value(QSL("threatBlock")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("fingerprintProtection")).toObject().value(QSL("enabled")).toBool(), true);
        QCOMPARE(tools.value(QSL("globalPrivacyControl")).toObject().value(QSL("enabled")).toBool(), true);
    }

    // Lookup by id finds every built-in and nothing else.
    for (const SecurityPresets::Preset &preset : std::as_const(presets)) {
        QCOMPARE(SecurityPresets::presetById(preset.id).id, preset.id);
    }
    QVERIFY(SecurityPresets::presetById(QSL("does-not-exist")).id.isEmpty());

    // Applying the recommended baseline goes through the same
    // validation as an import and reaches the live managers.
    {
        // start from a state every preset tool changes
        {
            Settings settings;
            settings.beginGroup(QSL("Web-Browser-Settings"));
            settings.setValue(QSL("HttpsOnlyMode"), !httpsOnlyBefore);
            settings.setValue(QSL("HttpsOnlyExclusions"), QStringList{QSL("preset.example")});
            settings.setValue(QSL("StripTrackingQuery"), !stripTrackingBefore);
            settings.setValue(QSL("FingerprintProtection"), !fingerprintBefore);
            settings.setValue(QSL("FingerprintExclusions"), QStringList{QSL("preset.example")});
            settings.setValue(QSL("GlobalPrivacyControl"), !gpcBefore);
            settings.endGroup();
        }
        interceptor->loadSettings();
        fingerprint->loadSettings();
        gpc->setEnabled(!gpcBefore);
        mApp->networkManager()->loadSettings();
        adblock->setEnabled(!adblockBefore);
        threatBlock->setEnabled(!threatEnabledBefore);
        threatBlock->setSourceUrl(QSL("https://preset.example/hosts"));
        if (dohSupported) {
            doh->setConfiguration(DnsOverHttpsManager::Disabled, QStringList());
        }

        const SecuritySettingsPorter::ImportResult result =
            SecuritySettingsPorter::applyDocument(SecurityPresets::presetById(QSL("recommended-baseline")).document);

        QVERIFY(result.ok);
        QVERIFY(!result.checksumMismatch);
        if (dohSupported) {
            QCOMPARE(result.appliedTools, 7);
            QCOMPARE(result.skippedTools.size(), 0);
        } else {
            QCOMPARE(result.appliedTools, 6);
            QCOMPARE(result.skippedTools.size(), 1);
            QVERIFY(result.skippedTools.constFirst().startsWith(QSL("secureDns")));
        }

        QCOMPARE(adblock->isEnabled(), true);
        QCOMPARE(interceptor->isEnabled(), true);
        QVERIFY(!interceptor->hasExplicitExclusion(QSL("preset.example")));
        QCOMPARE(Settings::globalSettings()->value(QSL("Web-Browser-Settings/StripTrackingQuery"), true).toBool(), true);
        if (dohSupported) {
            QCOMPARE(doh->mode(), DnsOverHttpsManager::SecureWithFallback);
            QCOMPARE(doh->serverTemplates(), QStringList{DnsOverHttpsManager::defaultServerTemplate()});
        }
        QCOMPARE(threatBlock->isEnabled(), true);
        QCOMPARE(threatBlock->sourceUrl(), ThreatBlockManager::defaultSourceUrl());
        QCOMPARE(fingerprint->isEnabled(), true);
        QVERIFY(!fingerprint->isExcluded(QSL("preset.example")));
        QCOMPARE(gpc->isEnabled(), true);

        // The guard script follows the preset.
        QVERIFY(!mApp->webProfile()->scripts()->find(QSL("_osza_fingerprint_guard")).isEmpty());
    }

    // The essentials preset turns the deeper tools back off; a preset
    // really replaces the whole configuration.
    {
        const SecuritySettingsPorter::ImportResult result =
            SecuritySettingsPorter::applyDocument(SecurityPresets::presetById(QSL("essentials")).document);

        QVERIFY(result.ok);
        QCOMPARE(fingerprint->isEnabled(), false);
        QCOMPARE(gpc->isEnabled(), false);
        if (dohSupported) {
            QCOMPARE(doh->mode(), DnsOverHttpsManager::Disabled);
        }
        QVERIFY(mApp->webProfile()->scripts()->find(QSL("_osza_fingerprint_guard")).isEmpty());
    }

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("HttpsOnlyMode"), httpsOnlyBefore);
        settings.setValue(QSL("HttpsOnlyExclusions"), httpsExclusionsBefore);
        settings.setValue(QSL("StripTrackingQuery"), stripTrackingBefore);
        settings.setValue(QSL("FingerprintProtection"), fingerprintBefore);
        settings.setValue(QSL("FingerprintExclusions"), fingerprintExclusionsBefore);
        settings.setValue(QSL("GlobalPrivacyControl"), gpcBefore);
        settings.endGroup();
    }
    interceptor->loadSettings();
    fingerprint->loadSettings();
    gpc->setEnabled(gpcBefore);
    mApp->networkManager()->loadSettings();
    adblock->setEnabled(adblockBefore);
    threatBlock->setEnabled(threatEnabledBefore);
    threatBlock->setSourceUrl(threatSourceBefore);
    if (dohSupported) {
        doh->setConfiguration(dohModeBefore, dohServersBefore);
    }

    QCOMPARE(adblock->isEnabled(), adblockBefore);
    QCOMPARE(interceptor->isEnabled(), httpsOnlyBefore);
    QCOMPARE(fingerprint->isEnabled(), fingerprintBefore);
    QCOMPARE(gpc->isEnabled(), gpcBefore);
    QCOMPARE(threatBlock->isEnabled(), threatEnabledBefore);
    QCOMPARE(threatBlock->sourceUrl(), threatSourceBefore);
    QCOMPARE(doh->mode(), dohModeBefore);
    QCOMPARE(doh->serverTemplates(), dohServersBefore);
}

void SecurityToolsTest::settingsDiffPageBuildTest()
{
    // The page builds for every shape it can be asked for - the
    // overview, each built-in baseline's diff, and the dead end for
    // an id that is not one of the built-ins - with every
    // placeholder substituted.
    const QString overview = SettingsDiffPage::buildPage();

    QVERIFY(overview.contains(QLatin1String("osza-settingsdiff")));
    QVERIFY(overview.contains(QSL("Security settings diff")));
    QVERIFY(!overview.contains(QLatin1String("%TITLE%")));
    QVERIFY(!overview.contains(QLatin1String("%SUBTITLE%")));
    QVERIFY(!overview.contains(QLatin1String("%OVERVIEW-HEADING%")));
    QVERIFY(!overview.contains(QLatin1String("%DATA-JSON%")));
    QVERIFY(!overview.contains(QLatin1String("%I18N-JSON%")));
    QVERIFY(!overview.contains(QLatin1String("%DIRECTION%")));

    // The overview data: one entry per built-in baseline, each with
    // the number of settings it would change here right now - the
    // same count the porter's preview computes.
    const QJsonObject overviewData = SettingsDiffPage::diffData();
    QCOMPARE(overviewData.value(QSL("mode")).toString(), QSL("overview"));

    const QJsonArray overviewPresets = overviewData.value(QSL("presets")).toArray();
    QCOMPARE(overviewPresets.size(), SecurityPresets::presets().size());

    for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
        const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(preset.document);
        QVERIFY(preview.ok);

        bool found = false;
        for (const QJsonValue &value : overviewPresets) {
            const QJsonObject entry = value.toObject();
            if (entry.value(QSL("id")).toString() != preset.id) {
                continue;
            }

            found = true;
            QCOMPARE(entry.value(QSL("name")).toString(), preset.name);
            QCOMPARE(entry.value(QSL("description")).toString(), preset.description);
            QCOMPARE(entry.value(QSL("changes")).toInt(), preview.changes.size());
        }
        QVERIFY(found);

        // A baseline's diff page and data: the preset, the preview
        // shaped for the page, and the shared display names.
        const QJsonObject data = SettingsDiffPage::diffData(preset.id);
        QCOMPARE(data.value(QSL("mode")).toString(), QSL("diff"));
        QCOMPARE(data.value(QSL("preset")).toObject().value(QSL("id")).toString(), preset.id);
        QCOMPARE(data.value(QSL("preset")).toObject().value(QSL("name")).toString(), preset.name);

        const QJsonObject previewObject = data.value(QSL("preview")).toObject();
        QVERIFY(previewObject.value(QSL("ok")).toBool());
        QCOMPARE(previewObject.value(QSL("configuredTools")).toInt(), preview.configuredTools);
        QCOMPARE(previewObject.value(QSL("totalTools")).toInt(), 7);
        QCOMPARE(previewObject.value(QSL("changes")).toArray().size(), preview.changes.size());

        const QString page = SettingsDiffPage::buildPage(preset.id);
        QVERIFY(page.contains(QLatin1String("osza-settingsdiff")));
        QVERIFY(page.contains(preset.name));

        // Every change row carries the stable keys, the display
        // names and the porter's own summary lines - the same lines
        // the import preview dialog shows.
        const QJsonArray changes = previewObject.value(QSL("changes")).toArray();
        for (int i = 0; i < changes.size(); ++i) {
            const QJsonObject change = changes.at(i).toObject();
            const QString tool = change.value(QSL("tool")).toString();
            const QString field = change.value(QSL("field")).toString();
            QVERIFY(!tool.isEmpty());
            QVERIFY(!field.isEmpty());
            QCOMPARE(change.value(QSL("toolName")).toString(), SecuritySettingsPorter::toolDisplayName(tool));
            QCOMPARE(change.value(QSL("fieldName")).toString(), SecuritySettingsPorter::fieldDisplayName(tool, field));
            QVERIFY(change.contains(QSL("current")));
            QVERIFY(change.contains(QSL("next")));
            QVERIFY(change.contains(QSL("summary")));
        }

        // Presets state all seven sections; the page accounts for
        // every one of them: changed, skipped or already matching.
        int quiet = 0;
        for (const QJsonValue &value : previewObject.value(QSL("quietTools")).toArray()) {
            QVERIFY(!value.toString().isEmpty());
            ++quiet;
        }

        QSet<QString> accounted;
        for (const QJsonValue &value : changes) {
            accounted.insert(value.toObject().value(QSL("tool")).toString());
        }
        for (const QString &entry : preview.skippedTools) {
            accounted.insert(entry.left(entry.indexOf(QSL(": "))));
        }
        QCOMPARE(quiet + accounted.size(), 7);
    }

    // An id that is not one of the built-ins is a dead end with a
    // way back, never an error page.
    const QJsonObject unknownData = SettingsDiffPage::diffData(QSL("no-such-baseline"));
    QCOMPARE(unknownData.value(QSL("mode")).toString(), QSL("unknown"));
    QCOMPARE(unknownData.value(QSL("presetId")).toString(), QSL("no-such-baseline"));
    QCOMPARE(unknownData.value(QSL("presets")).toArray().size(), SecurityPresets::presets().size());

    const QString unknownPage = SettingsDiffPage::buildPage(QSL("no-such-baseline"));
    QVERIFY(unknownPage.contains(QLatin1String("osza-settingsdiff")));
    QVERIFY(!unknownPage.contains(QLatin1String("%DATA-JSON%")));

    // The URL shape and its reader agree, for every id they can be
    // handed: no item means the overview, whitespace is trimmed, and
    // the round trip carries the id through.
    QCOMPARE(SettingsDiffPage::pageUrl().toString(), QSL("osza:settings-diff"));
    QCOMPARE(SettingsDiffPage::presetIdFromUrl(SettingsDiffPage::pageUrl()), QString());
    QCOMPARE(SettingsDiffPage::presetIdFromUrl(QUrl(QSL("osza:settings-diff?preset=essentials"))), QSL("essentials"));
    QCOMPARE(SettingsDiffPage::presetIdFromUrl(QUrl(QSL("osza:settings-diff?preset=%20essentials%20"))), QSL("essentials"));
    QCOMPARE(SettingsDiffPage::presetIdFromUrl(SettingsDiffPage::pageUrl(QSL("maximum-protection"))), QSL("maximum-protection"));
    QVERIFY(SettingsDiffPage::pageUrl(QSL("essentials")).toString().contains(QSL("preset=essentials")));

    // The per-tool deep link rides in the "tool" item: the preset
    // first, the tool second, whitespace trimmed, and the reader
    // carries both through. The porter's key list is the authority
    // for what a tool item can mean.
    const QStringList toolKeys = SecuritySettingsPorter::toolKeys();
    QCOMPARE(toolKeys.size(), 7);
    QVERIFY(toolKeys.contains(QSL("adblock")));
    QVERIFY(toolKeys.contains(QSL("httpsOnly")));
    QVERIFY(toolKeys.contains(QSL("trackingParameters")));
    QVERIFY(toolKeys.contains(QSL("secureDns")));
    QVERIFY(toolKeys.contains(QSL("threatBlock")));
    QVERIFY(toolKeys.contains(QSL("fingerprintProtection")));
    QVERIFY(toolKeys.contains(QSL("globalPrivacyControl")));

    const QUrl toolUrl = SettingsDiffPage::pageUrl(QSL("essentials"), QSL("secureDns"));
    QVERIFY(toolUrl.toString().contains(QSL("preset=essentials")));
    QVERIFY(toolUrl.toString().contains(QSL("tool=secureDns")));
    QCOMPARE(SettingsDiffPage::presetIdFromUrl(toolUrl), QSL("essentials"));
    QCOMPARE(SettingsDiffPage::toolIdFromUrl(toolUrl), QSL("secureDns"));
    QCOMPARE(SettingsDiffPage::toolIdFromUrl(SettingsDiffPage::pageUrl(QSL("essentials"))), QString());
    QCOMPARE(SettingsDiffPage::toolIdFromUrl(QUrl(QSL("osza:settings-diff?preset=essentials&tool=%20secureDns%20"))), QSL("secureDns"));
    QCOMPARE(SettingsDiffPage::toolIdFromUrl(SettingsDiffPage::pageUrl(QString(), QSL("secureDns"))), QSL("secureDns"));

    // Focusing every tool of every baseline is answered, with the
    // note naming the tool and matching what the preview says about
    // it: a section to show, a skip reason, or already matching.
    for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
        const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(preset.document);
        const QJsonObject toolsOfDocument = preset.document.value(QSL("tools")).toObject();

        for (const QString &toolKey : toolKeys) {
            const QJsonObject data = SettingsDiffPage::diffData(preset.id, toolKey);
            QCOMPARE(data.value(QSL("mode")).toString(), QSL("diff"));
            QVERIFY(data.contains(QSL("focusTool")));
            QVERIFY(!data.contains(QSL("unknownTool")));

            const QJsonObject focus = data.value(QSL("focusTool")).toObject();
            QCOMPARE(focus.value(QSL("key")).toString(), toolKey);
            QCOMPARE(focus.value(QSL("name")).toString(), SecuritySettingsPorter::toolDisplayName(toolKey));

            const QString note = focus.value(QSL("note")).toString();
            QVERIFY(!note.isEmpty());
            QVERIFY(note.contains(SecuritySettingsPorter::toolDisplayName(toolKey)));

            bool hasChange = false;
            for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
                if (change.tool == toolKey) {
                    hasChange = true;
                    break;
                }
            }

            bool isSkipped = false;
            QString skipReason;
            for (const QString &entry : preview.skippedTools) {
                if (entry.startsWith(QSL("%1: ").arg(toolKey))) {
                    isSkipped = true;
                    skipReason = entry.mid(toolKey.length() + 2);
                    break;
                }
            }

            if (hasChange) {
                QVERIFY(note.startsWith(QSL("Showing the changes for")));
            } else if (isSkipped) {
                QVERIFY(note.contains(skipReason));
            } else {
                // The built-in presets state all seven sections, so
                // an answered tool without changes is already at the
                // baseline's settings.
                QVERIFY(toolsOfDocument.contains(toolKey));
                QVERIFY(note.contains(QSL("already at the baseline's settings")));
            }
        }

        // A "tool" item naming no security tool is answered beside
        // the full diff, never with an error page.
        const QJsonObject unknownToolData = SettingsDiffPage::diffData(preset.id, QSL("not-a-tool"));
        QCOMPARE(unknownToolData.value(QSL("mode")).toString(), QSL("diff"));
        QCOMPARE(unknownToolData.value(QSL("unknownTool")).toString(), QSL("not-a-tool"));
        QVERIFY(!unknownToolData.contains(QSL("focusTool")));
        QVERIFY(unknownToolData.contains(QSL("preview")));

        // The focused page builds like any other.
        const QString focusedPage = SettingsDiffPage::buildPage(preset.id, QSL("secureDns"));
        QVERIFY(focusedPage.contains(QLatin1String("osza-settingsdiff")));
        QVERIFY(!focusedPage.contains(QLatin1String("%DATA-JSON%")));
    }

    // The tool item only means something together with a known
    // preset: without one it is the overview, with an unknown one the
    // dead end - the preset decides the shape, the tool never does.
    QCOMPARE(SettingsDiffPage::diffData(QString(), QSL("secureDns")).value(QSL("mode")).toString(), QSL("overview"));
    const QJsonObject unknownWithTool = SettingsDiffPage::diffData(QSL("no-such-baseline"), QSL("secureDns"));
    QCOMPARE(unknownWithTool.value(QSL("mode")).toString(), QSL("unknown"));
    QVERIFY(!unknownWithTool.contains(QSL("focusTool")));
    QVERIFY(!unknownWithTool.contains(QSL("unknownTool")));
}

void SecurityToolsTest::settingsDiffPageIntegrationTest()
{
    // The real page through the real osza: scheme handler: the
    // overview renders a card per baseline, a baseline's diff
    // renders exactly the changes the porter's preview computes, and
    // the dead end answers an unknown id. The diff follows the
    // settings - a change of state changes the page.
    auto *fingerprint = FingerprintManager::instance();
    const bool enabledBefore = fingerprint->isEnabled();

    auto runScript = [](WebPage *page, const QString &script) {
        QString result;
        QEventLoop loop;
        QTimer::singleShot(8000, &loop, &QEventLoop::quit);
        page->runJavaScript(script, [&result, &loop](const QVariant &value) {
            result = value.toString();
            loop.quit();
        });
        loop.exec();
        return result;
    };

    WebPage page;
    QSignalSpy loadFinishedSpy(&page, &QWebEnginePage::loadFinished);

    auto loadAndSettle = [&](const QUrl &url) -> bool {
        loadFinishedSpy.clear();
        page.load(url);
        return loadFinishedSpy.wait(20000);
    };

    // The overview: a card per baseline, linking to its diff.
    QVERIFY(loadAndSettle(QUrl(QSL("osza:settings-diff"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("overview"));
    QCOMPARE(runScript(&page, QSL("String(window.__oszaSettingsDiff.counts.presetCards)")),
             QString::number(SecurityPresets::presets().size()));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-preset').length")),
             QString::number(SecurityPresets::presets().size()));
    QVERIFY(runScript(&page, QSL("document.querySelector('a.sd-preset').getAttribute('href')")).contains(QSL("osza:settings-diff?preset=")));

    // A baseline's diff: the banner, one section per changed tool,
    // one row per changed field - the same counts the porter's
    // preview computes for the same document.
    const SecurityPresets::Preset baseline = SecurityPresets::presetById(QSL("recommended-baseline"));
    QVERIFY(!baseline.id.isEmpty());

    const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(baseline.document);
    QVERIFY(preview.ok);

    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("recommended-baseline"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("diff"));
    QCOMPARE(runScript(&page, QSL("String(window.__oszaSettingsDiff.counts.changeRows)")),
             QString::number(preview.changes.size()));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-change').length")),
             QString::number(preview.changes.size()));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-change__summary').length")),
             QString::number([preview]() {
                 int count = 0;
                 for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
                     count += SecuritySettingsPorter::exceptionSummaryLines(change).size();
                 }
                 return count;
             }()));
    QVERIFY(runScript(&page, QSL("document.querySelector('.sd-banner') === null ? 'missing' : 'shown'")) == QSL("shown"));

    // An unknown id: the dead end, with the baselines to go back to.
    QVERIFY(loadAndSettle(QUrl(QSL("osza:settings-diff?preset=definitely-not-a-baseline"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("unknown"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-banner--warn').length")), QSL("1"));
    QCOMPARE(runScript(&page, QSL("String(window.__oszaSettingsDiff.counts.presetCards)")),
             QString::number(SecurityPresets::presets().size()));

    // The diff follows the settings: with fingerprint protection on,
    // the essentials baseline (it turns the protection off) shows a
    // change for it; turned off, the section disappears.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    fingerprint->loadSettings();

    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("essentials"))));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section[data-tool=fingerprintProtection]').length")), QSL("1"));

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), false);
        settings.endGroup();
    }
    fingerprint->loadSettings();

    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("essentials"))));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section[data-tool=fingerprintProtection]').length")), QSL("0"));

    // The per-tool deep link lands where it promises: with the
    // protection on (a change, so a section), the focused page marks
    // that tool's section, scrolls to it, says so in the note, and
    // every section carries its own deep link back into the page.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), true);
        settings.endGroup();
    }
    fingerprint->loadSettings();

    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("essentials"), QSL("fingerprintProtection"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("diff"));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.data.focusTool.key")), QSL("fingerprintProtection"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section[data-tool=fingerprintProtection]').length")), QSL("1"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section.sd-tool--focus').length")), QSL("1"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section[data-tool=fingerprintProtection].sd-tool--focus').length")), QSL("1"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-focus-note').length")), QSL("1"));
    QVERIFY(runScript(&page, QSL("document.querySelector('.sd-focus-note') === null ? 'missing' : document.querySelector('.sd-focus-note').textContent"))
            .contains(QSL("Showing the changes for")));
    QVERIFY(runScript(&page, QSL("document.querySelector('.sd-focus-note') === null ? 'missing' : document.querySelector('.sd-focus-note').textContent"))
            .contains(SecuritySettingsPorter::toolDisplayName(QSL("fingerprintProtection"))));

    const SecurityPresets::Preset essentials = SecurityPresets::presetById(QSL("essentials"));
    const SecuritySettingsPorter::Preview essentialsPreview = SecuritySettingsPorter::previewDocument(essentials.document);
    QVERIFY(essentialsPreview.ok);

    int changedTools = 0;
    QString lastTool;
    for (const SecuritySettingsPorter::PreviewChange &change : essentialsPreview.changes) {
        if (change.tool != lastTool) {
            lastTool = change.tool;
            ++changedTools;
        }
    }

    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('a.sd-tool__link').length")),
             QString::number(changedTools));
    QCOMPARE(runScript(&page, QSL("document.querySelector('section[data-tool=fingerprintProtection] a.sd-tool__link') === null ? 'missing' : document.querySelector('section[data-tool=fingerprintProtection] a.sd-tool__link').getAttribute('href')")),
             QSL("osza:settings-diff?preset=essentials&tool=fingerprintProtection"));

    // A tool the baseline would not change is still answered: no
    // section to focus, and the note says the profile already runs
    // that tool exactly as the baseline wants.
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), false);
        settings.endGroup();
    }
    fingerprint->loadSettings();

    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("essentials"), QSL("fingerprintProtection"))));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('section[data-tool=fingerprintProtection]').length")), QSL("0"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-tool--focus').length")), QSL("0"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-focus-note').length")), QSL("1"));
    QVERIFY(runScript(&page, QSL("document.querySelector('.sd-focus-note') === null ? 'missing' : document.querySelector('.sd-focus-note').textContent"))
            .contains(QSL("already at the baseline's settings")));

    // A "tool" item naming no security tool: a warning line over the
    // full diff, which still renders exactly the porter's preview.
    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QSL("essentials"), QSL("definitely-not-a-tool"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("diff"));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.data.unknownTool")), QSL("definitely-not-a-tool"));
    QCOMPARE(runScript(&page, QSL("document.querySelectorAll('.sd-banner--warn').length")), QSL("1"));
    QCOMPARE(runScript(&page, QSL("String(window.__oszaSettingsDiff.counts.changeRows)")),
             QString::number(essentialsPreview.changes.size()));

    // Without a preset the tool item means nothing: the overview.
    QVERIFY(loadAndSettle(SettingsDiffPage::pageUrl(QString(), QSL("secureDns"))));
    QCOMPARE(runScript(&page, QSL("window.__oszaSettingsDiff.mode")), QSL("overview"));
    QCOMPARE(runScript(&page, QSL("String(window.__oszaSettingsDiff.counts.presetCards)")),
             QString::number(SecurityPresets::presets().size()));

    // restore the state the other tests expect
    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("FingerprintProtection"), enabledBefore);
        settings.endGroup();
    }
    fingerprint->loadSettings();
}
