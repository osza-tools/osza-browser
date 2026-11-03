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
#include "dnsoverhttpsmanager.h"
#include "httpsonlyinterceptor.h"
#include "networkmanager.h"
#include "mainapplication.h"
#include "qzcommon.h"
#include "securitymanager.h"
#include "securitysidebar.h"
#include "settings.h"
#include "threatblockmanager.h"
#include "webpage.h"

#include <QtTest/QtTest>
#include <QWebEnginePage>
#include <QEventLoop>

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

    // restore the original state
    sidebar.toggleHttpsOnly(httpsOnlyBefore);
    sidebar.toggleThreatBlock(threatBlockBefore);
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
