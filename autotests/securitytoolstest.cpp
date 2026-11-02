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

#include <QtTest/QtTest>

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

    // restore the original state
    sidebar.toggleHttpsOnly(httpsOnlyBefore);
}

OSZATEST_MAIN(SecurityToolsTest)
