#!/usr/bin/env python3
# ============================================================
# Osza - cross-site referrer protection verifier
#
# Standalone verification of the eighth bundled security tool,
# without a Qt build, in the spirit of verify_locationbar_badge.py
# and verify_settings_porter.py:
#
#   1. The interception contract: the rewrite runs only on a
#      QtWebEngine that can expose the request's headers (6.5+),
#      reads the request's real Referer (never introducing one
#      where the engine sent none), leaves the referrer alone for
#      the excluded sites and the requests staying inside one site,
#      clears on a scheme downgrade in both strengths, and counts
#      the rewrite against the site whose URLs stopped leaking.
#
#   2. The cross-site judgment: a pure-Python mirror of
#      NetworkUrlInterceptor::isSameSite() and referrerOrigin()
#      checked against the same truth table the autotest pins.
#
#   3. The manager contract: mode off / site-address / no-referrer
#      (0/1/2), the out-of-the-box default at the recommended
#      strength, corrupted settings landing on a known mode, and
#      the exclusion list's storage normalization and matching.
#
#   4. The wiring: the counter, the relaxed-protections query, the
#      padlock menu row, the security sidebar, the Preferences
#      rows, the self-test page row, the porter (export, import
#      validation, apply, preview), the three baselines, the diff
#      page's tool count, and the honest "requires QtWebEngine 6.5+"
#      treatment everywhere a build without the API shows up.
#
#   5. The autotests and the docs exist.
#
# Usage:
#   python3 tools/security/verify_referrer_guard.py
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, os.pardir, os.pardir))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


INTERCEPTOR_CPP = read("src", "lib", "network", "networkurlinterceptor.cpp")
INTERCEPTOR_H = read("src", "lib", "network", "networkurlinterceptor.h")
MANAGER_CPP = read("src", "lib", "security", "referrerguardmanager.cpp")
MANAGER_H = read("src", "lib", "security", "referrerguardmanager.h")
SECURITY_MANAGER_CPP = read("src", "lib", "security", "securitymanager.cpp")
SECURITY_MANAGER_H = read("src", "lib", "security", "securitymanager.h")
SITEINFO_CPP = read("src", "lib", "other", "siteinfowidget.cpp")
SITEINFO_H = read("src", "lib", "other", "siteinfowidget.h")
SITEINFO_UI = read("src", "lib", "other", "siteinfowidget.ui")
SIDEBAR_CPP = read("src", "lib", "sidebar", "securitysidebar.cpp")
SIDEBAR_H = read("src", "lib", "sidebar", "securitysidebar.h")
PREFS_CPP = read("src", "lib", "preferences", "preferences.cpp")
PREFS_H = read("src", "lib", "preferences", "preferences.h")
PREFS_UI = read("src", "lib", "preferences", "preferences.ui")
EXCEPTIONS_DIALOG_H = read("src", "lib", "preferences", "referrerexceptionsdialog.h")
PORTER_CPP = read("src", "lib", "security", "securitysettingsporter.cpp")
PRESETS_CPP = read("src", "lib", "security", "securitypresets.cpp")
SELFTEST_CPP = read("src", "lib", "security", "selftestpage.cpp")
DIFFPAGE_CPP = read("src", "lib", "security", "settingsdiffpage.cpp")
CMAKE = read("src", "lib", "CMakeLists.txt")
AUTOTEST_CPP = read("autotests", "securitytoolstest.cpp")
AUTOTEST_H = read("autotests", "securitytoolstest.h")
README = read("README.md")
CHANGELOG = read("CHANGELOG")

checks = [0, 0]


def check(label, ok):
    print(("  PASS " if ok else "  FAIL ") + label)
    checks[0] += 1
    checks[1] += 0 if ok else 1


# ------------------------------------------------------------------
# 1. The interception contract
# ------------------------------------------------------------------
print("1. the interception contract")

check("the rewrite is gated on the QtWebEngine version that can expose headers",
      INTERCEPTOR_CPP.count("#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 5, 0)") == 2
      and re.search(r"#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK\(6, 5, 0\)\s*\n"
                    r"\s*if \(m_referrerGuardMode != 0\) \{ // ReferrerGuardManager::Off", INTERCEPTOR_CPP) is not None
      and re.search(r"#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK\(6, 5, 0\)\s*\n"
                    r"void NetworkUrlInterceptor::applyReferrerGuardLocked", INTERCEPTOR_CPP) is not None)
check("the gate and the manager's isSupported() ask the same version",
      "#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 5, 0)" in MANAGER_CPP)
check("the rewrite runs only when a mode is set",
      re.search(r"if \(m_referrerGuardMode != 0\) \{ // ReferrerGuardManager::Off\s*\n"
                r"\s*applyReferrerGuardLocked\(info\);", INTERCEPTOR_CPP) is not None)
check("the rewrite reads the request's real Referer",
      'info.httpHeaders().value(QByteArrayLiteral("Referer"))' in INTERCEPTOR_CPP)
check("a request with no Referer keeps having none",
      re.search(r"if \(refererValue\.isEmpty\(\)\) \{\s*\n\s*return;\s*\n\s*\}", INTERCEPTOR_CPP) is not None)
check("a non-web referrer or target is left alone",
      INTERCEPTOR_CPP.count('!= QSL("http") && targetScheme != QSL("https")') >= 1
      and INTERCEPTOR_CPP.count('!= QSL("http") && referrerScheme != QSL("https")') == 1)
check("the rewrite runs after the tracking-parameter strip, before the per-domain user agent",
      INTERCEPTOR_CPP.index("stripTrackingParameters") < INTERCEPTOR_CPP.index("applyReferrerGuardLocked(info)")
      and INTERCEPTOR_CPP.index("applyReferrerGuardLocked(info)") < INTERCEPTOR_CPP.index("m_usePerDomainUserAgent"))
check("an excluded site's outgoing requests keep the site's own policy",
      "referrerGuardHostExcludedLocked(referrer.host())" in INTERCEPTOR_CPP)
check("the same-site judgment gates the rewrite",
      "isSameSite(referrer, target)" in INTERCEPTOR_CPP)
check("a scheme downgrade always clears, in both strengths",
      re.search(r"const bool downgrade = referrerScheme == QSL\(\"https\"\) && targetScheme == QSL\(\"http\"\);", INTERCEPTOR_CPP) is not None
      and re.search(r"if \(downgrade \|\| m_referrerGuardMode == 2\)", INTERCEPTOR_CPP) is not None)
check("the no-referrer strength clears through an empty value",
      'info.setHttpHeader(QByteArrayLiteral("Referer"), QByteArrayLiteral(""))' in INTERCEPTOR_CPP)
check("the site-address strength writes the origin the builder makes",
      'info.setHttpHeader(QByteArrayLiteral("Referer"), referrerOrigin(referrer).toUtf8())' in INTERCEPTOR_CPP)
check("the rewrite is counted against the site whose URLs stopped leaking",
      "reportReferrerTrimmed(referrer.host())" in INTERCEPTOR_CPP)

check("the IO-thread copy reads the mode with a range check",
      re.search(r'm_referrerGuardMode = settings\.value\(QSL\("ReferrerGuardMode"\), 1\)\.toInt\(\);\s*\n'
                r'\s*if \(m_referrerGuardMode < 0 \|\| m_referrerGuardMode > 2\) \{\s*\n'
                r'\s*m_referrerGuardMode = 1;\s*\n\s*\}', INTERCEPTOR_CPP) is not None)
check("the IO-thread copy reads the exclusion list from the same key",
      'settings.value(QSL("ReferrerGuardExclusions"), QStringList())' in INTERCEPTOR_CPP)
check("the guard's exclusion matching reuses the host-matching helper",
      "referrerGuardHostExcludedLocked" in INTERCEPTOR_H
      and "hostMatchesExclusionEntry(normalized, entry)" in INTERCEPTOR_CPP)

check("the header constants are shared with the manager's enum values",
      "enum Mode {\n        Off = 0,\n        OriginOnly = 1,\n        NoReferrer = 2\n    };" in MANAGER_H)

# ------------------------------------------------------------------
# 2. The cross-site judgment, mirrored
# ------------------------------------------------------------------
print("2. the cross-site judgment")


def is_same_site(referrer, target):
    """Pure-Python mirror of NetworkUrlInterceptor::isSameSite(): the
    same scheme, with the same host or two hosts of one domain family
    (the dot boundary keeping unrelated hosts apart), and never on a
    scheme downgrade."""
    def split(url):
        m = re.match(r"^([a-z]+)://([^/?#]*)([/?#]|$)", url)
        if not m:
            return None, None
        scheme, authority = m.group(1), m.group(2)
        host = authority.split("@")[-1].split(":")[0]
        return scheme, host.lower()

    referrer_scheme, referrer_host = split(referrer)
    target_scheme, target_host = split(target)

    if referrer_scheme is None or target_scheme is None:
        return False
    if referrer_scheme != target_scheme:
        return False
    if not referrer_host or not target_host:
        return False
    if referrer_host == target_host:
        return True
    return referrer_host.endswith("." + target_host) or target_host.endswith("." + referrer_host)


TRUTH_TABLE = [
    # one site telling itself where you were
    ("https://a.example/x?q=1", "https://a.example/y", True),
    ("https://a.example/x", "https://sub.a.example/y", True),
    ("https://sub.a.example/x", "https://a.example/y", True),
    ("https://a.example/x", "https://a.example:8443/y", True),
    ("http://a.example/x", "http://a.example:8080/y", True),
    # a downgrade is never same-site
    ("https://a.example/x", "http://a.example/y", False),
    ("https://a.example/x", "http://sub.a.example/y", False),
    # a scheme change in the safer direction is still another site
    ("http://a.example/x", "https://a.example/y", False),
    # unrelated hosts, including the suffix-sharing pair
    ("https://a.example/x", "https://b.example/y", False),
    ("https://a.example/x", "https://nota.example/y", False),
    ("https://a.example/x", "https://example.com/y", False),
    # the judgment needs both URLs
    ("https://a.example/x", "", False),
    ("", "https://a.example/y", False),
    ("https://a.example/x", "file:///tmp/y", False),
]

for referrer, target, expected in TRUTH_TABLE:
    check("mirror: %s -> %s is %s" % (referrer or "(empty)", target or "(empty)",
                                      "one site" if expected else "another site"),
          is_same_site(referrer, target) == expected)

check("the C++ judgment checks the scheme pair before the hosts",
      re.search(r'if \(referrerScheme == QSL\("https"\) && targetScheme == QSL\("http"\)\) \{\s*\n'
                r'\s*return false;\s*\n\s*\}\s*\n\s*if \(referrerScheme != targetScheme\) \{\s*\n'
                r'\s*return false;\s*\n\s*\}', INTERCEPTOR_CPP) is not None)
check("the C++ judgment compares the hosts with the dot boundary, both ways",
      'referrerHost.endsWith(QSL(".") + targetHost, Qt::CaseInsensitive)' in INTERCEPTOR_CPP
      and 'targetHost.endsWith(QSL(".") + referrerHost, Qt::CaseInsensitive)' in INTERCEPTOR_CPP)
check("ports are not compared - a port shuffle is one site's own arrangement",
      re.search(r"bool NetworkUrlInterceptor::isSameSite\(.*?\n\}", INTERCEPTOR_CPP, re.DOTALL).group(0).count("port(") == 0)

def referrer_origin(referrer):
    """Pure-Python mirror of NetworkUrlInterceptor::referrerOrigin():
    scheme, host, explicit non-default port, empty path."""
    m = re.match(r"^([a-z]+)://([^/?#]*)([/?#]|$)", referrer)
    scheme, authority = m.group(1), m.group(2)
    userinfo_host = authority.split("@")[-1]
    if ":" in userinfo_host:
        host, port = userinfo_host.rsplit(":", 1)
    else:
        host, port = userinfo_host, None
    default = {"https": "443", "http": "80"}.get(scheme)
    if port is None or port == default:
        return "%s://%s/" % (scheme, host)
    return "%s://%s:%s/" % (scheme, host, port)


ORIGIN_TABLE = [
    ("https://a.example/deep/path?query=1#frag", "https://a.example/"),
    ("http://a.example:8080/x", "http://a.example:8080/"),
    ("https://user@a.example/x", "https://a.example/"),
    ("https://a.example:443/x", "https://a.example/"),
    ("http://a.example:80/x", "http://a.example/"),
]

for source, expected in ORIGIN_TABLE:
    check("mirror: the address of %s is %s" % (source, expected),
          referrer_origin(source) == expected)

check("the C++ origin builder keeps the explicit port and drops everything else",
      re.search(r"origin\.setScheme\(referrer\.scheme\(\)\);\s*\n\s*origin\.setHost\(referrer\.host\(\)\);", INTERCEPTOR_CPP) is not None
      and 'origin.setPath(QSL("/"));' in INTERCEPTOR_CPP)

# ------------------------------------------------------------------
# 3. The manager contract
# ------------------------------------------------------------------
print("3. the manager contract")

check("three modes, off / site-address / no-referrer",
      "Off = 0" in MANAGER_H and "OriginOnly = 1" in MANAGER_H and "NoReferrer = 2" in MANAGER_H)
check("the out-of-the-box default is the recommended strength",
      'settings.value(QSL("ReferrerGuardMode"), static_cast<int>(OriginOnly)).toInt()' in MANAGER_CPP
      and "m_mode = OriginOnly;" in MANAGER_CPP)
check("a corrupted stored mode lands on the recommended strength",
      re.search(r"if \(mode >= Off && mode <= NoReferrer\) \{\s*\n\s*m_mode = static_cast<Mode>\(mode\);\s*\n"
                r"\s*\} else \{\s*\n\s*m_mode = OriginOnly;\s*\n\s*\}", MANAGER_CPP) is not None)
check("setMode persists and only reports real changes",
      'settings.setValue(QSL("ReferrerGuardMode"), static_cast<int>(mode));' in MANAGER_CPP)
check("isEnabled() answers off-ness only - the strength is not it",
      "return m_mode != Off;" in MANAGER_CPP)
check("isSupported() answers the compile-time capability",
      re.search(r"bool ReferrerGuardManager::isSupported\(\)\s*\n\{\s*\n"
                r"#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK\(6, 5, 0\)\s*\n"
                r"\s*return true;\s*\n#else\s*\n\s*return false;\s*\n#endif", MANAGER_CPP) is not None)

check("addExclusion stores lowercase",
      "const QString trimmed = host.trimmed().toLower();" in MANAGER_CPP)
check("the list is stored deduplicated, case-insensitively",
      "!m_exclusions.contains(trimmed, Qt::CaseInsensitive)" in MANAGER_CPP)
check("setExclusions normalizes the same list the porter's import path lands",
      re.search(r"void ReferrerGuardManager::setExclusions\(const QStringList &hosts\)\s*\n\{\s*\n"
                r"\s*m_exclusions\.clear\(\);\s*\n\s*for \(const QString &host : hosts\) \{\s*\n"
                r"\s*const QString trimmed = host\.trimmed\(\)\.toLower\(\);\s*\n\s*if \(!trimmed\.isEmpty\(\) && !m_exclusions\.contains\(trimmed, Qt::CaseInsensitive\)\) \{",
                MANAGER_CPP) is not None)
check("wildcard entries match the subdomains, like the other tools' lists",
      'trimmed.startsWith(QSL("*"))' in MANAGER_CPP
      and 'host.endsWith(trimmed.mid(1), Qt::CaseInsensitive)' in MANAGER_CPP)
check("entries cover the host and its subdomains, with the dot boundary",
      'host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive)' in MANAGER_CPP)

check("the manager is registered with the build",
      "security/referrerguardmanager.cpp" in CMAKE and "security/referrerguardmanager.h" in CMAKE)
check("the exceptions dialog is registered with the build",
      "preferences/referrerexceptionsdialog.cpp" in CMAKE and "preferences/referrerexceptionsdialog.h" in CMAKE)

MAINAPP_CPP = read("src", "lib", "app", "mainapplication.cpp")
check("the app loads the manager's state at startup, beside its siblings",
      re.search(r"GpcManager::instance\(\)->loadSettings\(\);\s*\n"
                r"\s*ReferrerGuardManager::instance\(\)->loadSettings\(\);", MAINAPP_CPP) is not None)

# ------------------------------------------------------------------
# 4. The wiring
# ------------------------------------------------------------------
print("4. the wiring")

check("the fifth counter exists, total and per-host",
      "quint64 referrersTrimmed() const;" in SECURITY_MANAGER_H
      and "quint64 referrersTrimmedForHost(const QString &host) const;" in SECURITY_MANAGER_H
      and "void reportReferrerTrimmed(const QString &host);" in SECURITY_MANAGER_H)
check("the counter is persisted under its own key",
      'QSL("ReferrersTrimmed")' in SECURITY_MANAGER_CPP)
check("the counter resets and reloads with the others",
      SECURITY_MANAGER_CPP.count("m_referrersTrimmed") >= 6)
check("the host counter rides the same table as the others",
      "counters.referrers++;" in SECURITY_MANAGER_CPP
      and "m_hostCounters.value(normalizeHost(host)).referrers" in SECURITY_MANAGER_CPP)

check("relaxedProtections() judges the referrer guard like its padlock row",
      re.search(r"const auto \*referrerGuard = ReferrerGuardManager::instance\(\);\s*\n"
                r"\s*if \(referrerGuard && referrerGuard->isEnabled\(\) && referrerGuard->isExcluded\(host\)\) \{\s*\n"
                r'\s*tools\.append\(QSL\("referrerGuard"\)\);', SECURITY_MANAGER_CPP) is not None)
check("the relaxed keys keep the padlock menu's row order",
      re.search(r'tools\.append\(QSL\("globalPrivacyControl"\)\);.*?'
                r'tools\.append\(QSL\("referrerGuard"\)\);.*?'
                r'tools\.append\(QSL\("threatBlock"\)\);', SECURITY_MANAGER_CPP, re.DOTALL) is not None)

check("the padlock menu carries the row",
      'setupToolDiffLink(ui->referrerGuardDiffLink, QSL("referrerGuard"));' in SITEINFO_CPP
      and "connect(ui->referrerButton, &QPushButton::clicked, this, &SiteInfoWidget::referrerGuardButtonClicked);" in SITEINFO_CPP)
check("the padlock menu's row is hidden when the build cannot run the tool",
      re.search(r"if \(!ReferrerGuardManager::isSupported\(\)\) \{\s*\n"
                r"\s*ui->referrerLabel->hide\(\);\s*\n\s*ui->referrerButton->hide\(\);\s*\n"
                r"\s*ui->referrerGuardDiffLink->hide\(\);\s*\n\s*return;\s*\n\s*\}", SITEINFO_CPP) is not None)
check("the padlock menu's button turns the tool on at the recommended strength",
      "manager->setMode(ReferrerGuardManager::OriginOnly);" in SITEINFO_CPP)
check("the padlock menu's button reloads the network stack and the page",
      SITEINFO_CPP.count("mApp->networkManager()->loadSettings();") >= 2)
check("the padlock menu UI carries the row's widgets",
      'name="referrerLabel"' in SITEINFO_UI and 'name="referrerButton"' in SITEINFO_UI
      and 'name="referrerGuardDiffLink"' in SITEINFO_UI)

check("the sidebar carries the quick switch, the state row and the diff link",
      'createToolRow(m_referrerGuardToggle, QSL("referrerGuard"))' in SIDEBAR_CPP
      and "m_referrerGuardState" in SIDEBAR_CPP)
check("the sidebar's switch is disabled when the build cannot run the tool",
      "m_referrerGuardToggle->setEnabled(ReferrerGuardManager::isSupported());" in SIDEBAR_CPP)
check("the sidebar's switch turns the tool on at the recommended strength",
      "manager->setMode(enabled ? ReferrerGuardManager::OriginOnly : ReferrerGuardManager::Off);" in SIDEBAR_CPP)
check("the sidebar carries the fifth tile and the fifth per-site row",
      'createCounterTile(tr("Referrers trimmed"), &m_referrersValue)' in SIDEBAR_CPP
      and 'createHostRow(tr("Referrers trimmed"), &m_siteReferrersValue)' in SIDEBAR_CPP)
check("the sidebar's live values read the fifth counter",
      "security->referrersTrimmed()" in SIDEBAR_CPP
      and "security->referrersTrimmedForHost(host)" in SIDEBAR_CPP)
check("the sidebar's state row names the version requirement when it applies",
      'requires QtWebEngine 6.5+.' in SIDEBAR_CPP)

check("Preferences carries the checkbox, the strength selector and the exceptions button",
      'name="referrerGuard"' in PREFS_UI and 'name="referrerGuardMode"' in PREFS_UI
      and 'name="referrerExceptionsButton"' in PREFS_UI)
check("Preferences maps the checkbox and the selector onto the mode's values",
      re.search(r"settings\.setValue\(QSL\(\"ReferrerGuardMode\"\), !ui->referrerGuard->isChecked\(\)\s*\n"
                r"\s*\? 0\s*\n\s*: \(ui->referrerGuardMode->currentIndex\(\) == 1 \? 2 : 1\)\);", PREFS_CPP) is not None)
check("Preferences loads the mode into the checkbox and the selector",
      "ui->referrerGuard->setChecked(referrerMode != 0);" in PREFS_CPP
      and "ui->referrerGuardMode->setCurrentIndex(referrerMode == 2 ? 1 : 0);" in PREFS_CPP)
check("Preferences disables the rows when the build cannot run the tool",
      'ui->referrerGuard->setEnabled(ReferrerGuardManager::isSupported());' in PREFS_CPP
      and 'ui->labelReferrerExceptions->setEnabled(ReferrerGuardManager::isSupported());' in PREFS_CPP
      and 'ui->referrerGuardMode->setEnabled(referrerMode != 0 && ReferrerGuardManager::isSupported());' in PREFS_CPP)
check("Preferences offers the bulk exceptions dialog",
      "ReferrerExceptionsDialog dialog(Settings::globalSettings()->value(QSL(\"Web-Browser-Settings/ReferrerGuardExclusions\")"
      in PREFS_CPP)
check("the updateSecurityToolsWidgets() refresh carries the mode too",
      PREFS_CPP.count("ui->referrerGuard->setChecked(referrerMode != 0);") == 2)

check("the self-test page reports the tool with its strength",
      'toolStatus(QSL("referrerguard")' in SELFTEST_CPP
      and 'tr("Cross-site referrer protection")' in SELFTEST_CPP)
check("the self-test page names the version requirement when it applies",
      'tr("Requires QtWebEngine 6.5 or newer.")' in SELFTEST_CPP)

check("the porter exports the tool's mode and exceptions",
      'tool.insert(QSL("mode"), static_cast<int>(ReferrerGuardManager::instance()->mode()));' in PORTER_CPP)
check("the porter validates the mode by its number, not its toInt() reading",
      re.search(r"if \(std::floor\(number\) == number\s*\n\s*&& number >= static_cast<double>\(ReferrerGuardManager::Off\)\s*\n"
                r"\s*&& number <= static_cast<double>\(ReferrerGuardManager::NoReferrer\)\)", PORTER_CPP) is not None)
check("the porter applies through the manager and the network reload",
      re.search(r"ReferrerGuardManager::instance\(\)->setMode\(static_cast<ReferrerGuardManager::Mode>\(plan\.referrerMode\)\);\s*\n"
                r"\s*ReferrerGuardManager::instance\(\)->setExclusions\(plan\.exclusions\);\s*\n"
                r"\s*mApp->networkManager\(\)->loadSettings\(\);", PORTER_CPP) is not None)
check("the porter skips the section with the reason when the build cannot run the tool",
      'porterTr("this build cannot use the referrer guard")' in PORTER_CPP)
check("the porter previews the mode with the tool's own labels",
      'return porterTr("on, at most the site\'s address to other sites");' in PORTER_CPP
      and 'return porterTr("on, no referrer to other sites");' in PORTER_CPP)
check("the porter's preview carries the exception summaries, like every other list",
      re.search(r'plan\.key == QSL\("referrerGuard"\)\).*?addChange\(plan\.key, QSL\("exclusions"\)', PORTER_CPP, re.DOTALL) is not None)
check("the porter names the tool",
      'return porterTr("Cross-site referrer protection");' in PORTER_CPP)
check("the porter's key list gains the tool",
      PORTER_CPP.count('plan.key = QSL(') == 9)

check("all three baselines state the tool explicitly",
      PRESETS_CPP.count('tools.insert(QSL("referrerGuard"), referrerGuardTool(') == 3)
check("Essentials and the recommended baseline trim to the site's address",
      PRESETS_CPP.count("referrerGuardTool(1)") == 2)
check("Maximum protection sends no referrer at all",
      "referrerGuardTool(2)" in PRESETS_CPP)
check("the preset descriptions speak of the always-on protections",
      "The eight always-on protections" in PRESETS_CPP)

check("the settings-diff page speaks of nine security tools",
      "of the 9 security tools." in DIFFPAGE_CPP
      and "const int kTotalTools = 9;" in DIFFPAGE_CPP)

# ------------------------------------------------------------------
# 5. The autotests and the docs
# ------------------------------------------------------------------
print("5. the autotests and the docs")

check("the autotest declares the referrer guard slots",
      all(slot in AUTOTEST_H for slot in ("referrerGuardModeTest()", "referrerGuardExclusionTest()",
                                          "referrerGuardSameSiteTest()", "referrerGuardHeaderIntegrationTest()")))
check("the autotest defines them",
      AUTOTEST_CPP.count("void SecurityToolsTest::referrerGuard") == 4)
check("the header integration test drives the three rewrite outcomes",
      "target-off" in AUTOTEST_CPP and "target-origin" in AUTOTEST_CPP and "target-none" in AUTOTEST_CPP)
check("the integration test witnesses the leak with the tool off",
      "unsafe-url" in AUTOTEST_CPP)
check("the porter round trip carries the referrer guard",
      "referrerModeTarget" in AUTOTEST_CPP and "reader.porter.example" in AUTOTEST_CPP)
check("the relaxed-protections query test covers the fifth key",
      '"referrerGuard"' in AUTOTEST_CPP)
check("the presets test pins the eighth section and its strengths",
      'tools.value(QSL("referrerGuard")).toObject().value(QSL("mode")).toInt()' in AUTOTEST_CPP)

check("the README tells the feature",
      "cross-site referrer protection" in README)
check("the README speaks of nine tools where it spoke of eight",
      "all nine tools" in README and "all eight tools" not in README)
check("the CHANGELOG has the entry",
      "Security tools (25): cross-site referrer protection" in CHANGELOG)

# ------------------------------------------------------------------
print()
if checks[1] == 0:
    print("OK: all %d checks passed" % checks[0])
    sys.exit(0)
print("FAILED: %d of %d checks" % (checks[1], checks[0]))
sys.exit(1)
