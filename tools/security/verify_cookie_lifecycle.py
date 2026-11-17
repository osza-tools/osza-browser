#!/usr/bin/env python3
# ============================================================
# Osza - cookie lifecycle verifier
#
# Standalone verification of the ninth bundled security tool,
# without a Qt build, in the spirit of verify_referrer_guard.py
# and verify_settings_porter.py:
#
#   1. The sweep contract: only persistent cookies are ever swept
#      (a session cookie dies with the browser anyway, so deleting
#      or counting it would be a claim the tool did not earn),
#      kept sites' cookies never move in any strength, the session
#      strength keeps what the startup snapshot holds, the sweep
#      deletes through the jar's own deleteCookie(), and it reports
#      exactly the cookies it removed.
#
#   2. The keep-list judgment: a pure-Python mirror of
#      CookieLifecycleManager's host matching (the leading dot the
#      cookie grammar allows, the suite's wildcard and subdomain
#      rules) and of sweepsAtExit(), checked against truth tables.
#
#   3. The manager contract: modes off / session / clear-on-exit
#      (0/1/2), the out-of-the-box default off (the sweep ends
#      sessions on exit and is a choice, not a floor), corrupted
#      settings landing on off, the keep-list's storage
#      normalization, and the startup snapshot's once-per-process,
#      never-persisted shape.
#
#   4. The wiring: the exit sweep's place in the shutdown path
#      (before the Cookie Manager's own pass, after the private-mode
#      return), the total-only counter, the relaxed-protections
#      query, the padlock menu row, the security sidebar, the
#      Preferences rows, the self-test page row, the porter
#      (export, import validation, apply, preview with the keep
#      phrasing), the three baselines, and the diff page's tool
#      count.
#
#   5. The autotests and the docs exist.
#
# Usage:
#   python3 tools/security/verify_cookie_lifecycle.py
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


MANAGER_CPP = read("src", "lib", "security", "cookielifecyclemanager.cpp")
MANAGER_H = read("src", "lib", "security", "cookielifecyclemanager.h")
COOKIEJAR_CPP = read("src", "lib", "cookies", "cookiejar.cpp")
MAINAPP_CPP = read("src", "lib", "app", "mainapplication.cpp")
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
KEEP_DIALOG_H = read("src", "lib", "preferences", "cookiekeeplistdialog.h")
KEEP_DIALOG_CPP = read("src", "lib", "preferences", "cookiekeeplistdialog.cpp")
PORTER_CPP = read("src", "lib", "security", "securitysettingsporter.cpp")
PORTER_H = read("src", "lib", "security", "securitysettingsporter.h")
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
# 1. The sweep contract
# ------------------------------------------------------------------
print("1. the sweep contract")

check("the sweep answers the mode first: off sweeps nothing",
      re.search(r"if \(m_mode == Off\) \{\s*\n\s*return false;\s*\n\s*\}", MANAGER_CPP) is not None
      and re.search(r"if \(m_mode == Off \|\| !jar\) \{\s*\n\s*return 0;\s*\n\s*\}", MANAGER_CPP) is not None)
check("a session cookie is never the sweep's to take",
      "cookie.expirationDate().isNull()" in MANAGER_CPP)
check("a kept site's cookies never move, in any strength",
      "if (isKept(cookie.domain())) {" in MANAGER_CPP)
check("the session strength keeps what the browser started with",
      re.search(r"if \(m_mode == SessionOnly && m_startupSnapshot\.contains\(cookieKey\(cookie\)\)\) \{\s*\n"
                r"\s*return false;\s*\n\s*\}", MANAGER_CPP) is not None)
check("the sweep walks the jar's own list and deletes through the jar's own call",
      "const QVector<QNetworkCookie> cookies = jar->getAllCookies();" in MANAGER_CPP
      and "jar->deleteCookie(cookie);" in MANAGER_CPP)
check("the sweep reports exactly the cookies it removed",
      re.search(r"if \(swept > 0\) \{\s*\n\s*SecurityManager::instance\(\)->reportCookiesSwept\(swept\);",
                MANAGER_CPP) is not None)
check("the sweep needs the jar it is handed",
      "performExitSweep(CookieJar *jar)" in MANAGER_H)

check("the exit sweep runs in the shutdown path, before the Cookie Manager's own pass",
      re.search(r"CookieLifecycleManager::instance\(\)->performExitSweep\(m_cookieJar\);\s*\n"
                r"\s*if \(deleteCookies\) \{\s*\n\s*m_cookieJar->deleteAllCookies\(false\);",
                MAINAPP_CPP) is not None)
check("the shutdown path returns for private windows before the sweep can run",
      MAINAPP_CPP.index("if (isPrivate()) {") < MAINAPP_CPP.index("performExitSweep(m_cookieJar)"))

check("the snapshot is taken once per process",
      re.search(r"if \(m_snapshotTaken \|\| !mApp\) \{\s*\n\s*return;\s*\n\s*\}", MANAGER_CPP) is not None
      and "m_snapshotTaken = true;" in MANAGER_CPP)
check("the snapshot is scheduled once, from the startup load",
      re.search(r"if \(!m_snapshotScheduled && !m_snapshotTaken && mApp && !mApp->isPrivate\(\)\) \{\s*\n"
                r"\s*m_snapshotScheduled = true;\s*\n\s*QTimer::singleShot\(kSnapshotDelayMs, this, &CookieLifecycleManager::takeStartupSnapshot\);",
                MANAGER_CPP) is not None)
check("the snapshot is never persisted - it describes this process",
      "CookieStartupSnapshot" not in MANAGER_CPP
      and "StartupSnapshot" not in read("src", "lib", "security", "securitysettingsporter.cpp"))
check("the snapshot records only persistent cookies",
      re.search(r"if \(!cookie\.expirationDate\(\)\.isNull\(\)\) \{\s*\n"
                r"\s*m_startupSnapshot\.insert\(cookieKey\(cookie\)\);", MANAGER_CPP) is not None)
check("the snapshot's key is the cookie's slot, not its value",
      re.search(r"return QString::fromUtf8\(cookie\.name\(\)\)\s*\n"
                r"\s*\+ QLatin1Char\('\|'\)\s*\n"
                r"\s*\+ cookie\.domain\(\)\.toLower\(\)\s*\n"
                r"\s*\+ QLatin1Char\('\|'\)\s*\n"
                r"\s*\+ cookie\.path\(\);", MANAGER_CPP) is not None)

# ------------------------------------------------------------------
# 2. The keep-list judgment, mirrored
# ------------------------------------------------------------------
print("2. the keep-list judgment")


def host_matches_entry(host, entry):
    """Pure-Python mirror of CookieLifecycleManager::hostMatchesEntry():
    the same matcher the referrer guard and the GPC exceptions apply."""
    entry = entry.strip()
    if not entry or not host:
        return False
    if entry.startswith("*"):
        return host.endswith(entry[1:])
    return host == entry or host.endswith("." + entry)


def is_kept(cookie_domain, keep_sites):
    """Pure-Python mirror of CookieLifecycleManager::isKept(): the
    cookie grammar's leading dot is understood and dropped before
    the suite's matching runs."""
    host = cookie_domain.strip().lower()
    if host.startswith("."):
        host = host[1:]
    if not host:
        return False
    return any(host_matches_entry(host, entry) for entry in keep_sites)


KEPT_TABLE = [
    # the entry host itself, and its spelling with the cookie grammar's dot
    ("example.com", ["example.com"], True),
    (".example.com", ["example.com"], True),
    ("EXAMPLE.com", ["example.com"], True),
    # subdomains are covered
    ("deep.sub.example.com", ["example.com"], True),
    # the dot boundary keeps unrelated hosts apart
    ("notexample.com", ["example.com"], False),
    ("xexample.com", ["example.com"], False),
    # wildcards cover the subdomains only - the suite's rule
    ("sub.wild.example", ["*.wild.example"], True),
    ("wild.example", ["*.wild.example"], False),
    ("wild.example.org", ["*.wild.example"], False),
    # the empty cases
    ("", ["example.com"], False),
    (".", ["example.com"], False),
    ("example.com", [], False),
    ("example.com", [""], False),
]

for domain, entries, expected in KEPT_TABLE:
    check("mirror: %r against %r is %s" % (domain or "(empty)", entries,
                                           "kept" if expected else "not kept"),
          is_kept(domain, entries) == expected)


def sweeps_at_exit(cookie, mode, keep_sites, snapshot):
    """Pure-Python mirror of CookieLifecycleManager::sweepsAtExit().
    The cookie is (name, domain, path, persistent); the snapshot is a
    set of cookie keys, as the startup snapshot builds them."""
    name, domain, path, persistent = cookie
    if mode == 0:
        return False
    if not persistent:
        return False
    if is_kept(domain, keep_sites):
        return False
    if mode == 1 and "%s|%s|%s" % (name, domain.lower(), path) in snapshot:
        return False
    return True


SWEEP_TABLE = [
    # (cookie, mode, keep_sites, snapshot, expected)
    # off sweeps nothing
    (("sid", "a.example", "/", True), 0, [], set(), False),
    (("sid", "a.example", "/", False), 0, [], set(), False),
    # the strict strength takes every persistent cookie
    (("old", "a.example", "/", True), 2, [], set(), True),
    # but never a session cookie
    (("sess", "a.example", "/", False), 2, [], set(), False),
    # and never a kept site's, in either strength
    (("kept", ".keep.example", "/", True), 2, ["keep.example"], set(), False),
    (("kept", ".keep.example", "/", True), 1, ["keep.example"], set(), False),
    (("sub", "sub.keep.example", "/", True), 2, ["keep.example"], set(), False),
    # the session strength keeps what the snapshot holds
    (("old", "a.example", "/", True), 1, [], {("old|a.example|/")}, False),
    (("new", "b.example", "/", True), 1, [], {("old|a.example|/")}, True),
    # without a snapshot, nothing provably existed at startup
    (("any", "a.example", "/", True), 1, [], set(), True),
    # the snapshot judges the slot, not the value: refreshed value,
    # same name/domain/path, still the startup cookie
    (("sid", "a.example", "/", True), 1, [], {("sid|a.example|/")}, False),
    # the same name on another domain is a different cookie
    (("sid", "other.example", "/", True), 1, [], {("sid|a.example|/")}, True),
    # the same name and domain on another path is a different cookie
    (("sid", "a.example", "/app", True), 1, [], {("sid|a.example|/")}, True),
]

for cookie, mode, keep_sites, snapshot, expected in SWEEP_TABLE:
    strength = {0: "off", 1: "session", 2: "clear-on-exit"}[mode]
    check("mirror: %s cookie for %s at the %s strength is %s"
          % ("persistent" if cookie[3] else "session", cookie[1], strength,
             "swept" if expected else "kept"),
          sweeps_at_exit(cookie, mode, keep_sites, snapshot) == expected)

check("the C++ keep judgment strips the cookie grammar's leading dot",
      re.search(r"if \(host\.startsWith\(QLatin1Char\('\.'\)\)\) \{\s*\n"
                r"\s*host\.remove\(0, 1\);\s*\n\s*\}", MANAGER_CPP) is not None)
check("the C++ matcher carries the suite's wildcard and dot boundary",
      'trimmed.startsWith(QSL("*"))' in MANAGER_CPP
      and 'host.endsWith(trimmed.mid(1), Qt::CaseInsensitive)' in MANAGER_CPP
      and 'host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive)' in MANAGER_CPP)

# ------------------------------------------------------------------
# 3. The manager contract
# ------------------------------------------------------------------
print("3. the manager contract")

check("three modes, off / session / clear-on-exit",
      "Off = 0" in MANAGER_H and "SessionOnly = 1" in MANAGER_H and "ClearOnExit = 2" in MANAGER_H)
check("the out-of-the-box default is off - the sweep is a choice, not a floor",
      'settings.value(QSL("CookieLifecycleMode"), static_cast<int>(Off)).toInt()' in MANAGER_CPP
      and "m_mode = Off;" in MANAGER_CPP)
check("a corrupted stored mode lands on off, never on an unknown mode",
      re.search(r"if \(mode >= Off && mode <= ClearOnExit\) \{\s*\n\s*m_mode = static_cast<Mode>\(mode\);\s*\n"
                r"\s*\} else \{\s*\n\s*m_mode = Off;\s*\n\s*\}", MANAGER_CPP) is not None)
check("setMode persists and only reports real changes",
      'settings.setValue(QSL("CookieLifecycleMode"), static_cast<int>(mode));' in MANAGER_CPP)
check("isEnabled() answers off-ness only - the strength is not it",
      "return m_mode != Off;" in MANAGER_CPP)
check("the keep-list rides its own settings key",
      'settings.value(QSL("CookieKeepSites"), QStringList()).toStringList()' in MANAGER_CPP
      and 'settings.setValue(QSL("CookieKeepSites"), m_keepSites);' in MANAGER_CPP)
check("addKeepSite stores lowercase",
      "const QString trimmed = host.trimmed().toLower();" in MANAGER_CPP)
check("the list is stored deduplicated, case-insensitively",
      "!m_keepSites.contains(trimmed, Qt::CaseInsensitive)" in MANAGER_CPP)
check("setKeepSites normalizes the same list the porter's import path lands",
      re.search(r"void CookieLifecycleManager::setKeepSites\(const QStringList &hosts\)\s*\n\{\s*\n"
                r"\s*m_keepSites\.clear\(\);\s*\n\s*for \(const QString &host : hosts\) \{\s*\n"
                r"\s*const QString trimmed = host\.trimmed\(\)\.toLower\(\);\s*\n\s*if \(!trimmed\.isEmpty\(\) && !m_keepSites\.contains\(trimmed, Qt::CaseInsensitive\)\) \{",
                MANAGER_CPP) is not None)
check("the manager announces mode and keep-list changes",
      "void modeChanged(CookieLifecycleManager::Mode mode);" in MANAGER_H
      and "void keepSitesChanged();" in MANAGER_H)
check("there is no engine version gate - the sweep is the browser's own act",
      "isSupported" not in MANAGER_H and "QTWEBENGINECORE_VERSION" not in MANAGER_CPP)

check("the manager is registered with the build",
      "security/cookielifecyclemanager.cpp" in CMAKE and "security/cookielifecyclemanager.h" in CMAKE)
check("the kept-sites dialog is registered with the build",
      "preferences/cookiekeeplistdialog.cpp" in CMAKE and "preferences/cookiekeeplistdialog.h" in CMAKE)

check("the app loads the manager's state at startup, beside its siblings",
      re.search(r"ReferrerGuardManager::instance\(\)->loadSettings\(\);\s*\n"
                r"(\s*//.*\n)*\s*CookieLifecycleManager::instance\(\)->loadSettings\(\);",
                MAINAPP_CPP) is not None)

# ------------------------------------------------------------------
# 4. The wiring
# ------------------------------------------------------------------
print("4. the wiring")

check("the sixth counter exists, totals only - the sweep is the browser's last act",
      "quint64 cookiesSwept() const;" in SECURITY_MANAGER_H
      and "void reportCookiesSwept(quint64 count);" in SECURITY_MANAGER_H
      and "cookiesSweptForHost" not in SECURITY_MANAGER_H
      and "cookiesSweptForHost" not in SECURITY_MANAGER_CPP)
check("the counter is persisted under its own key",
      'QSL("CookiesSwept")' in SECURITY_MANAGER_CPP)
check("the counter resets and reloads with the others",
      SECURITY_MANAGER_CPP.count("m_cookiesSwept") >= 6)
check("the swept report carries no host table - a table nothing will ever read is not a counter",
      re.search(r"void SecurityManager::reportCookiesSwept\(quint64 count\)\s*\n\{\s*\n"
                r"[^}]*m_cookiesSwept\.fetch_add\(count, std::memory_order_relaxed\);\s*\n\}",
                SECURITY_MANAGER_CPP) is not None
      and "HostCounters" not in SECURITY_MANAGER_CPP.split("reportCookiesSwept")[1].split("quint64 SecurityManager::adsBlocked")[0])

check("relaxedProtections() judges the kept site like its padlock row",
      re.search(r"const auto \*cookieLifecycle = CookieLifecycleManager::instance\(\);\s*\n"
                r"\s*if \(cookieLifecycle && cookieLifecycle->isEnabled\(\) && cookieLifecycle->isKept\(host\)\) \{\s*\n"
                r'\s*tools\.append\(QSL\("cookieLifecycle"\)\);', SECURITY_MANAGER_CPP) is not None)
check("the relaxed keys keep the padlock menu's row order",
      re.search(r'tools\.append\(QSL\("threatBlock"\)\);.*?'
                r'tools\.append\(QSL\("cookieLifecycle"\)\);', SECURITY_MANAGER_CPP, re.DOTALL) is not None)

check("the padlock menu carries the row",
      'setupToolDiffLink(ui->cookieLifecycleDiffLink, QSL("cookieLifecycle"));' in SITEINFO_CPP
      and "connect(ui->cookieLifecycleButton, &QPushButton::clicked, this, &SiteInfoWidget::cookieLifecycleButtonClicked);" in SITEINFO_CPP)
check("the padlock menu's row is hidden for schemes cookies do not ride",
      re.search(r"if \(scheme != QL1S\(\"http\"\) && scheme != QL1S\(\"https\"\)\) \{\s*\n"
                r"\s*ui->cookieLifecycleLabel->hide\(\);\s*\n\s*ui->cookieLifecycleButton->hide\(\);\s*\n"
                r"\s*ui->cookieLifecycleDiffLink->hide\(\);\s*\n\s*return;\s*\n\s*\}", SITEINFO_CPP) is not None)
check("the padlock menu's button turns the tool on at the session strength",
      "manager->setMode(CookieLifecycleManager::SessionOnly);" in SITEINFO_CPP)
check("the padlock menu's button does not reload - the sweep is an exit discipline",
      re.search(r"void SiteInfoWidget::cookieLifecycleButtonClicked\(\)\s*\n\{(?:(?!\n\}).)*?// Nothing to reload",
                SITEINFO_CPP, re.DOTALL) is not None)
check("the padlock menu UI carries the row's widgets",
      'name="cookieLifecycleLabel"' in SITEINFO_UI and 'name="cookieLifecycleButton"' in SITEINFO_UI
      and 'name="cookieLifecycleDiffLink"' in SITEINFO_UI)

check("the sidebar carries the quick switch, the state row and the diff link",
      'createToolRow(m_cookieLifecycleToggle, QSL("cookieLifecycle"))' in SIDEBAR_CPP
      and "m_cookieLifecycleState" in SIDEBAR_CPP)
check("the sidebar's switch turns the tool on at the session strength",
      "manager->setMode(enabled ? CookieLifecycleManager::SessionOnly : CookieLifecycleManager::Off);" in SIDEBAR_CPP)
check("the sidebar's any-on judgment includes the sweep",
      re.search(r"\|\| referrerGuard\s*\n\s*\|\| cookieLifecycle;", SIDEBAR_CPP) is not None)
check("the sidebar carries the sixth tile, and no per-site row for it",
      'createCounterTile(tr("Cookies swept"), &m_cookiesSweptValue)' in SIDEBAR_CPP
      and "security->cookiesSwept()" in SIDEBAR_CPP
      and "cookiesSweptForHost" not in SIDEBAR_CPP)
check("the sidebar's state row speaks the swept history",
      "cookie(s) swept so far." in SIDEBAR_CPP)

check("Preferences carries the checkbox, the strength selector and the kept-sites button",
      'name="cookieLifecycle"' in PREFS_UI and 'name="cookieLifecycleMode"' in PREFS_UI
      and 'name="cookieKeepSitesButton"' in PREFS_UI)
check("Preferences maps the checkbox and the selector onto the mode's values",
      re.search(r"settings\.setValue\(QSL\(\"CookieLifecycleMode\"\), !ui->cookieLifecycle->isChecked\(\)\s*\n"
                r"\s*\? 0\s*\n\s*: \(ui->cookieLifecycleMode->currentIndex\(\) == 1 \? 2 : 1\)\);", PREFS_CPP) is not None)
check("Preferences loads the mode into the checkbox and the selector",
      "ui->cookieLifecycle->setChecked(cookieMode != 0);" in PREFS_CPP
      and "ui->cookieLifecycleMode->setCurrentIndex(cookieMode == 2 ? 1 : 0);" in PREFS_CPP)
check("the updateSecurityToolsWidgets() refresh carries the mode too",
      PREFS_CPP.count("ui->cookieLifecycle->setChecked(cookieMode != 0);") == 2)
check("Preferences offers the bulk kept-sites dialog",
      "CookieKeepSitesDialog dialog(Settings::globalSettings()->value(QSL(\"Web-Browser-Settings/CookieKeepSites\")"
      in PREFS_CPP)
check("the dialog answers the same list it was given",
      "QStringList CookieKeepSitesDialog::keepSites() const" in KEEP_DIALOG_CPP
      and "keepSites() const;" in KEEP_DIALOG_H)

check("the self-test page reports the tool with its strength",
      'toolStatus(QSL("cookielifecycle")' in SELFTEST_CPP
      and 'tr("Cookie lifecycle on exit")' in SELFTEST_CPP)
check("the self-test page speaks the kept-site count and the swept history",
      "site(s) keep their cookies." in SELFTEST_CPP
      and "cookie(s) swept so far." in SELFTEST_CPP)

check("the porter exports the tool's mode and kept sites",
      'tool.insert(QSL("mode"), static_cast<int>(CookieLifecycleManager::instance()->mode()));' in PORTER_CPP
      and 'tool.insert(QSL("keepSites"),' in PORTER_CPP)
check("the porter validates the mode by its number, not its toInt() reading",
      re.search(r"if \(std::floor\(number\) == number\s*\n\s*&& number >= static_cast<double>\(CookieLifecycleManager::Off\)\s*\n"
                r"\s*&& number <= static_cast<double>\(CookieLifecycleManager::ClearOnExit\)\)", PORTER_CPP) is not None)
check("the porter applies through the manager, with no network reload and no skip",
      re.search(r"CookieLifecycleManager::instance\(\)->setMode\(static_cast<CookieLifecycleManager::Mode>\(plan\.cookieMode\)\);\s*\n"
                r"\s*CookieLifecycleManager::instance\(\)->setKeepSites\(plan\.keepSites\);", PORTER_CPP) is not None
      and "cannot use the cookie" not in PORTER_CPP)
check("the porter previews the mode with the tool's own labels",
      'return porterTr("on, only this session\'s cookies swept");' in PORTER_CPP
      and 'return porterTr("on, every cookie except kept sites swept");' in PORTER_CPP)
check("the porter's preview carries the kept-sites summaries in the keep phrasing",
      'porterTr("Stops keeping cookies for: %1")' in PORTER_CPP
      and 'porterTr("Starts keeping cookies for: %1")' in PORTER_CPP)
check("the porter names the tool and its field",
      'return porterTr("Cookie lifecycle on exit");' in PORTER_CPP
      and 'return porterTr("Kept sites");' in PORTER_CPP)
check("the porter's key list gains the tool",
      PORTER_CPP.count('plan.key = QSL(') == 9)
check("the format documentation shows the section's shape",
      '"cookieLifecycle"' in PORTER_H and '"keepSites"' in PORTER_H)

check("all three baselines state the tool explicitly",
      PRESETS_CPP.count('tools.insert(QSL("cookieLifecycle"), cookieLifecycleTool(') == 3)
check("Essentials and the recommended baseline leave the sweep off",
      PRESETS_CPP.count("cookieLifecycleTool(0)") == 2)
check("Maximum protection sweeps every cookie and keeps no site",
      "cookieLifecycleTool(2)" in PRESETS_CPP)
check("the preset descriptions speak the split honestly",
      "The eight always-on protections" in PRESETS_CPP
      and "the cookie exit sweep stays off" in PRESETS_CPP)

check("the settings-diff page speaks of nine security tools",
      "of the 9 security tools." in DIFFPAGE_CPP
      and "const int kTotalTools = 9;" in DIFFPAGE_CPP)

# ------------------------------------------------------------------
# 5. The autotests and the docs
# ------------------------------------------------------------------
print("5. the autotests and the docs")

check("the autotest declares the cookie lifecycle slots",
      all(slot in AUTOTEST_H for slot in ("cookieLifecycleModeTest()", "cookieLifecycleKeepListTest()",
                                          "cookieLifecycleSweepTest()", "cookieLifecycleExitSweepIntegrationTest()")))
check("the autotest defines them",
      AUTOTEST_CPP.count("void SecurityToolsTest::cookieLifecycle") == 4)
check("the integration test drives the sweep against the real cookie store",
      "sweep-startup" in AUTOTEST_CPP and "sweep-session" in AUTOTEST_CPP
      and "sweep-keep.example" in AUTOTEST_CPP and "sweep-doomed" in AUTOTEST_CPP)
check("the integration test takes the snapshot itself when it still can",
      "manager->takeStartupSnapshot();" in AUTOTEST_CPP
      and "manager->hasStartupSnapshot()" in AUTOTEST_CPP)
check("the relaxed-protections query test covers the sixth key",
      '"cookieLifecycle"' in AUTOTEST_CPP)
check("the presets test pins the ninth section and its strengths",
      'tools.value(QSL("cookieLifecycle")).toObject().value(QSL("mode")).toInt()' in AUTOTEST_CPP)
check("the porter round trip carries the cookie lifecycle",
      "cookieModeTarget" in AUTOTEST_CPP and "mail.porter.example" in AUTOTEST_CPP)
check("the settings-diff accounting keeps its identity at nine sections",
      "QCOMPARE(quiet + accounted.size(), 9);" in AUTOTEST_CPP)

check("the README tells the feature",
      "cookie lifecycle on exit" in README)
check("the README speaks of nine tools where it spoke of eight",
      "all nine tools" in README and "all eight tools" not in README)
check("the README's badge list names the kept site",
      "a kept site whose" in README)
check("the CHANGELOG has the entry",
      "Security tools (26): cookie lifecycle on exit" in CHANGELOG)

# ------------------------------------------------------------------
print()
if checks[1] == 0:
    print("OK: all %d checks passed" % checks[0])
    sys.exit(0)
print("FAILED: %d of %d checks" % (checks[1], checks[0]))
sys.exit(1)
