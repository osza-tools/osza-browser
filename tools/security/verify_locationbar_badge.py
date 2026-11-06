#!/usr/bin/env python3
# ============================================================
# Osza - location-bar protections badge verifier
#
# Standalone verification of the protections-relaxed badge in the
# location bar (the amber dot on the site icon that says the site
# has per-site exceptions) and of the blocklist update-in-progress
# pulse (the breathing cyan glow behind the icon while a refresh
# runs), without a Qt build, in the spirit of
# verify_settings_diff_page.py and verify_settings_porter.py:
#
#   1. The state exists once: SecurityManager::relaxedProtections()
#      is the only place that judges "which protections are relaxed
#      for this site" outside the padlock menu's own rows, both
#      location bars route through it, and no one else does.
#
#   2. The query is honest per tool: enabled first, then the site's
#      own exception (hasExplicitExclusion / isExcluded / isExcluded
#      / isSessionAllowed - the exact APIs the padlock menu's rows
#      use), http/https only, keys in the padlock menu's row order.
#
#   3. The keys are the porter's: the four literals the query
#      appends are exactly the four per-site tools in the porter's
#      buildPlans() key list, so a badge can never name a tool the
#      porter (import, diff, presets) does not know; the display
#      names come from toolDisplayName(), the same catalog the
#      padlock menu and the dashboard use.
#
#   4. Both marks are drawn once each: SiteIcon::paintRelaxedBadge
#      and SiteIcon::paintUpdatePulse are the only drawing codes
#      (composited into the location bar's 16 px icon, painted over
#      the popup's own icon area), so the two surfaces cannot drift
#      apart.
#
#   5. The badge refreshes everywhere the state can move: the five
#      hooks in the location bar (urlChanged, the updateSiteIcon
#      funnel, loadFinished, loadSettings, the padlock menu
#      closing through SiteIcon::siteInfoClosed) and the popup's
#      equivalents (showSiteIcon from iconChanged and urlChanged,
#      setPrivacyState refreshing through showSiteIcon); typing
#      clears it (the search icon carries no site state). The pulse
#      is wired once, to the manager's lifecycle: updateStarted,
#      listUpdated and updateFailed all land in one slot that asks
#      isUpdating() - the same mutex-guarded flag every other
#      surface reports through - in both bars.
#
#   6. The tooltip contract: the default tooltip has exactly one
#      translation context (SiteIcon, the constructor and the
#      composed tooltip agree), the relaxed tooltip is built in one
#      place that both surfaces call, and the pulse's note is one
#      string (listUpdatingToolTip) named by both surfaces'
#      tooltips wherever the glow appears.
#
#   7. Qt keyword discipline in the touched headers (Q_SIGNALS /
#      Q_SLOTS, never bare signals:/slots: - the tree builds with
#      -DQT_NO_KEYWORDS) and the one-pixmap-shape discipline of
#      composeBadgeIcon (device pixel ratio preserved, so high-dpi
#      needs no second code path).
#
#   8. The autotests carry the feature: the query test (order,
#      per-tool joins, tool-off retirement, scheme gate, subdomains)
#      and the widget tests (badge and tooltip on the site icon, the
#      same-scheme navigation that only urlChanged can carry, the
#      osza: scheme clearing it; the pulse arriving and leaving the
#      icon with its tooltip, the breath moving).
#
#   9. The README and the CHANGELOG tell the user about it.
#
# Usage:
#   python3 tools/security/verify_locationbar_badge.py
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    os.pardir, os.pardir)

SECURITY_MANAGER_H = os.path.join(ROOT, "src", "lib", "security", "securitymanager.h")
SECURITY_MANAGER_CPP = os.path.join(ROOT, "src", "lib", "security", "securitymanager.cpp")
PORTER_CPP = os.path.join(ROOT, "src", "lib", "security", "securitysettingsporter.cpp")
SITEINFO_CPP = os.path.join(ROOT, "src", "lib", "other", "siteinfowidget.cpp")
SITEICON_H = os.path.join(ROOT, "src", "lib", "navigation", "siteicon.h")
SITEICON_CPP = os.path.join(ROOT, "src", "lib", "navigation", "siteicon.cpp")
LOCATIONBAR_H = os.path.join(ROOT, "src", "lib", "navigation", "locationbar.h")
LOCATIONBAR_CPP = os.path.join(ROOT, "src", "lib", "navigation", "locationbar.cpp")
POPUPBAR_CPP = os.path.join(ROOT, "src", "lib", "popupwindow", "popuplocationbar.cpp")
AUTOTEST_H = os.path.join(ROOT, "autotests", "securitytoolstest.h")
AUTOTEST_CPP = os.path.join(ROOT, "autotests", "securitytoolstest.cpp")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG")

import re

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

manager_h = read(SECURITY_MANAGER_H)
manager_cpp = read(SECURITY_MANAGER_CPP)
porter_cpp = read(PORTER_CPP)
siteinfo_cpp = read(SITEINFO_CPP)
siteicon_h = read(SITEICON_H)
siteicon_cpp = read(SITEICON_CPP)
locationbar_h = read(LOCATIONBAR_H)
locationbar_cpp = read(LOCATIONBAR_CPP)
popupbar_cpp = read(POPUPBAR_CPP)
autotest_h = read(AUTOTEST_H)
autotest_cpp = read(AUTOTEST_CPP)
readme = read(README)
changelog = read(CHANGELOG)

failures = 0
checks = 0


def check(label, ok):
    global failures, checks
    checks += 1
    print(("  PASS " if ok else "  FAIL ") + label)
    if not ok:
        failures += 1


def body(text, signature):
    """The source of one function, from its signature to the next
    function definition at the same level - a small structural cut
    so the checks below reason about whole functions, not lines.
    The boundary accepts the two shapes this tree's definitions
    take (a plain ')' and a ') const') so a cut can never run past
    the end of the function it means."""
    start = text.find(signature)
    if start == -1:
        return None
    rest = text[start:]
    next_def = re.search(r"\n[A-Za-z].*\)(?:\s+const)?\s*\n?\{", rest[len(signature):])
    end = len(signature) + next_def.start() if next_def else len(rest)
    return rest[:end]


# ------------------------------------------------------------------
# 1. The state exists once
# ------------------------------------------------------------------
print("1. one query, two consumers, no strays")

query_sig = "QStringList SecurityManager::relaxedProtections(const QUrl &url)"
query = body(manager_cpp, query_sig)
check("SecurityManager::relaxedProtections is defined in securitymanager.cpp",
      query is not None)
check("the query is declared in securitymanager.h",
      "static QStringList relaxedProtections(const QUrl &url);" in manager_h)

consumers = []
for name, text in (("locationbar.cpp", locationbar_cpp),
                   ("popuplocationbar.cpp", popupbar_cpp)):
    if "SecurityManager::relaxedProtections(" in text:
        consumers.append(name)
check("both location bars query through it (locationbar.cpp, popuplocationbar.cpp)",
      consumers == ["locationbar.cpp", "popuplocationbar.cpp"])

# The padlock menu judges its rows directly; the query must agree
# with each row instead of duplicating a second judgment - the
# cross-checks in section 2 enforce that agreement.
strays = []
for path in (os.path.join(ROOT, "src"), os.path.join(ROOT, "autotests")):
    for dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            if not filename.endswith((".cpp", ".h")):
                continue
            if filename in ("securitymanager.cpp", "siteinfowidget.cpp"):
                continue
            full = os.path.join(dirpath, filename)
            if "relaxedProtections(" in read(full) and full not in (
                    LOCATIONBAR_CPP, POPUPBAR_CPP, SITEICON_H, SITEICON_CPP,
                    SECURITY_MANAGER_H, AUTOTEST_CPP, AUTOTEST_H):
                strays.append(os.path.relpath(full, ROOT))
check("no other file judges per-site relaxed protections", strays == [])

# ------------------------------------------------------------------
# 2. The query is honest per tool
# ------------------------------------------------------------------
print("2. the query judges like the padlock menu's rows")

check("scheme gate first: http/https only, like the rows",
      "scheme != QL1S(\"http\") && scheme != QL1S(\"https\")" in query)

tool_checks = [
    ("httpsOnly", "httpsOnlyInterceptor()", "isEnabled()", "hasExplicitExclusion(host)"),
    ("fingerprintProtection", "FingerprintManager::instance()", "isEnabled()", "isExcluded(host)"),
    ("globalPrivacyControl", "GpcManager::instance()", "isEnabled()", "isExcluded(host)"),
    ("threatBlock", "threatBlockManager()", "isEnabled()", "isSessionAllowed(host)"),
]
appended_order = [m.group(1) for m in re.finditer(r'tools\.append\(QSL\("([a-zA-Z]+)"\)\);', query)]
check("the four tools append in the padlock menu's row order",
      appended_order == ["httpsOnly", "fingerprintProtection", "globalPrivacyControl", "threatBlock"])

for key, manager, enabled, per_site in tool_checks:
    ok = (manager in query and enabled in query and per_site in query)
    # each per-site test runs only while its tool is enabled:
    # the appends sit inside "if (tool && tool->isEnabled() && ...)"
    pattern = r"if \([^)]*isEnabled\(\) && [^)]*" + re.escape(per_site) + r"\)"
    ok = ok and re.search(pattern, query) is not None
    check("%s: %s, enabled-gated, %s" % (key, manager, per_site), ok)

check("both network-owned managers come from mApp->networkManager()",
      query.count("mApp->networkManager()->") == 2)

# ------------------------------------------------------------------
# 3. The keys are the porter's
# ------------------------------------------------------------------
print("3. keys and names from the porter's catalog")

porter_keys = re.findall(r'plan\.key = QSL\("([a-zA-Z]+)"\);', porter_cpp)
check("the porter's buildPlans() knows all seven tools",
      len(porter_keys) == 7)

per_site_keys = ["httpsOnly", "fingerprintProtection", "globalPrivacyControl", "threatBlock"]
check("the four per-site keys are a subset of the porter's keys",
      all(k in porter_keys for k in per_site_keys))

for key in per_site_keys:
    check("toolDisplayName() names %s" % key,
          'tool == QSL("%s")' % key in porter_cpp)

check("the location bar resolves names through the porter only",
      "SecuritySettingsPorter::toolDisplayName(key)" in locationbar_cpp)
check("the popup resolves names through the porter only",
      "SecuritySettingsPorter::toolDisplayName(key)" in popupbar_cpp)

# ------------------------------------------------------------------
# 4. The badge is drawn once
# ------------------------------------------------------------------
print("4. one drawing code, two surfaces")

check("SiteIcon::paintRelaxedBadge is declared in siteicon.h",
      "static void paintRelaxedBadge(QPainter *painter, const QRectF &iconArea);" in siteicon_h)
badge = body(siteicon_cpp, "void SiteIcon::paintRelaxedBadge(QPainter *painter, const QRectF &iconArea)")
check("SiteIcon::paintRelaxedBadge is defined in siteicon.cpp", badge is not None)
check("the badge geometry scales with the icon area (no hardcoded size)",
      "iconArea.width()" in badge and "drawEllipse" in badge)
check("the badge is amber (between the suite's cyan and the interstitial's red)",
      "0xf5, 0xa5, 0x24" in badge)

check("SiteIcon::paintUpdatePulse is declared in siteicon.h",
      "static void paintUpdatePulse(QPainter *painter, const QRectF &iconArea, qreal phase);" in siteicon_h)
pulse = body(siteicon_cpp, "void SiteIcon::paintUpdatePulse(QPainter *painter, const QRectF &iconArea, qreal phase)")
check("SiteIcon::paintUpdatePulse is defined in siteicon.cpp", pulse is not None)
check("the pulse geometry scales with the icon area (no hardcoded size)",
      "iconArea.width()" in pulse and "iconArea.center()" in pulse and "drawEllipse" in pulse)
check("the pulse is the suite's cyan (the browser at work, not the amber of an exception nor the red of the warning)",
      "0x00, 0xc8, 0xa8" in pulse)
check("the pulse breathes through the phase (a triangle wave, dim at the edges, bright at the center - never a blink)",
      "qAbs(2.0 * phase - 1.0)" in pulse and "breathe" in pulse)

check("the location bar composites the badge into the 16 px icon",
      "paintRelaxedBadge(&p, QRectF(0, 0, 16, 16));" in body(siteicon_cpp, "QIcon SiteIcon::composeBadgeIcon(const QIcon &icon) const"))
check("the popup paints it over its own icon area",
      "SiteIcon::paintRelaxedBadge(&p, QRectF(rect()));" in popupbar_cpp)
compose = body(siteicon_cpp, "QIcon SiteIcon::composeBadgeIcon(const QIcon &icon) const")
check("the location bar composites the pulse into the 16 px icon, behind the glyph",
      "paintUpdatePulse(&p, QRectF(0, 0, 16, 16), m_pulsePhase);" in compose)
check("the popup paints the pulse over its own icon area, behind the glyph",
      "SiteIcon::paintUpdatePulse(&p, QRectF(rect()), m_pulsePhase);" in popupbar_cpp)

badge_draws = []
for name, text in (("siteicon.cpp", siteicon_cpp), ("popuplocationbar.cpp", popupbar_cpp)):
    badge_draws += ["%s:%d" % (name, i + 1)
                    for i, line in enumerate(text.splitlines())
                    if "drawEllipse" in line]
check("drawEllipse lives only inside the two painters in siteicon.cpp (one drawing code each, none in the popup)",
      len(badge_draws) == 4 and all("siteicon.cpp" in d for d in badge_draws))

check("the composite keeps the source pixmap's device pixel ratio",
      "setDevicePixelRatio(base.devicePixelRatio())" in compose)
check("the composite returns the untouched icon when nothing is relaxed and no update runs",
      "if (m_relaxedProtections.isEmpty() && !m_listUpdating)" in compose)
check("updateIcon routes through the composite",
      "ToolButton::setIcon(composeBadgeIcon(m_icon));" in siteicon_cpp)
check("the icon-set debounce survives the badge (the timer still guards rapid base changes)",
      "m_updateTimer->start();" in siteicon_cpp)
check("the pulse has its own timer, started and stopped by its setter",
      "m_pulseTimer->start();" in siteicon_cpp and "m_pulseTimer->stop();" in siteicon_cpp
      and "&SiteIcon::advancePulse" in siteicon_cpp)
advance = body(siteicon_cpp, "void SiteIcon::advancePulse()")
check("the pulse's phase advances and wraps inside advancePulse",
      advance is not None
      and "m_pulsePhase += 0.08;" in advance and "m_pulsePhase -= 1.0;" in advance)

# ------------------------------------------------------------------
# 5. The badge refreshes everywhere the state can move
# ------------------------------------------------------------------
print("5. every refresh hook")

hooks = [
    ("urlChanged drives it (same-scheme navigations, focused or not)",
     "connect(m_webView, &QWebEngineView::urlChanged, this, &LocationBar::updateProtectionsBadge);" in locationbar_cpp),
    ("the updateSiteIcon funnel refreshes it (privacy, completer close, loads from the bar)",
     "    updateProtectionsBadge();\n}" in body(locationbar_cpp, "void LocationBar::updateSiteIcon()")),
    ("loadFinished refreshes it (reloads)",
     "updateProtectionsBadge();" in body(locationbar_cpp, "void LocationBar::loadFinished()")),
    ("loadSettings refreshes it (a global switch retires the exception)",
     "updateProtectionsBadge();" in body(locationbar_cpp, "void LocationBar::loadSettings()")),
    ("the padlock menu closing refreshes it (HTTPS-Only on https reloads nothing)",
     "connect(m_siteIcon, &SiteIcon::siteInfoClosed, this, &LocationBar::updateProtectionsBadge);" in locationbar_cpp),
    ("updateProtectionsBadge is a slot of the location bar",
     "void updateProtectionsBadge();" in locationbar_h),
    ("popupClosed emits the signal the bar listens for",
     "Q_EMIT siteInfoClosed();" in body(siteicon_cpp, "void SiteIcon::popupClosed()")),
    ("siteInfoClosed is declared under Q_SIGNALS",
     "void siteInfoClosed();" in siteicon_h.split("Q_SIGNALS:", 1)[1].split("private Q_SLOTS:", 1)[0]),
    ("typing clears it (the search icon carries no site state)",
     "m_siteIcon->setRelaxedProtections(QStringList());" in body(locationbar_cpp, "void LocationBar::textEdited(const QString &text)")),
    ("the completer-visible branch clears it too",
     "m_siteIcon->setRelaxedProtections(QStringList());" in body(locationbar_cpp, "void LocationBar::updateSiteIcon()").split("return;")[0]),
    ("the popup's urlChanged refreshes its icon and badge",
     "connect(m_view, &QWebEngineView::urlChanged, this, &PopupLocationBar::showSiteIcon);" in popupbar_cpp),
    ("the popup's setPrivacyState refreshes through showSiteIcon",
     "showSiteIcon();" in body(popupbar_cpp, "void PopupLocationBar::setPrivacyState(bool state)")),
    ("the popup's showSiteIcon queries and applies the badge",
     "m_siteIcon->setRelaxedProtections(protections);" in body(popupbar_cpp, "void PopupLocationBar::showSiteIcon()")),
    ("an unchanged list is a no-op (the hooks can fire freely)",
     "if (m_relaxedProtections == protections) {" in siteicon_cpp
     and "if (m_relaxedProtections == protections) {" in popupbar_cpp),
    ("an unchanged update value is a no-op too (the lifecycle signals can fire freely)",
     "if (m_listUpdating == updating) {" in siteicon_cpp
     and "if (m_listUpdating == updating) {" in popupbar_cpp),
    ("the manager's updateStarted lands in the location bar's indicator slot",
     "connect(threatBlockManager, &ThreatBlockManager::updateStarted, this, &LocationBar::updateBlocklistIndicator);" in locationbar_cpp),
    ("the manager's listUpdated lands in the same slot (the pulse ends with the evidence)",
     "connect(threatBlockManager, &ThreatBlockManager::listUpdated, this, &LocationBar::updateBlocklistIndicator);" in locationbar_cpp),
    ("the manager's updateFailed lands in the same slot (a named failure silences it too)",
     "connect(threatBlockManager, &ThreatBlockManager::updateFailed, this, &LocationBar::updateBlocklistIndicator);" in locationbar_cpp),
    ("updateBlocklistIndicator is a slot of the location bar",
     "void updateBlocklistIndicator();" in locationbar_h),
    ("the slot asks the one mutex-guarded in-flight query, like every other surface",
     "setListUpdating(mApp->networkManager()->threatBlockManager()->isUpdating());" in locationbar_cpp),
    ("a refresh already running when the bar appears still pulses (the initial sync)",
     "\n    updateBlocklistIndicator();\n" in locationbar_cpp),
    ("the popup wires the same three lifecycle signals to its own indicator slot",
     "connect(threatBlockManager, &ThreatBlockManager::updateStarted, this, &PopupLocationBar::updateBlocklistIndicator);" in popupbar_cpp
     and "connect(threatBlockManager, &ThreatBlockManager::listUpdated, this, &PopupLocationBar::updateBlocklistIndicator);" in popupbar_cpp
     and "connect(threatBlockManager, &ThreatBlockManager::updateFailed, this, &PopupLocationBar::updateBlocklistIndicator);" in popupbar_cpp),
    ("the popup's indicator slot asks the same one query",
     "setListUpdating(mApp->networkManager()->threatBlockManager()->isUpdating());" in popupbar_cpp
     and "void updateBlocklistIndicator();" in read(os.path.join(ROOT, "src", "lib", "popupwindow", "popuplocationbar.h"))),
    ("a refresh already running when the popup appears still pulses (the initial sync)",
     "\n    updateBlocklistIndicator();\n" in popupbar_cpp),
    ("the pulse's own timer in the popup breathes at the location bar's cadence",
     "m_pulseTimer->setInterval(80);" in popupbar_cpp and "&PopupSiteIcon::advancePulse" in popupbar_cpp),
]
for label, ok in hooks:
    check(label, ok)

# ------------------------------------------------------------------
# 6. The tooltip contract
# ------------------------------------------------------------------
print("6. the tooltip")

check("relaxedProtectionsToolTip is declared in siteicon.h",
      "static QString relaxedProtectionsToolTip(const QStringList &protections, bool clickable);" in siteicon_h)
tooltip = body(siteicon_cpp, "QString SiteIcon::relaxedProtectionsToolTip(const QStringList &protections, bool clickable)")
check("relaxedProtectionsToolTip is defined in siteicon.cpp", tooltip is not None)
check("it names the protections and distinguishes clickable from passive",
      ".arg(names)" in tooltip and tooltip.count("tr(") == 2)
check("both surfaces build their tooltip through it",
      "relaxedProtectionsToolTip(m_relaxedProtections, true)" in siteicon_cpp
      and "SiteIcon::relaxedProtectionsToolTip(m_relaxedProtections, false)" in popupbar_cpp)
check("the default tooltip has one translation context (SiteIcon: the constructor and the composed tooltip agree)",
      siteicon_cpp.count('tr("Show information about this page")') == 2
      and "LocationBar::tr(" not in siteicon_cpp)

apply_tooltip = body(siteicon_cpp, "void SiteIcon::applyToolTip()")
check("the tooltip is composed in one place both setters call",
      apply_tooltip is not None
      and "applyToolTip();" in body(siteicon_cpp, "void SiteIcon::setRelaxedProtections(const QStringList &protections)")
      and "applyToolTip();" in body(siteicon_cpp, "void SiteIcon::setListUpdating(bool updating)"))
check("the composed tooltip speaks the standing state first, then the pulse's note, else the default",
      "parts.append(relaxedProtectionsToolTip(m_relaxedProtections, true));" in apply_tooltip
      and "parts.append(listUpdatingToolTip());" in apply_tooltip
      and 'tr("Show information about this page")' in apply_tooltip)
check("listUpdatingToolTip is declared and defined, one string, one context",
      "static QString listUpdatingToolTip();" in siteicon_h
      and body(siteicon_cpp, "QString SiteIcon::listUpdatingToolTip()") is not None
      and siteicon_cpp.count('tr("The malicious-site blocklist is being refreshed now.")') == 1)
check("the popup's tooltip names the pulse through the same string",
      "SiteIcon::listUpdatingToolTip()" in popupbar_cpp)
check("setListUpdating exposes the state the autotest asserts on",
      "bool listUpdating() const;" in siteicon_h)

# ------------------------------------------------------------------
# 7. Qt keyword and API discipline
# ------------------------------------------------------------------
print("7. discipline")

for name, text in (("siteicon.h", siteicon_h), ("locationbar.h", locationbar_h),
                   ("securitymanager.h", manager_h)):
    check("%s uses Q_SIGNALS/Q_SLOTS only (the tree builds with -DQT_NO_KEYWORDS)" % name,
          not re.search(r"^\s*(signals|slots)\s*:", text, re.MULTILINE))

check("setRelaxedProtections exposes the state the autotest asserts on",
      "QStringList relaxedProtections() const;" in siteicon_h)

# ------------------------------------------------------------------
# 8. The autotests carry the feature
# ------------------------------------------------------------------
print("8. autotests")

check("the query test is declared and defined",
      "void relaxedProtectionsQueryTest();" in autotest_h
      and "void SecurityToolsTest::relaxedProtectionsQueryTest()" in autotest_cpp)
check("the widget test is declared and defined",
      "void locationBarProtectionsBadgeTest();" in autotest_h
      and "void SecurityToolsTest::locationBarProtectionsBadgeTest()" in autotest_cpp)
check("the pulse widget test is declared and defined",
      "void locationBarListUpdatePulseTest();" in autotest_h
      and "void SecurityToolsTest::locationBarListUpdatePulseTest()" in autotest_cpp)

query_test = body(autotest_cpp, "void SecurityToolsTest::relaxedProtectionsQueryTest()")
widget_test = body(autotest_cpp, "void SecurityToolsTest::locationBarProtectionsBadgeTest()")

check("the query test: order of the four keys",
      'QStringList{QSL("httpsOnly"), QSL("fingerprintProtection"), QSL("globalPrivacyControl"), QSL("threatBlock")}' in query_test)
check("the query test: a tool off globally retires the exception",
      'off.setValue(QSL("FingerprintProtection"), false);' in query_test)
check("the query test: the scheme gate (osza:, file:, empty URL)",
      'QUrl(QSL("osza:start"))' in query_test and 'QUrl(QSL("file:///tmp/x"))' in query_test
      and "relaxedProtections(QUrl())" in query_test)
check("the query test: subdomains and a clean sibling",
      "deep.%1" in query_test and "sibling.example" in query_test)
check("the query test: the keys exist in the porter's catalog",
      "SecuritySettingsPorter::toolKeys().contains(key)" in query_test)

check("the widget test: finds the real site icon of a real window",
      'findChild<SiteIcon*>(QSL("locationbar-siteicon"))' in widget_test)
check("the widget test: the badge and its tooltip appear on an excepted site",
      "toolTip().contains(SecuritySettingsPorter::toolDisplayName" in widget_test
      and "iconWithBadge != iconWithoutBadge" in widget_test)
check("the widget test: the same-scheme navigation clears it (only urlChanged can)",
      "clean2.example" in widget_test
      and "QCOMPARE(siteIcon->icon().pixmap(16).toImage(), iconWithoutBadge);" in widget_test)
check("the widget test: the browser's own scheme clears it",
      'QUrl(QSL("osza:start"))' in widget_test)
check("the widget test: restores the settings it touched",
      "httpsOnlyBefore" in widget_test and "exclusionsBefore" in widget_test)

pulse_test = body(autotest_cpp, "void SecurityToolsTest::locationBarListUpdatePulseTest()")

check("the pulse test: finds the real site icon of a real window",
      'findChild<SiteIcon*>(QSL("locationbar-siteicon"))' in pulse_test)
check("the pulse test: the glow arrives with the tooltip's note and changes the icon",
      "setListUpdating(true)" in pulse_test and "iconWithPulse != iconAtRest" in pulse_test
      and "SiteIcon::listUpdatingToolTip()" in pulse_test)
check("the pulse test: the breath moves (ticks later, still a glow over the same padlock)",
      "QTest::qWait(200)" in pulse_test and "!= iconAtRest" in pulse_test)
check("the pulse test: the end returns the plain icon and the default tooltip",
      "setListUpdating(false)" in pulse_test
      and "QCOMPARE(siteIcon->icon().pixmap(16).toImage(), iconAtRest);" in pulse_test
      and 'QSL("Show information about this page")' in pulse_test)
check("the pulse test: an unchanged value is a no-op",
      pulse_test.count("setListUpdating(true)") == 2)

# ------------------------------------------------------------------
# 9. The docs
# ------------------------------------------------------------------
print("9. docs")

check("the README tells the user about the badge",
      "badge" in readme.lower() and "relaxed" in readme.lower())
check("the README tells the user about the pulse",
      "puls" in readme.lower() and "refresh" in readme.lower())
check("the CHANGELOG has an entry",
      "badge" in changelog.lower())
check("the CHANGELOG has a pulse entry too",
      "puls" in changelog.lower())

print()
if failures:
    print("FAILED: %d of %d checks" % (failures, checks))
    raise SystemExit(1)
print("OK: all %d checks passed" % checks)
