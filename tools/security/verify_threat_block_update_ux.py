#!/usr/bin/env python3
# ============================================================
# Osza - threat-block update-UX verifier
#
# Standalone verification of the blocklist update lifecycle as the
# surfaces report it (the interstitial's list-state row and the
# padlock menu's threat-block row speaking isUpdating() /
# updateFailed in relative-age, failure and "refresh now" terms),
# without a Qt build, in the spirit of verify_threat_interstitial.py
# and verify_settings_diff_page.py:
#
#   1. One staleness judgment: the file-local listIsStale() answers
#      "is this list due for a refresh"; the public isListStale()
#      and the manager's own timer (checkForUpdate) route through
#      it, and the interstitial reads it under the lock it already
#      holds (the public query would deadlock there).
#
#   2. The remembered failure: lastUpdateError() is declared,
#      locked and documented; m_lastError is set before every
#      updateFailed emission, cleared when a list lands and when a
#      new attempt starts; m_updating became mutex-guarded shared
#      state (the interstitial reads it on the IO thread). The
#      lifecycle now speaks its start too: updateStarted() is
#      declared, emitted exactly where an attempt actually begins
#      (outside the mutex, before the source is weighed), and the
#      chrome hears the whole renewal through it.
#
#   3. The interstitial's list-state row: one snapshot (exactly one
#      lock), the age through describeListAge() (relative, the
#      decision-weighing phrasing), the three honest tails
#      (updating now / the last update failed, escaped / the not-
#      downloaded-yet honesty kept), and the "refresh now" link
#      built from the one URL shape and HTML-escaped for the href.
#      The row also speaks the movement the last refresh brought
#      next to the size and age it belongs to: remembered once, in
#      applyListData() (the one path a renewal takes, never the
#      startup disk load) from the count of the list it replaced -
#      "(+1,204 hosts since the last refresh)", "(unchanged since
#      the last refresh)", and silence for a first list or after
#      a restart, which have seen no movement to claim.
#
#   3c. One movement, every surface that speaks the list's age: the
#      wording is composed in exactly one place
#      (ThreatBlockManager::listMovementLocked, served to the
#      padlock menu's coverage row and the sidebar's status row by
#      the public self-locking listMovement()), so the interstitial's
#      evidence row, the padlock row and the sidebar speak the same
#      string with the same silences and can never name two
#      different movements for one refresh.
#
#   4. The refresh URL contract: refreshListPageUrl() /
#      isRefreshListPageUrl() mirror the proceed URL's shape, the
#      two flags answer for neither but themselves, and the scheme
#      handler answers the update address with updateNow() (never
#      in test mode) and a re-serve of the same interstitial.
#
#   4b. The interstitial re-serves itself when a refresh lands: the
#      page showing the standing warning (WebPage, tabs and popups
#      alike) wires the manager's two lifecycle ends - a list
#      landing and a failure - to a guarded reload of its own
#      osza:threatblocked address, so the evidence re-weighs itself
#      instead of the chrome's pulse ending being the cue to
#      reload. The start is deliberately unwired (nothing the page
#      can say changes), only the plain interstitial address moves,
#      and the in-flight tail tells the user the page renews itself.
#
#   5. The padlock row: the .ui declares the update button, the
#      row's states speak the same age and failure, the button
#      starts the refresh and keeps the menu open (the per-site
#      button still closes), and the manager's own signals re-
#      render the row while the menu is open. Revoking a "proceed
#      anyway" through the per-site button now renews the evidence
#      the re-judgment is made against - updateNow() beside the
#      reload, never in test mode, the rule every update trigger
#      follows.
#
#   6. The other status surfaces keep the voice: the sidebar and
#      the self-test page name a failed refresh and speak the
#      relative age; the sidebar and the padlock menu's coverage
#      row append the movement through the public listMovement()
#      (the one composed string the evidence row rides); Preferences
#      keeps the clock time (the configuration surface).
#
#   7. The behavior mirrors: a Python mirror of describeListAge()'s
#      buckets and the staleness boundary runs the cases, and the
#      C++ is pinned to the same two-step shapes.
#
#   8. The autotests carry the feature: threatBlockListUpdateState-
#      Test pins the buckets, the staleness, the remembered
#      failure and its recovery, the stale-file path and the page
#      hrefs, and now the start signal (an attempt against an
#      invalid source is still an attempt); the page-URL test pins
#      the refresh round trip; the locationBarListUpdatePulseTest
#      drives the location bar's update-in-progress pulse end to
#      end; the extended threatBlockListDeltaTest pins the public
#      query's wordings beside the page's, and the new
#      threatBlockListMovementSurfacesTest drives the padlock
#      menu's coverage row and the sidebar's status row against
#      the one string the evidence row speaks.
#
#   9. Qt keyword discipline in the touched headers, the qrc still
#      ships the page, and the README and CHANGELOG tell the user.
#
# Usage:
#   python3 tools/security/verify_threat_block_update_ux.py
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    os.pardir, os.pardir)

MANAGER_H = os.path.join(ROOT, "src", "lib", "security", "threatblockmanager.h")
MANAGER_CPP = os.path.join(ROOT, "src", "lib", "security", "threatblockmanager.cpp")
SCHEME_CPP = os.path.join(ROOT, "src", "lib", "network", "schemehandlers", "oszaschemehandler.cpp")
WEBPAGE_H = os.path.join(ROOT, "src", "lib", "webengine", "webpage.h")
WEBPAGE_CPP = os.path.join(ROOT, "src", "lib", "webengine", "webpage.cpp")
SITEINFO_UI = os.path.join(ROOT, "src", "lib", "other", "siteinfowidget.ui")
SITEINFO_H = os.path.join(ROOT, "src", "lib", "other", "siteinfowidget.h")
SITEINFO_CPP = os.path.join(ROOT, "src", "lib", "other", "siteinfowidget.cpp")
SIDEBAR_CPP = os.path.join(ROOT, "src", "lib", "sidebar", "securitysidebar.cpp")
SELFTEST_CPP = os.path.join(ROOT, "src", "lib", "security", "selftestpage.cpp")
PREFS_CPP = os.path.join(ROOT, "src", "lib", "preferences", "preferences.cpp")
HTML_QRC = os.path.join(ROOT, "src", "lib", "data", "html.qrc")
AUTOTEST_H = os.path.join(ROOT, "autotests", "securitytoolstest.h")
AUTOTEST_CPP = os.path.join(ROOT, "autotests", "securitytoolstest.cpp")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


manager_h = read(MANAGER_H)
manager_cpp = read(MANAGER_CPP)
scheme_cpp = read(SCHEME_CPP)
webpage_h = read(WEBPAGE_H)
webpage_cpp = read(WEBPAGE_CPP)
siteinfo_ui = read(SITEINFO_UI)
siteinfo_h = read(SITEINFO_H)
siteinfo_cpp = read(SITEINFO_CPP)
sidebar_cpp = read(SIDEBAR_CPP)
selftest_cpp = read(SELFTEST_CPP)
prefs_cpp = read(PREFS_CPP)
html_qrc = read(HTML_QRC)
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
    """The source of one function, from its signature to its closing
    brace at column zero - a small structural cut so the checks below
    reason about whole functions, not lines (the same cut
    verify_threat_interstitial.py makes)."""
    start = text.find(signature)
    if start == -1:
        return None
    rest = text[start:]
    end = rest.find("\n}\n")
    return rest[:end + 3] if end > -1 else rest


interstitial = body(manager_cpp, "QString ThreatBlockManager::interstitialPage(const QUrl &blockedUrl) const")
movement_locked = body(manager_cpp, "QString ThreatBlockManager::listMovementLocked() const")
movement_pub = body(manager_cpp, "QString ThreatBlockManager::listMovement() const")
fetch = body(manager_cpp, "void ThreatBlockManager::fetchList()")
check_for_update = body(manager_cpp, "void ThreatBlockManager::checkForUpdate()")
apply_list = body(manager_cpp, "void ThreatBlockManager::applyList(const QSet<QString> &hosts, const QDateTime &when)")
apply_list_data = body(manager_cpp, "int ThreatBlockManager::applyListData(const QByteArray &data)")
load_list = body(manager_cpp, "bool ThreatBlockManager::loadList()")
update_row = body(siteinfo_cpp, "void SiteInfoWidget::updateThreatBlockState()")
update_click = body(siteinfo_cpp, "void SiteInfoWidget::threatBlockUpdateButtonClicked()")
site_click = body(siteinfo_cpp, "void SiteInfoWidget::threatBlockButtonClicked()")
sidebar_status = body(sidebar_cpp, "void SecuritySideBar::updateStatus()")
state_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockListUpdateStateTest()")
delta_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockListDeltaTest()")
movement_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockListMovementSurfacesTest()")
url_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockPageUrlTest()")
re_serve_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockInterstitialReServeTest()")

# ------------------------------------------------------------------
# 1. One staleness judgment
# ------------------------------------------------------------------
print("1. one staleness judgment, every question through it")

helper = body(manager_cpp, "bool listIsStale(const QDateTime &updated)")
check("the file-local listIsStale(updated) helper is defined in threatblockmanager.cpp",
      helper is not None)
check("the helper's judgment is the refresh interval, strictly older (the boundary is not due)",
      "!updated.isValid()" in helper and "kRefreshIntervalMs" in helper
      and "> kRefreshIntervalMs" in helper)
check("the interval constant is spoken exactly three times (its definition, the helper, the timer cadence)",
      manager_cpp.count("kRefreshIntervalMs") == 3)

check("isListStale() is declared in the header with its contract (empty or older than the interval)",
      "bool isListStale() const;" in manager_h
      and "older than the" in manager_h and "refresh interval" in manager_h)

public_stale = body(manager_cpp, "bool ThreatBlockManager::isListStale() const")
check("the public isListStale() locks and routes through the helper (empty list or old date)",
      public_stale is not None and "QMutexLocker lock(&m_mutex);" in public_stale
      and "m_blockedHosts.isEmpty() || listIsStale(m_lastUpdate)" in public_stale)

check("checkForUpdate() asks the same public judgment - the timer never refreshes a list the surfaces call fresh",
      check_for_update is not None and "if (isListStale())" in check_for_update
      and "msecsTo" not in check_for_update)

check("the interstitial reads staleness through the file-local helper under its lock (the public query would deadlock)",
      interstitial is not None and "listIsStale(m_lastUpdate)" in interstitial
      and "if (isListStale())" not in interstitial)

# ------------------------------------------------------------------
# 2. The remembered failure
# ------------------------------------------------------------------
print("2. the update-lifecycle state is real")

check("lastUpdateError() is declared in the header",
      "QString lastUpdateError() const;" in manager_h)
check("the header documents the lifecycle (empty when the last attempt succeeded, cleared by a retry)",
      "attempt succeeded" in manager_h and "cleared when a new attempt starts" in manager_h)

last_error = body(manager_cpp, "QString ThreatBlockManager::lastUpdateError() const")
check("lastUpdateError() locks the mutex like every read path",
      last_error is not None and "QMutexLocker lock(&m_mutex);" in last_error
      and "return m_lastError;" in last_error)

check("m_lastError is a mutex-guarded member beside m_updating",
      "bool m_updating;\n    QString m_lastError;" in manager_h)
check("the constructor initializes it",
      ", m_lastError()" in manager_cpp)

check("a list landing clears the failure (the state ends with the success the surfaces report)",
      apply_list is not None and "m_lastError.clear();" in apply_list)
check("a new attempt clears it too (while it runs, the surfaces report the refresh in flight)",
      fetch is not None and "m_updating = true;" in fetch and fetch.index("m_lastError.clear();") < fetch.index("m_nam"))

check("the invalid-source failure is remembered before it is announced",
      fetch is not None and 'm_lastError = tr("The blocklist source URL is not valid.");' in fetch)
check("the network failures flow into the same memory before the signal",
      fetch is not None and "m_lastError = error;" in fetch and "Q_EMIT updateFailed(error);" in fetch)
check("the three failure causes still exist (reply error, no data, no valid hosts)",
      "reply->errorString()" in fetch and "returned no data" in fetch and "did not contain any valid hosts" in fetch)
check("updateFailed is emitted from exactly the two remembering sites",
      manager_cpp.count("Q_EMIT updateFailed(") == 2)

is_updating = body(manager_cpp, "bool ThreatBlockManager::isUpdating() const")
check("isUpdating() now reads the flag under the mutex (the interstitial asks from the IO thread)",
      is_updating is not None and "QMutexLocker lock(&m_mutex);" in is_updating)
check("the in-flight flag is set and cleared under the lock",
      fetch is not None and "m_updating = true;" in fetch and "m_updating = false;" in fetch)

check("updateStarted is declared in the header with its contract (exactly when an attempt actually begins)",
      "void updateStarted();" in manager_h and "attempt actually begins" in manager_h)
check("updateStarted is emitted from exactly the one site where an attempt begins",
      manager_cpp.count("Q_EMIT updateStarted(") == 1)
check("the start is announced outside the mutex and before the source is weighed",
      fetch is not None and "Q_EMIT updateStarted();" in fetch
      and fetch.index("Q_EMIT updateStarted();") > fetch.index("m_lastError.clear();")
      and fetch.index("Q_EMIT updateStarted();") < fetch.index("url.isValid()"))
check("an attempt already running starts nothing (the declined fetch emits nothing)",
      fetch is not None and fetch.find("if (m_updating) {") > -1
      and fetch.find("if (m_updating) {") < fetch.find("Q_EMIT updateStarted();"))

# ------------------------------------------------------------------
# 3. The interstitial's list-state row
# ------------------------------------------------------------------
print("3. the interstitial's list-state row")

check("the rows are still read under one lock (one coherent snapshot, now with the lifecycle)",
      interstitial is not None and interstitial.count("QMutexLocker lock(&m_mutex);") == 1)
check("the in-flight state is read inside that lock, not through the self-locking query",
      interstitial is not None and "if (m_updating) {" in interstitial and "isUpdating()" not in interstitial)
check("the remembered failure is read inside that lock as well",
      "m_lastError" in interstitial and "lastUpdateError()" not in interstitial)

check("the age is spoken in relative terms through describeListAge()",
      "describeListAge(m_lastUpdate)" in interstitial
      and "QLocale::ShortFormat" not in interstitial)
check("the '%1 hosts, updated %2' wording keeps its shape",
      'tr("%1 hosts, updated %2"' in interstitial)
check("the not-downloaded honesty stays",
      'tr("not downloaded yet")' in interstitial)

check("the in-flight tail is translated, and tells the user the page renews itself when the update completes",
      'tr(" - updating now; this page renews itself when the update completes")' in interstitial)
check("the failure tail names the error, HTML-escaped",
      'tr(" - the last update failed: %1")' in interstitial
      and "m_lastError.toHtmlEscaped()" in interstitial)

check("the refresh link is built from the one URL shape and escaped for the href attribute",
      "refreshListPageUrl(blockedUrl).toString(QUrl::FullyEncoded)" in interstitial
      and 'refreshHref.replace(QLatin1Char(\'&\'), QSL("&amp;"));' in interstitial)
check("the link label is translated once and escaped",
      'tr("Refresh the blocklist now").toHtmlEscaped()' in interstitial)
check("the link is offered exactly when the list is due, the download failed, or nothing is in place - never while one runs",
      "wantsRefresh = true;" in interstitial
      and interstitial.count("wantsRefresh = true;") == 2)

check("the movement the last refresh brought rides the row, composed under the same one lock as the rest of the snapshot",
      interstitial is not None and "listMovementLocked();" in interstitial
      and interstitial.count("QMutexLocker lock(&m_mutex);") == 1)
check("a non-zero movement is spoken with its sign, next to the size and age it belongs to",
      'tr(" (%1 hosts since the last refresh)"' in movement_locked)
check("the sign is composed from the remembered delta, its magnitude locale-spelled",
      'm_lastDelta > 0 ? QSL("+") : QSL("-")' in movement_locked and "qAbs(m_lastDelta)" in movement_locked)
check("a refresh that moved nothing says so - that is evidence too",
      'tr(" (unchanged since the last refresh)")' in movement_locked)
check("the movement only rides a list that exists (the not-downloaded row stays bare)",
      movement_locked is not None and "m_blockedHosts.isEmpty()" in movement_locked
      and interstitial.index('tr("not downloaded yet")') < interstitial.index("listMovementLocked();"))

# ------------------------------------------------------------------
# 3b. The movement is remembered once, where the renewal lands
# ------------------------------------------------------------------
print("3b. the movement is remembered once")

check("the delta members are declared beside the lifecycle state, with their contract",
      "int m_lastDelta;" in manager_h and "bool m_deltaValid;" in manager_h
      and "movement the last landed refresh brought" in manager_h)
check("the constructor initializes them",
      ", m_lastDelta(0)" in manager_cpp and ", m_deltaValid(false)" in manager_cpp)
check("the movement is remembered in applyListData - the one path a renewal takes",
      apply_list_data is not None and "hosts.size() - previousCount" in apply_list_data
      and "m_deltaValid = previousCount > 0;" in apply_list_data)
check("it is remembered before the swap lands (in place when the listUpdated handlers run)",
      apply_list_data is not None
      and apply_list_data.index("m_lastDelta = hosts.size() - previousCount;") < apply_list_data.index("applyList(hosts, now);"))
check("the startup load from disk never claims a movement (a restart has not seen one)",
      load_list is not None and "m_lastDelta" not in load_list)
check("applyList itself stays the pure swap (the landing, not the remembering)",
      apply_list is not None and "m_lastDelta" not in apply_list)

# ------------------------------------------------------------------
# 3c. One movement, every surface that speaks the age
# ------------------------------------------------------------------
print("3c. one movement, every surface that speaks the age")

check("the movement is composed in one place, declared beside the session walk it mirrors",
      "QString listMovementLocked() const;" in manager_h)
check("the public listMovement() is declared with its contract (the parenthetical, the surfaces, never two numbers)",
      "QString listMovement() const;" in manager_h
      and "parenthetical" in manager_h and "never be spoken in two places" in manager_h)
check("the public query locks and routes through the private one (the deadlock-free split the interstitial requires)",
      movement_pub is not None and "QMutexLocker lock(&m_mutex);" in movement_pub
      and "return listMovementLocked();" in movement_pub)
check("the one composition silences exactly where no movement can be claimed (no list, or none was seen)",
      movement_locked is not None
      and "m_blockedHosts.isEmpty() || !m_deltaValid" in movement_locked)
check("the two wordings exist exactly once in the tree (composed once, appended everywhere)",
      manager_cpp.count("hosts since the last refresh") == 1
      and manager_cpp.count("(unchanged since the last refresh)") == 1)
check("the padlock coverage row and the sidebar append the composed movement, never their own wording",
      "since the last refresh" not in siteinfo_cpp and "since the last refresh" not in sidebar_cpp)
check("the padlock coverage row appends the movement next to the age it speaks",
      update_row is not None and "manager->listMovement()" in update_row
      and 'tr("%1 (list updated %2)")' in update_row)
check("the sidebar appends it next to the size and age, before the failure tail",
      sidebar_status is not None and "threatBlock->listMovement()" in sidebar_status
      and sidebar_status.index("listMovement()") < sidebar_status.index("the last update failed"))
check("the interstitial composes through the private form under its one lock (the public query would deadlock there)",
      interstitial is not None and "listMovementLocked();" in interstitial
      and "listMovement()" not in interstitial)

# ------------------------------------------------------------------
# 4. The refresh URL contract
# ------------------------------------------------------------------
print("4. the refresh URL and the scheme handler")

refresh_url = body(manager_cpp, "QUrl ThreatBlockManager::refreshListPageUrl(const QUrl &blockedUrl)")
refresh_test = body(manager_cpp, "bool ThreatBlockManager::isRefreshListPageUrl(const QUrl &pageUrl)")
check("refreshListPageUrl() is declared and defined, carrying one percent-encoded blocked URL",
      "static QUrl refreshListPageUrl(const QUrl &blockedUrl);" in manager_h
      and refresh_url is not None and "QUrl::toPercentEncoding(blockedUrl.toString())" in refresh_url
      and 'QSL("&update=1")' in refresh_url)
check("isRefreshListPageUrl() is declared and defined, mirroring the proceed recognizer's shape",
      "static bool isRefreshListPageUrl(const QUrl &pageUrl);" in manager_h
      and refresh_test is not None and 'endsWith(QSL("&update=1"))' in refresh_test)

check("the scheme handler answers the update address",
      "ThreatBlockManager::isRefreshListPageUrl(job->requestUrl())" in scheme_cpp)
handler_branch = scheme_cpp[scheme_cpp.find("isRefreshListPageUrl(job->requestUrl())"):scheme_cpp.find("isRefreshListPageUrl(job->requestUrl())") + 1200]
check("the handler starts the refresh, never in test mode (the rule every update trigger follows)",
      "updateNow();" in handler_branch and "isTestModeEnabled()" in handler_branch)
check("the handler re-serves the same interstitial rather than deciding anything about the site",
      "job->redirect(ThreatBlockManager::blockPageUrl(blocked));" in handler_branch
      and "allowForSession" not in handler_branch)
check("the proceed branch is intact and stays the only allowlist path",
      scheme_cpp.count("allowForSession(blocked.host())") == 1)
check("blockedUrlFromPageUrl still truncates at Osza's own separator (the round trip both flags ride)",
      "value.indexOf(QLatin1Char('&'))" in manager_cpp)

# ------------------------------------------------------------------
# 4b. The interstitial re-serves itself when a refresh lands
# ------------------------------------------------------------------
print("4b. the interstitial re-serves itself when a refresh lands")

webpage_ctor = webpage_cpp[:webpage_cpp.find("WebPage::~WebPage")]
re_serve = body(webpage_cpp, "void WebPage::reServeThreatInterstitial()")

check("WebPage declares the re-serve slot beside its other private slots",
      "void reServeThreatInterstitial();" in webpage_h)
check("the page wires both ends of the lifecycle (a list landing, and a failure)",
      "&ThreatBlockManager::listUpdated, this, &WebPage::reServeThreatInterstitial" in webpage_ctor
      and "&ThreatBlockManager::updateFailed, this, &WebPage::reServeThreatInterstitial" in webpage_ctor)
check("the start is deliberately unwired (it changes nothing the page can say)",
      "updateStarted" not in webpage_ctor)
check("the re-serve asks one cheap question of the page's own address (scheme and path)",
      re_serve is not None and 'current.scheme() == QL1S("osza")' in re_serve
      and 'current.path() == QL1S("threatblocked")' in re_serve)
check("the re-serve is one reload of the address the warning lives at (nothing else moves)",
      re_serve is not None
      and re_serve.count("triggerAction(QWebEnginePage::Reload);") == 1
      and "navigate" not in re_serve)
# The reload rides the Reload web action - QWebEnginePage has no
# reload() member (the interstitial's first spelling of the re-serve
# called one and broke the build), so the re-serve triggers the same
# action watchedFileChanged() already does; nothing else in the body
# moves the page.
check("the reload is the web action watchedFileChanged() already triggers",
      "triggerAction(QWebEnginePage::Reload);" in body(webpage_cpp, "void WebPage::watchedFileChanged(const QString &file)"))
check("the wiring includes the manager's header (the connection names the class)",
      '#include "threatblockmanager.h"' in webpage_cpp)

# ------------------------------------------------------------------
# 5. The padlock row
# ------------------------------------------------------------------
print("5. the padlock row")

check("the .ui declares the update button beside the per-site one",
      'name="threatBlockUpdateButton"' in siteinfo_ui and 'name="threatBlockButton"' in siteinfo_ui)
check("the handler is declared",
      "void threatBlockUpdateButtonClicked();" in siteinfo_h)

check("the row speaks the download in flight",
      'tr("The malicious-site blocklist is being <b>downloaded</b> now.")' in update_row)
check("the row names a failed download with the retry",
      'tr("The malicious-site blocklist could not be downloaded: %1")' in update_row
      and 'tr("Try the update again")' in update_row)
check("the still-loading honesty stays",
      'tr("The malicious-site blocklist is still <b>loading</b>.")' in update_row)
check("the coverage states carry the list's age in the same relative phrasing",
      'tr("%1 (list updated %2)")' in update_row
      and "ThreatBlockManager::describeListAge(manager->lastUpdate())" in update_row)
check("a refresh in flight is named next to the coverage",
      'tr("%1 The list is being refreshed now.")' in update_row)
check("a failed refresh is named next to the coverage, escaped",
      'tr("%1 The last update failed: %2")' in update_row and ".toHtmlEscaped()" in update_row)
check("the stale state offers the renewal through the same staleness judgment",
      'tr("Update the blocklist now")' in update_row and "manager->isListStale()" in update_row)
check("every state hides what it does not carry (both buttons start hidden)",
      update_row is not None and update_row.count("->hide();") >= 4)

check("the update button starts the refresh and keeps the menu open (the row witnesses the result)",
      update_click is not None and "updateNow();" in update_click
      and "updateThreatBlockState();" in update_click and "close()" not in update_click)
check("the per-site button still takes effect and closes",
      site_click is not None and "close();" in site_click)
check("revoking a \"proceed anyway\" renews the evidence it re-weighs with (never in test mode)",
      site_click is not None and "removeSessionAllow(url.host());" in site_click
      and "updateNow();" in site_click and "isTestModeEnabled()" in site_click
      and site_click.index("updateNow();") > site_click.index("removeSessionAllow(url.host());"))

ctor = siteinfo_cpp[:siteinfo_cpp.find("SiteInfoWidget::~SiteInfoWidget")]
check("the manager's own signals re-render the row while the menu is open",
      "&ThreatBlockManager::listUpdated, this, &SiteInfoWidget::updateThreatBlockState" in ctor
      and "&ThreatBlockManager::updateFailed, this, &SiteInfoWidget::updateThreatBlockState" in ctor)

# ------------------------------------------------------------------
# 6. The other status surfaces keep the voice
# ------------------------------------------------------------------
print("6. one voice across the surfaces")

check("the sidebar names a failed download",
      "lastUpdateError()" in sidebar_cpp and "The blocklist download failed: %1" in sidebar_cpp)
check("the sidebar appends the failure to the list it left behind",
      "the last update failed: %1" in sidebar_cpp)
check("the sidebar speaks the relative age (its row refreshes every second)",
      "ThreatBlockManager::describeListAge(threatBlock->lastUpdate())" in sidebar_cpp)
check("the self-test page names the failure and the age the same way",
      "lastUpdateError()" in selftest_cpp and "describeListAge" in selftest_cpp)
check("the self-test detail is not HTML-escaped (the page inserts it through textContent)",
      "lastUpdateError().toHtmlEscaped()" not in selftest_cpp)
check("Preferences keeps the clock time (the configuration surface, where the source is set)",
      "QLocale::ShortFormat" in prefs_cpp)

# ------------------------------------------------------------------
# 7. The behavior mirrors
# ------------------------------------------------------------------
print("7. the behavior, simulated")


def describe_list_age(elapsed_s):
    """The mirror of describeListAge(): the bucket word, clamped at
    zero, minute before hour before day."""
    elapsed_s = max(0, elapsed_s)
    if elapsed_s < 60:
        return "less than a minute ago"
    minutes = elapsed_s // 60
    if minutes < 60:
        return "minute"
    hours = minutes // 60
    if hours < 24:
        return "hour"
    return "day"


cases = [
    # (label, seconds since the list landed, expected bucket)
    ("just now", 0, "less than a minute ago"),
    ("the last minute", 59, "less than a minute ago"),
    ("the first minute boundary", 60, "minute"),
    ("the last minute of an hour", 3599, "minute"),
    ("the first hour boundary", 3600, "hour"),
    ("the last hour of a day", 86399, "hour"),
    ("the first day boundary", 86400, "day"),
    ("a long offline stretch", 45 * 86400, "day"),
    ("a clock skew into the future clamps to just now", -300, "less than a minute ago"),
]
for label, seconds, expected in cases:
    check("%s -> %r" % (label, expected), describe_list_age(seconds) == expected)

check("the C++ age is clamped before the buckets",
      "qMax<qint64>(0, since.secsTo(QDateTime::currentDateTimeUtc()))" in manager_cpp)
check("the C++ buckets are the mirror's (< 60, elapsed / 60, minutes < 60, minutes / 60, hours < 24, hours / 24)",
      "elapsed < 60" in manager_cpp and "elapsed / 60" in manager_cpp
      and "minutes < 60" in manager_cpp and "minutes / 60" in manager_cpp
      and "hours < 24" in manager_cpp and "hours / 24" in manager_cpp)

REFRESH_MS = 12 * 60 * 60 * 1000


def is_list_stale(has_hosts, age_ms):
    """The mirror of isListStale(): no list, no timestamp, or older
    than the refresh interval (the boundary itself is not due)."""
    return (not has_hosts) or (age_ms is None) or age_ms > REFRESH_MS


for label, has_hosts, age_ms, expected in (
        ("an empty list is due", False, 0, True),
        ("a list without a timestamp is due", True, None, True),
        ("a fresh list is not due", True, 60 * 1000, False),
        ("exactly the interval is not due (strictly older only)", True, REFRESH_MS, False),
        ("one millisecond past the interval is due", True, REFRESH_MS + 1, True),
        ("days old is due", True, 3 * REFRESH_MS, True)):
    check("%s -> %r" % (label, expected), is_list_stale(has_hosts, age_ms) == expected)


def describe_delta(previous, new):
    """The mirror of the row's movement: None when there was no list
    to move from (the first download, a restart's disk load),
    'unchanged' when the refresh moved nothing, else the signed
    count - the exact judgment m_deltaValid and m_lastDelta carry."""
    if previous == 0:
        return None
    delta = new - previous
    if delta == 0:
        return "unchanged"
    return ("+" if delta > 0 else "-") + str(abs(delta))


for label, previous, new, expected in (
        ("the first list ever claims no movement", 0, 124000, None),
        ("a growing list speaks its growth", 122796, 124000, "+1204"),
        ("a shrinking list speaks its loss", 124000, 123970, "-30"),
        ("a refresh that moved nothing says so", 124000, 124000, "unchanged"),
        ("a list emptied entirely speaks the whole loss", 124000, 0, "-124000")):
    check("%s -> %r" % (label, expected), describe_delta(previous, new) == expected)

check("the C++ silences the movement exactly when the previous list was empty",
      "m_deltaValid = previousCount > 0;" in manager_cpp)
check("the C++ sign is the mirror's (a composed '+' or '-', the magnitude absolute)",
      'm_lastDelta > 0 ? QSL("+") : QSL("-")' in manager_cpp and "qAbs(m_lastDelta)" in manager_cpp)
check("the zero movement has its own wording, not a signed zero",
      'tr(" (unchanged since the last refresh)")' in manager_cpp
      and "+0" not in manager_cpp)

# ------------------------------------------------------------------
# 8. The autotests carry the feature
# ------------------------------------------------------------------
print("8. autotests")

check("the update-state test is declared and defined",
      "void threatBlockListUpdateStateTest();" in autotest_h
      and "void SecurityToolsTest::threatBlockListUpdateStateTest()" in autotest_cpp)

check("the test pins the age buckets and the fallbacks",
      'QSL("less than a minute ago")' in state_test and 'QSL("unknown date")' in state_test
      and 'QSL("minute")' in state_test and 'QSL("hour")' in state_test and 'QSL("day")' in state_test)
check("the test pins freshness and the remembered failure through an invalid source",
      "isListStale()" in state_test and "ftp://blocklists.example/list.txt" in state_test
      and "failedSpy" in state_test and "lastUpdateError().isEmpty()" in state_test)
check("the test pins the interstitial's failure state and its action",
      'QSL("the last update failed")' in state_test and 'QSL("Refresh the blocklist now")' in state_test)
check("the test pins the page's refresh href (one percent-encoded value, the escaped separator)",
      '"&amp;update=1"' in state_test)
check("the test pins the stale-file path and the recovery",
      "# updated: 2020-01-01T00:00:00" in state_test
      and "staleManager.isListStale()" in state_test)
check("the test restores the state it touched",
      state_test.rstrip().endswith("}")
      and state_test.rstrip().endswith("manager->loadSettings();\n}"))
check("the page-URL test pins the refresh round trip and the flags' disjointness",
      "refreshListPageUrl(url)" in url_test and "isRefreshListPageUrl(refresh)" in url_test
      and "isProceedPageUrl(refresh)" in url_test)
check("the lifecycle test pins the start signal (an invalid source is still an attempt)",
      "startedSpy" in state_test and "QCOMPARE(startedSpy.count(), 1)" in state_test)
check("the pulse widget test is declared and defined",
      "void locationBarListUpdatePulseTest();" in autotest_h
      and "void SecurityToolsTest::locationBarListUpdatePulseTest()" in autotest_cpp)

check("the delta test is declared and defined",
      "void threatBlockListDeltaTest();" in autotest_h
      and "void SecurityToolsTest::threatBlockListDeltaTest()" in autotest_cpp)
check("the delta test pins the growth, the loss and the no-change wordings",
      'QSL("+2 host")' in delta_test and 'QSL("-2 host")' in delta_test
      and 'QSL("(unchanged since the last refresh)")' in delta_test
      and 'QSL("hosts since the last refresh")' in delta_test)
check("the delta test pins the public query's own wordings beside the page's",
      'QSL("+2 hosts since the last refresh")' in delta_test
      and 'QSL("-2 hosts since the last refresh")' in delta_test
      and 'QCOMPARE(manager->listMovement(), QSL(" (unchanged since the last refresh)"))' in delta_test
      and 'QCOMPARE(manager->listMovement(), QString())' in delta_test)
check("the delta test pins the silences (a first list, and the same list reloaded from disk after a restart)",
      delta_test.count('QSL("since the last refresh")') == 2
      and "diskManager" in delta_test and "diskManager.loadSettings();" in delta_test
      and "diskManager.listMovement().isEmpty()" in delta_test)
check("the delta test drives the movement through the renewal's own path",
      delta_test.count("applyListData(") >= 5)
check("the movement-surfaces test is declared and defined",
      "void threatBlockListMovementSurfacesTest();" in autotest_h
      and "void SecurityToolsTest::threatBlockListMovementSurfacesTest()" in autotest_cpp)
check("the movement-surfaces test pins the padlock coverage row and the sidebar status row against the one string",
      'QSL("threatBlockLabel")' in movement_test and 'QSL("threatBlockState")' in movement_test
      and "manager->listMovement()" in movement_test
      and 'QSL("(list updated ")' in movement_test
      and 'QSL("hosts, updated ")' in movement_test)
check("the movement-surfaces test pins the evidence row speaking the very same string",
      "interstitialPage" in movement_test
      and "warning.contains(movement)" in movement_test)
check("the movement-surfaces test pins the shared silence after a restart",
      "diskManager" in movement_test and "listMovement().isEmpty()" in movement_test)

check("the re-serve test is declared and defined",
      "void threatBlockInterstitialReServeTest();" in autotest_h
      and "void SecurityToolsTest::threatBlockInterstitialReServeTest()" in autotest_cpp)
check("the re-serve test drives the real WebEngine (the warning stands on a real page)",
      re_serve_test is not None and "WebPage page;" in re_serve_test
      and "loadFinishedSpy" in re_serve_test
      and 'QSL("http://blocked-reserve.example/payload")' in re_serve_test)
check("the re-serve test pins the movement arriving on the re-served page",
      'QSL("+2 hosts since the last refresh")' in re_serve_test
      and "bodyText()" in re_serve_test)
check("the re-serve test pins the re-weigh (a list without the host answers honestly)",
      'QSL("not on the current blocklist")' in re_serve_test)
check("the re-serve test pins the guard (a page that is not the warning never moves)",
      "quietSpy" in re_serve_test and "QCOMPARE(quietSpy.count(), 0)" in re_serve_test)
check("the re-serve test pins the failure's re-serve with its retry",
      'QSL("the last update failed")' in re_serve_test
      and "updateNow();" in re_serve_test
      and 'QSL("Refresh the blocklist now")' in re_serve_test
      and 'QSL("updating now")' in re_serve_test)

# ------------------------------------------------------------------
# 9. Build discipline and docs
# ------------------------------------------------------------------
print("9. build discipline, docs")

for name, text in (("threatblockmanager.h", manager_h), ("siteinfowidget.h", siteinfo_h),
                   ("securitytoolstest.h", autotest_h)):
    check("%s keeps Qt keyword discipline (no bare slots: or signals:)" % name,
          not re.search(r"^\s*(slots|signals):", text, re.M))
check("the manager's signal block keeps the Q_SIGNALS spelling",
      "Q_SIGNALS:" in manager_h)
check("html.qrc still ships threatblocked.html",
      "threatblocked.html" in html_qrc)

readme_flat = " ".join(readme.split())
check("the README tells the user the evidence carries its freshness and a renewal",
      "Refresh the blocklist now" in readme_flat and "updated" in readme_flat)
check("the README tells the user the evidence speaks its movement",
      "since the last refresh" in readme_flat)
check("the README names the surfaces that speak the movement (the coverage row and the sidebar join the evidence)",
      "security sidebar's status row" in readme_flat
      and "padlock menu's threat-block row" in readme_flat)
check("the CHANGELOG has a Security tools (20) entry for the update UX",
      "Security tools (20)" in changelog and "refresh" in changelog.lower())
check("the CHANGELOG has a Security tools (22) entry for the movement on the evidence rows",
      "Security tools (22)" in changelog and "since the last refresh" in changelog)
check("the CHANGELOG has a Security tools (23) entry for the movement joining the coverage row and the sidebar",
      "Security tools (23)" in changelog and "coverage row" in changelog)
check("the CHANGELOG has a Security tools (24) entry for the interstitial re-serving itself",
      "Security tools (24)" in changelog and "re-serve" in changelog)
check("the README tells the user the warning page renews itself when a refresh lands",
      "renews itself" in readme_flat)

print()
if failures:
    print("FAILED: %d of %d checks" % (failures, checks))
    raise SystemExit(1)
print("OK: all %d checks passed" % checks)
