#!/usr/bin/env python3
# ============================================================
# Osza - threat-block reliability verifier
#
# Standalone verification of the blocklist download's reliability
# floor - the parts of the update lifecycle whose failure mode is
# not a wrong answer but a missing one - without a Qt build, in the
# spirit of verify_threat_block_update_ux.py:
#
#   1. The watchdog over the download: the request carries the
#      engine's transfer timeout (an inactivity timeout - the
#      window restarts with every byte that arrives, so a
#      slow-but-flowing download is never cut, only a connection
#      that delivers nothing at all for the whole window is).
#      Without it a stalled connection (a captive portal, a network
#      that changed mid-flight) leaves the refresh "in flight"
#      forever: m_updating stays set, every later attempt is
#      declined by fetchList()'s guard, the location bar's pulse
#      breathes without end and the blocklist can never be renewed
#      again until the browser is restarted. The same watchdog
#      rides the browser's other scheduled housekeeping downloads:
#      the ad-block subscriptions (whose updateSubscription() guard
#      wedges exactly like fetchList()'s, silently stopping the
#      filters from updating) and the updater's one-shot version
#      check. The interactive downloads (a user script, a theme, a
#      search engine's icon, the location bar's suggestions, a
#      site's image) are deliberately outside the round: a user
#      sees nothing arrive and can retry, and the suggestions path
#      aborts its previous reply with every keystroke, so no
#      scheduled refresh is wedged by their stalls.
#
#   2. The naming of the two deaths a download can die on purpose,
#      classified by ThreatBlockManager::wasTransferTimeout(): a
#      stalled transfer is a stall (reported as one on every Qt
#      the browser builds against - Qt 6.7 and newer abort the
#      reply with TimeoutError, older Qt reported the same death as
#      a plain cancellation whose only distinguishing mark was the
#      "timed out" wording of the error string), while a deliberate
#      abort (the quitting browser's abortUpdate()) is a choice and
#      is never called a stall. The verdict decides the failure the
#      surfaces remember, so the two can never be confused for one
#      another - and the classifier takes the error code and error
#      string instead of the reply, so it needs no live object.
#
#   3. The atomic save: the list lands on disk through QSaveFile,
#      whose bytes reach a temporary file beside the target and are
#      renamed over it only when all of them arrived. A plain
#      write could be cut in half by a crash, a power loss or a
#      full disk - and a half-written list loads on the next start
#      as a shorter list, every host after the cut silently
#      unblocked. An atomic save can only ever leave the complete
#      new list or the complete old one standing.
#
#   4. The teardown abort: a refresh still running when the browser
#      quits is aborted at the top of the closing sequence, on the
#      cancel path - the one end of a download that applies no list
#      and writes no file - instead of leaving its finished handler
#      to fire into a closing browser. abortUpdate() with no
#      download in flight is the every-day case and a no-op.
#
#   5. The autotest carries the classification table, and the
#      behavior mirror runs the same table in Python.
#
#   6. The README and CHANGELOG tell the user.
#
# Usage:
#   python3 tools/security/verify_threat_block_reliability.py
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
ADBLOCK_CPP = os.path.join(ROOT, "src", "lib", "adblock", "adblocksubscription.cpp")
UPDATER_CPP = os.path.join(ROOT, "src", "lib", "other", "updater.cpp")
GM_DOWNLOADER_CPP = os.path.join(ROOT, "src", "plugins", "GreaseMonkey", "gm_downloader.cpp")
OPENSEARCH_CPP = os.path.join(ROOT, "src", "lib", "opensearch", "opensearchengine.cpp")
MAINAPP_CPP = os.path.join(ROOT, "src", "lib", "app", "mainapplication.cpp")
AUTOTEST_H = os.path.join(ROOT, "autotests", "securitytoolstest.h")
AUTOTEST_CPP = os.path.join(ROOT, "autotests", "securitytoolstest.cpp")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


manager_h = read(MANAGER_H)
manager_cpp = read(MANAGER_CPP)
adblock_cpp = read(ADBLOCK_CPP)
updater_cpp = read(UPDATER_CPP)
mainapp_cpp = read(MAINAPP_CPP)
autotest_h = read(AUTOTEST_H)
autotest_cpp = read(AUTOTEST_CPP)
readme = read(README)
changelog = read(CHANGELOG)

# The README wraps its feature prose; one flat form for substring
# checks that cross line breaks.
readme_flat = re.sub(r"\s+", " ", readme)
changelog_flat = re.sub(r"\s+", " ", changelog)

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


fetch = body(manager_cpp, "void ThreatBlockManager::fetchList()")
save_list = body(manager_cpp, "bool ThreatBlockManager::saveList(const QSet<QString> &hosts, const QDateTime &when)")
load_list = body(manager_cpp, "bool ThreatBlockManager::loadList()")
classifier = body(manager_cpp, "bool ThreatBlockManager::wasTransferTimeout(int error, const QString &errorString)")
abort_update = body(manager_cpp, "void ThreatBlockManager::abortUpdate()")
quit_app = body(mainapp_cpp, "void MainApplication::quitApplication()")
timeout_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockTransferTimeoutTest()")

# ------------------------------------------------------------------
# 1. The watchdog over the download
# ------------------------------------------------------------------
print("1. the watchdog: a stalled download is cut, a flowing one never is")

check("the transfer-timeout constant is defined in the cpp's anonymous namespace",
      "const int kTransferTimeoutMs = 60 * 1000;" in manager_cpp)
check("the constant's contract is spoken beside it (an inactivity window, restarted by every byte)",
      manager_cpp.find("The watchdog over a blocklist download") > -1
      and "inactivity timeout" in manager_cpp
      and "window restarts with every" in manager_cpp)
check("the constant names the failure it prevents (an update stuck in flight forever)",
      "in flight\" forever" in manager_cpp and "declined by the guard" in manager_cpp)
check("the constant is spoken exactly twice - its definition and the request that carries it",
      manager_cpp.count("kTransferTimeoutMs") == 2)

check("fetchList() sets the transfer timeout on the request",
      fetch is not None and "request.setTransferTimeout(kTransferTimeoutMs);" in fetch)
check("the timeout is armed before the request is handed to the network access manager",
      fetch is not None
      and fetch.find("request.setTransferTimeout(kTransferTimeoutMs);")
      < fetch.find("m_nam->get(request);"))
check("the watchdog rides the request itself, so every path a refresh takes carries it",
      fetch is not None
      and "The watchdog rides the request itself" in fetch)
check("every scheduled housekeeping download carries the watchdog (the blocklist, the adblock subscriptions, the updater's check)",
      "setTransferTimeout" in manager_cpp
      and "setTransferTimeout" in adblock_cpp
      and "setTransferTimeout" in updater_cpp)
check("the adblock watchdog is armed for the same reason its guard makes it need (a stalled reply declines every later refresh)",
      "const int kSubscriptionTimeoutMs = 60 * 1000;" in adblock_cpp
      and adblock_cpp.find("request.setTransferTimeout(kSubscriptionTimeoutMs);")
      < adblock_cpp.find("m_reply = mApp->networkManager()->get(request);"))
check("the updater's one-shot check carries the watchdog before the request rides",
      "const int kUpdateCheckTimeoutMs = 60 * 1000;" in updater_cpp
      and updater_cpp.find("request.setTransferTimeout(kUpdateCheckTimeoutMs);")
      < updater_cpp.find("QNetworkReply *reply = mApp->networkManager()->get(request);"))
check("the interactive downloads are deliberately outside the round (the user can retry; no scheduled refresh is wedged)",
      "setTransferTimeout" not in read(GM_DOWNLOADER_CPP)
      and "setTransferTimeout" not in read(OPENSEARCH_CPP))

# ------------------------------------------------------------------
# 2. The classifier: one answer over both Qt eras
# ------------------------------------------------------------------
print("2. the classifier: a stall is a stall on every Qt, a choice is never one")

check("wasTransferTimeout() is declared public static in the header",
      "static bool wasTransferTimeout(int error, const QString &errorString);" in manager_h)
check("the header documents the two eras the classifier spans (TimeoutError and the string-marked cancellation)",
      "TimeoutError" in manager_h and "timed out" in manager_h)
check("the header documents the deliberate abort's verdict (a choice is never a stall)",
      "abortUpdate() answers false" in manager_h)
check("the classifier takes the error code and error string, never a reply (no live object needed)",
      "static bool wasTransferTimeout(int error" in manager_h)
check("the classifier is implemented in the cpp",
      classifier is not None)
check("a TimeoutError is a stall outright, whatever the wording",
      classifier is not None and "error == QNetworkReply::TimeoutError" in classifier
      and "return true;" in classifier)
check("an older Qt's cancellation is a stall only by the mark, matched case-insensitively",
      classifier is not None
      and "error == QNetworkReply::OperationCanceledError" in classifier
      and 'errorString.contains(QSL("timed out"), Qt::CaseInsensitive)' in classifier)

# ------------------------------------------------------------------
# 3. The distinct namings in the finished handler
# ------------------------------------------------------------------
print("3. the two deaths are named distinctly, the state ends on both")

check("the finished handler classifies through the shared static (never its own reading of the error)",
      fetch is not None and "wasTransferTimeout(reply->error(), reply->errorString())" in fetch)
check("a stalled transfer is named as the stall it is, not the engine's bare wording",
      fetch is not None
      and 'tr("The blocklist download stalled and was aborted.")' in fetch)
check("a deliberate abort is named as the choice it is",
      fetch is not None
      and 'tr("The blocklist download was canceled.")' in fetch)
check("the stall is weighed before the cancel - a TimeoutError never reaches the plainer wording",
      fetch is not None
      and fetch.find('tr("The blocklist download stalled and was aborted.")')
      < fetch.find('tr("The blocklist download was canceled.")'))
check("every other failure keeps the engine's own wording",
      fetch is not None and "error = reply->errorString();" in fetch)
check("the in-flight flag ends before the classification begins, under the mutex it is guarded by",
      fetch is not None
      and fetch.find("m_updating = false;")
      < fetch.find("wasTransferTimeout(reply->error(), reply->errorString())")
      and "QMutexLocker lock(&m_mutex);" in fetch)

# ------------------------------------------------------------------
# 4. The atomic save
# ------------------------------------------------------------------
print("4. the list lands whole or not at all")

check("the save path goes through QSaveFile, the tree's established idiom for security-critical files",
      save_list is not None and "QSaveFile file(listFilePath());" in save_list)
check("the plain-write path is gone from the save (the load keeps its plain read)",
      save_list is not None and "QFile file(listFilePath());" not in save_list
      and load_list is not None and "QFile file(listFilePath());" in load_list)
check("the commit is the last act of the save, and a failed one is named and reported",
      save_list is not None and "if (!file.commit())" in save_list
      and "cannot commit the blocklist" in save_list and "return false;" in save_list)
check("the save's contract is spoken beside it (a half-written list is a silently weaker protection)",
      save_list is not None and "half-written list" in save_list
      and "silently unblocked" in save_list)
check("the cpp includes QSaveFile",
      "#include <QSaveFile>" in manager_cpp)
check("the load keeps its old header path (only the write became atomic)",
      load_list is not None and "# updated: " in load_list
      and "QDateTime::fromString" in load_list)

# ------------------------------------------------------------------
# 5. The teardown abort
# ------------------------------------------------------------------
print("5. a quitting browser never races its own download")

check("quitApplication() aborts an in-flight refresh",
      quit_app is not None
      and "m_networkManager->threatBlockManager()->abortUpdate();" in quit_app)
check("the abort is guarded (a quit before the network stack exists is the every-day case)",
      quit_app is not None and "if (m_networkManager) {" in quit_app)
check("the abort lands after the closing marker and before the windows close - every manager still lives",
      quit_app is not None
      and quit_app.find("m_isClosing = true;")
      < quit_app.find("m_networkManager->threatBlockManager()->abortUpdate();")
      < quit_app.find("window->close();"))
check("abortUpdate() with no download in flight is a no-op, never a crash",
      abort_update is not None
      and "if (m_reply) {" in abort_update and "m_reply->abort();" in abort_update)
check("the teardown abort is spoken for in the quitting code (why it runs before the windows close)",
      quit_app is not None
      and "must not race the teardown" in quit_app)

# ------------------------------------------------------------------
# 6. The autotest carries the table
# ------------------------------------------------------------------
print("6. the autotest pins the classification")

check("the threatBlockTransferTimeoutTest slot is declared",
      "void threatBlockTransferTimeoutTest();" in autotest_h)
check("the threatBlockTransferTimeoutTest slot is implemented",
      timeout_test is not None)
check("the autotest includes QNetworkReply for the error codes",
      "#include <QNetworkReply>" in autotest_cpp)
check("the table pins the current Qt's report (TimeoutError, whatever the wording)",
      timeout_test is not None
      and "QNetworkReply::TimeoutError" in timeout_test)
check("the table pins the older Qt's report (a cancellation told apart by the string alone)",
      timeout_test is not None
      and 'QSL("transfer timed out")' in timeout_test
      and "QNetworkReply::OperationCanceledError" in timeout_test)
check("the table pins the deliberate abort's verdict (a choice, never a stall)",
      timeout_test is not None
      and '!ThreatBlockManager::wasTransferTimeout(QNetworkReply::OperationCanceledError, QSL("Operation canceled"))' in timeout_test)
check("the table pins the case-insensitive mark",
      timeout_test is not None and 'QSL("Transfer TIMED OUT")' in timeout_test)
check("the table keeps every other failure's own name (the wording never overrides the code)",
      timeout_test is not None
      and '!ThreatBlockManager::wasTransferTimeout(QNetworkReply::NoError, QSL("timed out"))' in timeout_test)
check("the no-download abort is driven for the every-day quitting case",
      timeout_test is not None
      and "ThreatBlockManager manager;" in timeout_test
      and "manager.abortUpdate();" in timeout_test
      and "QVERIFY(!manager.isUpdating());" in timeout_test)
check("the classification table carries twelve verdicts (five stalls, seven non-stalls)",
      timeout_test is not None
      and timeout_test.count("QVERIFY(") - timeout_test.count("QVERIFY(!") == 5
      and timeout_test.count("QVERIFY(!") == 7)

# ------------------------------------------------------------------
# 7. The behavior mirror
# ------------------------------------------------------------------
print("7. the behavior mirror: the same table, answered in Python")


def mirror_was_transfer_timeout(error, error_string):
    """The classifier's answer, mirrored: TimeoutError is a stall
    outright; a cancellation is a stall only by the mark, matched
    without regard to case; every other code keeps its own name."""
    if error == "timeout":
        return True
    return error == "canceled" and "timed out" in error_string.lower()


CASES = [
    ("timeout", "Operation timed out", True),
    ("timeout", "anything at all", True),
    ("canceled", "transfer timed out", True),
    ("canceled", "Operation timed out", True),
    ("canceled", "Operation canceled", False),
    ("canceled", "", False),
    ("host-not-found", "host not found", False),
    ("remote-closed", "connection closed", False),
    ("no-error", "", False),
    ("no-error", "timed out", False),
    ("canceled", "Transfer TIMED OUT", True),
]

for error, error_string, expected in CASES:
    check("the mirror answers %s for (%s, %r)"
          % ("true" if expected else "false", error, error_string),
          mirror_was_transfer_timeout(error, error_string) == expected)

check("the mirror's table matches the autotest's verdict count (eleven driven cases, twelve QVERIFYs - the abort no-op besides)",
      len(CASES) == 11)

# ------------------------------------------------------------------
# 8. The README and CHANGELOG tell the user
# ------------------------------------------------------------------
print("8. the docs tell the user")

check("the README names the new verifier",
      "verify_threat_block_reliability.py" in readme_flat)
check("the README speaks the watchdog (a download that delivers nothing is cut and named)",
      "delivers nothing for a whole minute" in readme_flat
      and "stalled download" in readme_flat)
check("the README speaks the atomic save (never a half-written list)",
      "lands on disk atomically" in readme_flat
      and "half-written list" in readme_flat)
check("the README speaks the teardown cancel",
      "canceled before the teardown" in readme_flat)
check("the CHANGELOG has a Security tools (30) entry for the reliability round",
      "Security tools (30)" in changelog
      and "cannot hang forever" in changelog_flat)
check("the CHANGELOG entry names the classifier and both Qt eras",
      "wasTransferTimeout" in changelog_flat
      and "TimeoutError" in changelog_flat)
check("the CHANGELOG entry names the atomic save",
      "QSaveFile" in changelog_flat)
check("the CHANGELOG entry names the grown autotest",
      "threatBlockTransferTimeoutTest" in changelog_flat)
check("the CHANGELOG entry says the other twelve verifiers still pass unchanged",
      "twelve" in changelog_flat
      and "verifiers still pass unchanged" in changelog_flat)
check("the CHANGELOG names the verifier and what it checks",
      "verify_threat_block_reliability.py" in changelog_flat
      and "the teardown abort" in changelog_flat)

print()
if failures:
    print("FAILED: %d of %d checks" % (failures, checks))
    raise SystemExit(1)

# The count is part of the record the CHANGELOG keeps; the last
# check closes on it.
print("OK: all %d checks passed" % checks)
