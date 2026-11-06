#!/usr/bin/env python3
# ============================================================
# Osza - threat-block interstitial verifier
#
# Standalone verification of the threat-block interstitial's "why
# is this site flagged?" disclosure (the details that name the
# matching blocklist entry, the list's source and its size and last
# update), without a Qt build, in the spirit of
# verify_settings_diff_page.py and verify_locationbar_badge.py:
#
#   1. One matching walk: the file-local matchingEntry() answers
#      for every question of the shape "which entry of this set
#      covers this host" - isHostBlocked, shouldBlock,
#      isSessionAllowedLocked and the new matchingListEntry() all
#      route through it, so the entry the interstitial shows can
#      never disagree with the decision it explains.
#
#   2. The public query is what it claims: pure (neither the
#      enabled switch nor a session allow changes it), declared in
#      the header, thread safe, and NOT called from
#      interstitialPage() (which already holds the mutex - calling
#      the public self-locking query there would deadlock).
#
#   3. The placeholder contract: every %TOKEN% the interstitial
#      HTML carries is substituted by interstitialPage() or
#      QzTools::applyDirectionToPage(), and every token the C++
#      side replaces exists in the page - the retired
#      %DETAILS-HEADING% is gone from both sides, and the new
#      tokens (%WHY-LINK%, %MATCH-ENTRY%, %MATCH-INFO%,
#      %SOURCE-LABEL%, %SOURCE-INFO%) are present on both.
#
#   4. The disclosure is a native <details>: no script on the
#      toggle (the page's only script stays goBack), the summary is
#      not a link, it starts collapsed, the built-in marker is
#      suppressed both ways (list-style and ::-webkit-details-marker)
#      and the chevron is aria-hidden and rotates on open.
#
#   5. The evidence rows are honest and escaped: the four rows
#      (blocked URL, matching entry, source, list state) are built
#      under one lock - one coherent snapshot of the blocklist, not
#      the decision of one refresh mixed with the entries of
#      another - every interpolated value is HTML-escaped, the
#      source falls back to the default when unconfigured, and the
#      page answers "not on the current blocklist" / "unknown (the
#      blocklist is not loaded)" instead of inventing an entry.
#
#   6. The matching algorithm behaves: a Python mirror of the
#      shared walk runs the autotest's cases (exact, normalized,
#      closest ancestor, exact-beats-ancestor, suffix spoof, empty
#      host, empty list), and the C++ helper is pinned to the same
#      two-step shape (the host itself first, then the parent walk
#      with the dot boundary).
#
#   7. The autotests carry the feature: the matching-entry test and
#      the extended interstitial test are declared and defined,
#      with the disclosure, the entry tails, the honest states, the
#      escaped hostile source and the source save/restore.
#
#   8. Qt keyword discipline in the touched header (Q_SIGNALS /
#      Q_SLOTS, never bare signals:/slots: - the tree builds with
#      -DQT_NO_KEYWORDS) and the qrc still ships the page.
#
#   9. The README and the CHANGELOG tell the user about it.
#
# Usage:
#   python3 tools/security/verify_threat_interstitial.py
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
INTERSTITIAL_HTML = os.path.join(ROOT, "src", "lib", "data", "html", "threatblocked.html")
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
interstitial_html = read(INTERSTITIAL_HTML)
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
    reason about whole functions, not lines. (The codebase's Allman
    style keeps every inner brace indented, so the first \n} at
    column zero reliably ends the function; the cut also stops at a
    namespace-closing brace, which is fine for every body asked
    for here.)"""
    start = text.find(signature)
    if start == -1:
        return None
    rest = text[start:]
    end = rest.find("\n}\n")
    return rest[:end + 3] if end > -1 else rest


interstitial = body(manager_cpp, "QString ThreatBlockManager::interstitialPage(const QUrl &blockedUrl) const")

# ------------------------------------------------------------------
# 1. One matching walk
# ------------------------------------------------------------------
print("1. one matching walk, every question through it")

helper = body(manager_cpp, "QString matchingEntry(const QString &host, const QSet<QString> &set)")
check("the file-local matchingEntry(host, set) helper is defined in threatblockmanager.cpp",
      helper is not None)
check("the helper answers for the host itself first, then the parent walk",
      "set.contains(host)" in helper and "return host;" in helper)
check("the helper's parent walk keeps the dot boundary",
      "name.indexOf(QLatin1Char('.'))" in helper and "name.mid(dot + 1)" in helper)
check("the helper never touches a mutex (the caller holds it)",
      "QMutexLocker" not in helper)

for signature, label in (
        ("bool ThreatBlockManager::isHostBlocked(const QString &host) const",
         "isHostBlocked routes through the shared walk"),
        ("QString ThreatBlockManager::matchingListEntry(const QString &host) const",
         "matchingListEntry routes through the shared walk"),
        ("bool ThreatBlockManager::shouldBlock(const QString &host) const",
         "shouldBlock routes through the shared walk"),
        ("bool ThreatBlockManager::isSessionAllowedLocked(const QString &host) const",
         "isSessionAllowedLocked routes through the shared walk")):
    fn = body(manager_cpp, signature)
    check(label, fn is not None and "matchingEntry(" in fn)

# The only other parent walk in the file is removeSessionAllow,
# which is a different operation (it removes every covering
# ancestor, not just the match) - it must stay, with its comment.
remove = body(manager_cpp, "void ThreatBlockManager::removeSessionAllow(const QString &host)")
check("removeSessionAllow keeps its own whole-chain removal walk (a different operation)",
      remove is not None and "m_sessionAllowed.remove(parent);" in remove)

# No query keeps an inline copy of the walk (the helper walks with
# "name", removeSessionAllow's chain with "parent").
walks = manager_cpp.count("indexOf(QLatin1Char('.'))")
check("the parent walk exists exactly twice (the helper, removeSessionAllow's chain)",
      walks == 2)

# ------------------------------------------------------------------
# 2. The public query is what it claims
# ------------------------------------------------------------------
print("2. the public matchingListEntry query")

check("matchingListEntry is declared in the header",
      "QString matchingListEntry(const QString &host) const;" in manager_h)
check("the header documents the purity (neither switch nor allow changes it)",
      "pure list query" in manager_h)

query = body(manager_cpp, "QString ThreatBlockManager::matchingListEntry(const QString &host) const")
check("the query locks the mutex (thread safe, like every read path)",
      "QMutexLocker lock(&m_mutex);" in query)
check("the query normalizes the host before the lookup",
      "normalizeHost(host)" in query)

check("interstitialPage reads the entry under its own lock (the file-local helper, not the self-locking public query)",
      interstitial is not None and "matchingEntry(name, m_blockedHosts)" in interstitial
      and "matchingListEntry(" not in interstitial)

# ------------------------------------------------------------------
# 3. The placeholder contract
# ------------------------------------------------------------------
print("3. the placeholder contract, both sides agree")

html_tokens = set(re.findall(r"%([A-Z0-9-]+)%", interstitial_html))
cpp_tokens = set(re.findall(r'QLatin1String\("%([A-Z0-9-]+)%"\)', interstitial))

check("every HTML token is substituted by interstitialPage() (DIRECTION by applyDirectionToPage)",
      html_tokens - cpp_tokens - {"DIRECTION"} == set())
check("every C++ token exists in the HTML (HOST arrives through the EXPLAIN-1 translation)",
      cpp_tokens - html_tokens == {"HOST"})
check("the retired %DETAILS-HEADING% is gone from both sides",
      "DETAILS-HEADING" not in html_tokens and "DETAILS-HEADING" not in cpp_tokens)
for token in ("WHY-LINK", "MATCH-ENTRY", "MATCH-INFO", "SOURCE-LABEL", "SOURCE-INFO"):
    check("the new %%%s%% token exists on both sides" % token,
          token in html_tokens and token in cpp_tokens)
check("the EXPLAIN tokens still round-trip (the regex must not lose the digit)",
      "EXPLAIN-1" in html_tokens and "EXPLAIN-2" in cpp_tokens)
check("interstitialPage still hands the page to applyDirectionToPage",
      "QzTools::applyDirectionToPage(page)" in interstitial)

# ------------------------------------------------------------------
# 4. The disclosure markup
# ------------------------------------------------------------------
print("4. a native <details>, no script on the toggle")

check("the details block is a native <details> element",
      '<details class="vx-threat__why">' in interstitial_html)
check("the disclosure starts collapsed (no open attribute)",
      "<details" in interstitial_html and 'open' not in interstitial_html.split("<details", 1)[1].split(">", 1)[0])
check("the summary is a <summary>, not a link that would navigate",
      '<summary class="vx-threat__why-toggle">' in interstitial_html
      and "<a" not in interstitial_html.split("<summary", 1)[1].split("</summary>", 1)[0])
check("the summary carries the %WHY-LINK% question",
      "<span>%WHY-LINK%</span>" in interstitial_html)
check("the chevron is aria-hidden and not focusable (the summary is the control)",
      'class="vx-threat__chev"' in interstitial_html
      and 'aria-hidden="true"' in interstitial_html and 'focusable="false"' in interstitial_html)
check("the built-in marker is suppressed both ways (list-style and ::-webkit-details-marker)",
      "list-style: none" in interstitial_html and "::-webkit-details-marker { display: none; }" in interstitial_html)
check("the chevron rotates on open",
      ".vx-threat__why[open] .vx-threat__chev" in interstitial_html and "rotate(180deg)" in interstitial_html)
check("the answer reveals with an animation the shared reduced-motion rule can kill",
      "vx-threat-reveal" in interstitial_html)

script = interstitial_html.split("<script>", 1)[1].split("</script>", 1)[0]
check("the toggle needs no script (the page's only script stays goBack)",
      "goBack" in script and "details" not in script.lower())

rows = re.findall(r"<dt>%([A-Z0-9-]+)%</dt>", interstitial_html)
check("the four evidence rows in order: blocked URL, matching entry, source, list state",
      rows == ["BLOCKED-URL", "MATCH-ENTRY", "SOURCE-LABEL", "LIST-STATE"])

# ------------------------------------------------------------------
# 5. The evidence rows are honest and escaped
# ------------------------------------------------------------------
print("5. honest states, one snapshot, escaping")

check("the rows are read under one lock (one coherent snapshot of the blocklist)",
      interstitial.count("QMutexLocker lock(&m_mutex);") == 1)
check("the exact match says how it matched",
      'tr("%1 (the host itself is on the list)"' in interstitial)
check("the subdomain match names the listed parent that covers it",
      'tr("%1 (the visited host is a subdomain of this entry)"' in interstitial)
check("a page reached without a current match says so (stale address, hand-crafted URL)",
      'tr("not on the current blocklist")' in interstitial)
check("the not-loaded state says so instead of inventing an entry",
      'tr("unknown (the blocklist is not loaded)")' in interstitial)
check("the pre-existing honest list state stays",
      'tr("not downloaded yet")' in interstitial)
check("the entry is HTML-escaped before it reaches the page",
      "entry.toHtmlEscaped()" in interstitial)
check("the source is HTML-escaped before it reaches the page",
      "m_sourceUrl).toHtmlEscaped()" in interstitial)
check("an unconfigured manager still names the default source (never an empty row)",
      "m_sourceUrl.isEmpty() ? defaultSourceUrl() : m_sourceUrl" in interstitial)
check("the host and the URL keep their escaping",
      "blockedUrl.host().toHtmlEscaped()" in interstitial
      and "blockedUrl.toDisplayString().toHtmlEscaped()" in interstitial)
check("the summary question is translated",
      'tr("Why is this site flagged?")' in interstitial)

# ------------------------------------------------------------------
# 6. The matching algorithm behaves (a Python mirror of the walk)
# ------------------------------------------------------------------
print("6. the walk's behavior, simulated")


def matching_entry(host, entries):
    """The mirror of the C++ matchingEntry(): the host itself first,
    then each parent domain in turn, closest first."""
    if not host or not entries:
        return ""
    if host in entries:
        return host
    name = host
    while True:
        dot = name.find(".")
        if dot < 0 or dot + 1 >= len(name):
            return ""
        name = name[dot + 1:]
        if name in entries:
            return name


cases = [
    # (label, host, entries, expected)
    ("exact match returns the host",
     "bad.example", {"bad.example", "sub.ok.example"}, "bad.example"),
    ("the closest listed ancestor answers for a subdomain",
     "deep.www.bad.example", {"bad.example"}, "bad.example"),
    ("an exact listing beats the ancestor on the walk up",
     "x.www.bad.example", {"bad.example", "www.bad.example"}, "www.bad.example"),
    ("the dot boundary keeps the suffix spoof out",
     "evilbad.example", {"bad.example"}, ""),
    ("a listed parent of a different host does not match",
     "bad.example.evil.org", {"bad.example"}, ""),
    ("an unlisted host matches nothing",
     "good.example", {"bad.example"}, ""),
    ("the empty host matches nothing",
     "", {"bad.example"}, ""),
    ("the empty set matches nothing",
     "bad.example", set(), ""),
]
for label, host, entries, expected in cases:
    check("%s -> %r" % (label, expected), matching_entry(host, entries) == expected)

check("the C++ helper checks the set before the host (the empty set short-circuits)",
      "host.isEmpty() || set.isEmpty()" in helper)

# ------------------------------------------------------------------
# 7. The autotests carry the feature
# ------------------------------------------------------------------
print("7. autotests")

check("the matching-entry test is declared and defined",
      "void threatBlockMatchingEntryTest();" in autotest_h
      and "void SecurityToolsTest::threatBlockMatchingEntryTest()" in autotest_cpp)

entry_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockMatchingEntryTest()")
interstitial_test = body(autotest_cpp, "void SecurityToolsTest::threatBlockInterstitialTest()")

check("the matching test pins: exact, normalized, closest ancestor",
      'matchingListEntry(QSL("bad.example")), QSL("bad.example")' in entry_test
      and 'matchingListEntry(QSL("BAD.Example")), QSL("bad.example")' in entry_test
      and 'matchingListEntry(QSL("deep.www.bad.example")), QSL("bad.example")' in entry_test)
check("the matching test pins: an exact listing beats the ancestor",
      'matchingListEntry(QSL("www.bad.example")), QSL("www.bad.example")' in entry_test)
check("the matching test pins: the suffix spoofs and the empty host",
      'matchingListEntry(QSL("evilbad.example")).isEmpty()' in entry_test
      and "matchingListEntry(QString()).isEmpty()" in entry_test)
check("the matching test pins: pure query (off switch and session allow change nothing)",
      "setEnabled(false);" in entry_test and "allowForSession" in entry_test)
check("the matching test pins: the entry exists exactly when the host is blocked",
      entry_test.count("isHostBlocked(") >= 3)
check("the matching test restores the list it touched",
      entry_test.rstrip().endswith("}") and "applyListData(QByteArray());" in entry_test)

check("the interstitial test asserts the disclosure and its question",
      'page.contains(QSL("<details"))' in interstitial_test
      and 'page.contains(QSL("Why is this site flagged?"))' in interstitial_test)
check("the interstitial test asserts both match tails",
      "the host itself is on the list" in interstitial_test
      and "the visited host is a subdomain of this entry" in interstitial_test)
check("the interstitial test asserts the no-current-match honesty",
      "not on the current blocklist" in interstitial_test)
check("the interstitial test asserts the not-loaded honesty",
      "unknown (the blocklist is not loaded)" in interstitial_test)
check("the interstitial test asserts the source row and escapes a hostile source",
      'page.contains(QSL("Blocklist source"))' in interstitial_test
      and "source.example/list?&lt;script&gt;" in interstitial_test
      and '!hostileSourcePage.contains(QSL("list?<script>"))' in interstitial_test)
check("the interstitial test saves and restores the source it touched",
      "sourceBefore" in interstitial_test)
check("the interstitial test keeps the pre-existing checks (heading, escaping, both ways out)",
      "Dangerous site blocked" in interstitial_test
      and "%3Cscript%3E&amp;q=1" in interstitial_test
      and "proceedHref" in interstitial_test
      and "not downloaded yet" in interstitial_test)

# ------------------------------------------------------------------
# 8. Build discipline
# ------------------------------------------------------------------
print("8. build discipline")

check("the touched header keeps Qt keyword discipline (no bare slots: or signals: - the tree builds with -DQT_NO_KEYWORDS)",
      not re.search(r"^\s*(slots|signals):", manager_h, re.M))
check("the header's signal block uses the Q_SIGNALS spelling",
      "Q_SIGNALS:" in manager_h)
check("html.qrc still ships threatblocked.html",
      "threatblocked.html" in html_qrc)
renderers = []
for dirpath, _dirnames, filenames in os.walk(os.path.join(ROOT, "src")):
    for filename in filenames:
        if not filename.endswith((".cpp", ".h")):
            continue
        full = os.path.join(dirpath, filename)
        if "interstitialPage(" in read(full):
            renderers.append(os.path.relpath(full, ROOT))
renderers.sort()
check("the manager stays the one renderer (the scheme handler and nobody else calls it)",
      renderers == ["src/lib/network/schemehandlers/oszaschemehandler.cpp",
                    "src/lib/security/threatblockmanager.cpp",
                    "src/lib/security/threatblockmanager.h"])

# ------------------------------------------------------------------
# 9. The docs
# ------------------------------------------------------------------
print("9. docs")

readme_flat = " ".join(readme.split())
check("the README tells the user the warning page explains the decision",
      "Why is this site flagged?" in readme_flat and "matching blocklist entry" in readme_flat
      and "last update" in readme_flat)
check("the CHANGELOG has a Security tools (19) entry for the disclosure",
      "Security tools (19)" in changelog and "flagged" in changelog)

print()
if failures:
    print("FAILED: %d of %d checks" % (failures, checks))
    raise SystemExit(1)
print("OK: all %d checks passed" % checks)
