#!/usr/bin/env python3
# ============================================================
# Osza - security settings diff page verifier
#
# Standalone behavioural verification of the osza:settings-diff
# page (src/lib/data/html/settingsdiff.html) without a Qt build,
# in the spirit of verify_selftest_page.py and
# verify_settings_porter.py:
#
#   1. The page and its builder cannot drift apart: every %TOKEN%
#      the HTML carries is substituted by
#      SettingsDiffPage::buildPage() in settingsdiffpage.cpp, and
#      every token the builder replaces exists in the HTML (the
#      same cross-check verify_settings_porter.py applies to the
#      document format constants).
#
#   2. The page script never builds markup out of data: no
#      innerHTML anywhere, and the mock DOM throws if it is called
#      anyway - every dynamic string goes through textContent, so
#      nothing a settings file could carry can inject markup.
#
#   3. The URL shape agrees on all sides: the page's links, the
#      pageUrl() builder in settingsdiffpage.cpp, the page name
#      registered in the scheme handler (oszaschemehandler.cpp), the
#      security dashboard's per-tool row links (securitysidebar.cpp)
#      and the padlock menu's per-site entry links
#      (siteinfowidget.cpp) all spell
#      osza:settings-diff[?preset=<id>][&tool=<key>], the baseline
#      they refer to is resolved through the preset catalog in one
#      place (SettingsDiffPage::recommendedBaseline()), and whether
#      a "tool" item names one of the tools is judged by the porter's
#      own key list (toolKeys()) - the dashboard's rows and the
#      padlock's entries included.
#
#   4. The data contract the page script reads is exactly the one
#      diffData() writes: every OSZA_DIFF.* field referenced by the
#      script is present in the C++ producer (static cross-check
#      of the JSON keys).
#
#   5. The copy action on the section anchors and the clipboard it
#      needs: a plain click copies the deep link through the async
#      Clipboard API with the legacy execCommand path as the
#      fallback, modified clicks are left to the browser, and the
#      C++ side answers the clipboard feature permissions for
#      internal osza: pages (a sanitized write granted, a read
#      denied - webpage.cpp pins the policy).
#
#   6. The page script runs (Node VM, mocked DOM) for every shape
#      diffData() can produce, with scenarios mirroring the
#      autotests: the overview (a card per built-in baseline,
#      linking to its diff), a baseline's diff (the banner, one
#      section per changed tool, one row per changed field, the
#      porter's exception-summary lines, the skipped/unchanged/
#      quiet lists), the per-tool deep links on every section, a
#      focused diff (the tool's section marked and scrolled to,
#      the note rendered as text; a tool with no section answered
#      by its note alone), an unknown tool over the full diff, the
#      no-change diff, the unknown-preset dead end, the defensive
#      broken-preview shape, and the copy action of a section
#      anchor on every path it can take (async copy, refused then
#      legacy copy, nothing copies at all, modified click).
#
# Usage:
#   python3 tools/security/verify_settings_diff_page.py
#   (requires node >= 12 on PATH)
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    os.pardir, os.pardir)
HTML_PATH = os.path.join(ROOT, "src", "lib", "data", "html", "settingsdiff.html")
PAGE_CPP_PATH = os.path.join(ROOT, "src", "lib", "security", "settingsdiffpage.cpp")
HANDLER_CPP_PATH = os.path.join(ROOT, "src", "lib", "network", "schemehandlers", "oszaschemehandler.cpp")
PRESETS_CPP_PATH = os.path.join(ROOT, "src", "lib", "security", "securitypresets.cpp")
SIDEBAR_CPP_PATH = os.path.join(ROOT, "src", "lib", "sidebar", "securitysidebar.cpp")
SITEINFO_CPP_PATH = os.path.join(ROOT, "src", "lib", "other", "siteinfowidget.cpp")
WEBPAGE_CPP_PATH = os.path.join(ROOT, "src", "lib", "webengine", "webpage.cpp")

import copy
import json
import re
import subprocess
import sys
import tempfile

html = open(HTML_PATH, encoding="utf-8").read()
page_cpp = open(PAGE_CPP_PATH, encoding="utf-8").read()
handler_cpp = open(HANDLER_CPP_PATH, encoding="utf-8").read()
presets_cpp = open(PRESETS_CPP_PATH, encoding="utf-8").read()
sidebar_cpp = open(SIDEBAR_CPP_PATH, encoding="utf-8").read()
siteinfo_cpp = open(SITEINFO_CPP_PATH, encoding="utf-8").read()
webpage_cpp = open(WEBPAGE_CPP_PATH, encoding="utf-8").read()

failures = 0
checks = 0


def check(label, ok):
    global failures, checks
    checks += 1
    print(("  PASS " if ok else "  FAIL ") + label)
    if not ok:
        failures += 1


def parse_presets():
    """The built-in preset ids, parsed from securitypresets.cpp the
    same way verify_settings_porter.py parses them."""
    ids = re.findall(r'preset\.id = QSL\("([a-z-]+)"\)', presets_cpp)
    assert ids, "no preset ids found in securitypresets.cpp"
    return ids


# ------------------------------------------------------------------
# 1. The placeholder contract between the HTML and buildPage()
# ------------------------------------------------------------------
print("== placeholders: the HTML and the builder agree ==")

html_tokens = set(re.findall(r"%[A-Z0-9-]+%", html))
cpp_tokens = set(re.findall(r'"(%[A-Z0-9-]+%)"', page_cpp))

check("every HTML token is substituted by buildPage()",
      html_tokens - cpp_tokens - {"%DIRECTION%"} == set())
check("the direction token is applied too (QzTools::applyDirectionToPage)",
      "applyDirectionToPage" in page_cpp)
check("every buildPage() token exists in the HTML",
      cpp_tokens - html_tokens == set())

# ------------------------------------------------------------------
# 2. textContent only: no markup out of data
# ------------------------------------------------------------------
print("== rendering: no markup out of data ==")

script = re.search(r"<script>(.*?)</script>", html, re.DOTALL).group(1)

check("the page script never touches innerHTML",
      "innerHTML" not in script)
check("the page script never touches document.write",
      "document.write" not in script)
check("the page script never touches eval",
      re.search(r"\beval\s*\(", script) is None)

# ------------------------------------------------------------------
# 3. The URL shape, on all four sides
# ------------------------------------------------------------------
print("== URL shape: page links, pageUrl(), scheme handler, dashboard ==")

PAGE_URL = "osza:settings-diff"

# The dashboard's row links point at one baseline's diff; the id has
# to be one the catalog carries, or the links would promise a dead
# end.
CATALOG_IDS = parse_presets()

check("the page links build %s?preset=<id>" % PAGE_URL,
      ("'%s?preset=' + encodeURIComponent" % PAGE_URL) in script)
check("the page links build the &tool=<key> deep links",
      ("'&tool=' + encodeURIComponent") in script)
check("the footer links back to the plain %s" % PAGE_URL,
      ('href="%s"' % PAGE_URL) in html)
check("pageUrl() builds the same scheme and path",
      re.search(r'setScheme\(QSL\("osza"\)\)', page_cpp) is not None
      and re.search(r'setPath\(QSL\("settings-diff"\)\)', page_cpp) is not None)
check("pageUrl() builds the preset and the tool items",
      re.search(r'addQueryItem\(QSL\("preset"\)', page_cpp) is not None
      and re.search(r'addQueryItem\(QSL\("tool"\)', page_cpp) is not None)
check("the scheme handler serves the page",
      'QSL("settings-diff")' in handler_cpp)
check("the scheme handler hands the preset query to the page",
      "SettingsDiffPage::presetIdFromUrl" in handler_cpp)
check("the scheme handler hands the tool query to the page",
      "SettingsDiffPage::toolIdFromUrl" in handler_cpp)
check("whether a tool item names a tool is the porter's judgment",
      "SecuritySettingsPorter::toolKeys()" in page_cpp)

# The security dashboard's per-tool rows are the fourth side: they
# link to a tool's part of a baseline's diff with the same address,
# built by the same pageUrl(), for a baseline resolved through the
# catalog and a key judged by the porter's own list. The catalog
# resolution lives in SettingsDiffPage now - the one resolver every
# consumer asks - so "recommended" cannot mean two things.
check("the dashboard's per-tool links go through pageUrl()",
      "SettingsDiffPage::pageUrl(" in sidebar_cpp)
check("the recommended baseline is resolved through the catalog, in one place",
      re.search(r"presetById\(QLatin1String\(kRecommendedBaselineId\)\)", page_cpp) is not None
      and "recommended-baseline" in page_cpp)
check("the dashboard's per-tool links ask the one resolver",
      "SettingsDiffPage::recommendedBaseline()" in sidebar_cpp)
check("the dashboard's baseline is one the catalog carries",
      "recommended-baseline" in CATALOG_IDS)
check("the dashboard builds a row link only for a key the porter knows",
      "SecuritySettingsPorter::toolKeys().contains(" in sidebar_cpp)
check("the dashboard's links land in the shared openToolDiff()",
      "SettingsDiffPage::openToolDiff(m_window, toolKey)" in sidebar_cpp)

# The padlock menu's per-site entries are the fifth side: the two
# tools with per-site state in the menu (HTTPS-Only mode, fingerprint
# protection) carry the same "diff" link beside their entry, built
# and landed the same way as the dashboard's rows.
check("the padlock's per-site entries are the two per-site tools",
      'setupToolDiffLink(ui->httpsOnlyDiffLink, QSL("httpsOnly"))' in siteinfo_cpp
      and 'setupToolDiffLink(ui->fingerprintProtectionDiffLink, QSL("fingerprintProtection"))' in siteinfo_cpp)
check("the padlock's per-site links ask the one resolver",
      "SettingsDiffPage::recommendedBaseline()" in siteinfo_cpp)
check("the padlock's per-site links go through pageUrl()",
      "SettingsDiffPage::pageUrl(baseline.id, toolKey)" in siteinfo_cpp)
check("the padlock builds a link only for a key the porter knows",
      "SecuritySettingsPorter::toolKeys().contains(toolKey)" in siteinfo_cpp)
check("the padlock's links land in the shared openToolDiff()",
      "SettingsDiffPage::openToolDiff(m_window, toolKey)" in siteinfo_cpp)
check("the padlock's osza: links belong to the browser, never the OS",
      "setOpenExternalLinks(false)" in siteinfo_cpp)
check("the padlock's links hide with their per-site rows",
      "ui->httpsOnlyDiffLink->hide()" in siteinfo_cpp
      and "ui->fingerprintProtectionDiffLink->hide()" in siteinfo_cpp)

# ------------------------------------------------------------------
# 4. The data contract: every OSZA_DIFF key the script reads is
#    produced by diffData()
# ------------------------------------------------------------------
print("== data contract: the script reads what diffData() writes ==")

script_keys = set(re.findall(r"OSZA_DIFF\.([A-Za-z]+)", script))
for m in re.finditer(r"(?:preset|preview|presets|changes?|entry)\.([A-Za-z]+)", script):
    script_keys.add(m.group(1))

produced_keys = set(re.findall(r'insert\(QSL\("([A-Za-z]+)"\)', page_cpp))

# Keys of the change rows, preset entries and the focus answers the
# page reads.
read_keys = {
    # overview entries and the preset object
    "id", "name", "description", "changes",
    # the preview object
    "ok", "error", "configuredTools", "totalTools",
    "skippedTools", "unchangedTools", "quietTools",
    # the change rows
    "tool", "toolName", "field", "fieldName", "current", "next",
    "summary",
    # the page-level fields
    "mode", "preset", "presetId", "presets", "preview",
    # the per-tool focus answers
    "focusTool", "unknownTool", "key", "note",
}

missing = read_keys - produced_keys
check("every data key the page reads is inserted by diffData()",
      missing == set())
if missing:
    print("        missing from the producer: %s" % sorted(missing))

# The i18n contract: every key the page script reads through t()/tf()
# exists in i18nJson(), and i18nJson() carries no key the page never
# reads - the two sides cannot drift apart silently.
js_i18n_keys = set(re.findall(r"\bt[f]?\(\x27([a-z_]+)\x27", script))
# plainList(root, 'heading_key', ...) reads the key through its
# parameter - the literal at its call sites counts as a read.
js_i18n_keys |= set(re.findall(r"plainList\([^,]+, \x27([a-z_]+)\x27", script))
cpp_i18n_keys = set(re.findall(r'strings\.insert\(QSL\("([a-z_]+)"\)', page_cpp))

check("every i18n key the page reads exists in i18nJson()",
      js_i18n_keys - cpp_i18n_keys == set())
if js_i18n_keys - cpp_i18n_keys:
    print("        missing from i18nJson(): %s" % sorted(js_i18n_keys - cpp_i18n_keys))
check("i18nJson() carries no key the page never reads",
      cpp_i18n_keys - js_i18n_keys == set())
if cpp_i18n_keys - js_i18n_keys:
    print("        unused in the page: %s" % sorted(cpp_i18n_keys - js_i18n_keys))

# ------------------------------------------------------------------
# 5. The copy action on the section anchors, and the clipboard it
#    needs on both sides of the scheme handler
# ------------------------------------------------------------------
print("== copy link: the anchors' action, and the clipboard it needs ==")

check("every section anchor is wired for copying",
      "wireCopyLink(deepLink, deepLinkHref)" in script)
check("the anchor announces the copy, not just a link",
      "t('tool_link_title')" in script
      and "Copy a link to this tool's part of the diff" in page_cpp)
check("the copy prefers the async Clipboard API",
      "navigator.clipboard.writeText" in script)
check("the copy falls back to the legacy execCommand path",
      "document.execCommand('copy')" in script)
check("a modified click is left to the browser",
      "event.ctrlKey" in script)

# The C++ side of the clipboard: the async API asks for a
# permission, and for the browser's own pages the policy is pinned
# here. Permissions arrive as QWebEnginePermission handles answered
# where they stand (the Qt5 feature API retired with the Qt 6
# permission objects), and Qt's clipboard permission is one
# combined type in every version - Chromium asks for its sanitized
# write as ClipboardReadWrite too, so no Qt release ever delivered
# a separate one - and for the trusted internal pages it is
# granted, the same trust the legacy execCommand path already
# extends to them. Everything else still goes through the HTML5
# permission manager.
osza_clipboard_block = re.search(
    r'if \(permission\.origin\(\)\.scheme\(\) == QL1S\("osza"\)\) \{(.*?)\n    \}',
    webpage_cpp, re.DOTALL)
check("the clipboard permission is answered for osza: pages",
      osza_clipboard_block is not None)
if osza_clipboard_block:
    block = osza_clipboard_block.group(1)
    check("the combined clipboard type is granted for osza: pages",
          re.search(r"case QWebEnginePermission::PermissionType::ClipboardReadWrite:.*?permission\.grant\(\)",
                    block, re.DOTALL) is not None)
    check("no clipboard type that Qt never shipped is referenced",
          "ClipboardSanitizedWrite" not in block)
    check("the grant is not behind a Qt version guard",
          "QT_VERSION_CHECK" not in block)
    check("no clipboard permission is rejected behind the grant",
          re.search(r"case QWebEnginePermission::PermissionType::ClipboardReadWrite:.*?permission\.reject\(\)",
                    block, re.DOTALL) is None)
    check("the grant answers where it stands (no deferral through the manager)",
          "requestPermissions" not in block)
check("every other permission still asks the permission manager",
      "mApp->html5PermissionsManager()->requestPermissions(this, permission)" in webpage_cpp)

# ------------------------------------------------------------------
# 6. The page script, in a Node VM with a mocked DOM, for every
#    shape diffData() can produce
# ------------------------------------------------------------------

PRESET_IDS = CATALOG_IDS

# A diff shaped exactly like the porter's preview: three tools with
# changes, one of them an exclusions change carrying the porter's
# one-line summaries, one skipped section, one absent tool, two
# configured-but-quiet tools.
DIFF_DATA = {
    "mode": "diff",
    "preset": {
        "id": "recommended-baseline",
        "name": "Recommended baseline",
        "description": "All seven protections on with the project defaults.",
    },
    "preview": {
        "ok": True,
        "configuredTools": 6,
        "totalTools": 7,
        "changes": [
            {"tool": "adblock", "toolName": "AdBlock",
             "field": "enabled", "fieldName": "Enabled",
             "current": "off", "next": "on", "summary": []},
            {"tool": "httpsOnly", "toolName": "HTTPS-Only mode",
             "field": "enabled", "fieldName": "Enabled",
             "current": "off", "next": "on", "summary": []},
            {"tool": "httpsOnly", "toolName": "HTTPS-Only mode",
             "field": "exclusions", "fieldName": "Site exceptions",
             "current": "bank.example, keep.example",
             "next": "keep.example, legacy.example",
             "summary": ["Clears the exception for: bank.example",
                         "Adds an exception for: legacy.example"]},
            {"tool": "secureDns", "toolName": "Secure DNS (DNS-over-HTTPS)",
             "field": "mode", "fieldName": "Mode",
             "current": "off", "next": "on, with fallback to the system resolver",
             "summary": []},
        ],
        "skippedTools": ["Fingerprint protection: a field is missing or has the wrong type"],
        "unchangedTools": ["Global Privacy Control (Sec-GPC)"],
        "quietTools": ["Tracking parameter stripping"],
    },
}

OVERVIEW_DATA = {
    "mode": "overview",
    "presets": [
        {"id": pid, "name": pid.replace("-", " ").title(),
         "description": "The %s baseline." % pid,
         "changes": index + 1}
        for index, pid in enumerate(PRESET_IDS)
    ],
}

UNKNOWN_DATA = {
    "mode": "unknown",
    "presetId": "no-such-baseline",
    "presets": [
        {"id": pid, "name": pid.replace("-", " ").title(),
         "description": "The %s baseline." % pid}
        for pid in PRESET_IDS
    ],
}

BROKEN_DATA = {
    "mode": "diff",
    "preset": {"id": "recommended-baseline", "name": "Recommended baseline",
               "description": "description"},
    "preview": {"ok": False, "error": "The tools section is malformed."},
}

NO_CHANGE_DATA = {
    "mode": "diff",
    "preset": {"id": "maximum-protection", "name": "Maximum protection",
               "description": "All seven on, secure DNS only."},
    "preview": {
        "ok": True,
        "configuredTools": 7,
        "totalTools": 7,
        "changes": [],
        "skippedTools": [],
        "unchangedTools": [],
        "quietTools": ["AdBlock", "HTTPS-Only mode", "Tracking parameter stripping",
                       "Secure DNS (DNS-over-HTTPS)", "Malicious site protection",
                       "Fingerprint protection", "Global Privacy Control (Sec-GPC)"],
    },
}

# The focused shapes: a tool the baseline would change (a section to
# mark and scroll to), a tool it would not (the note answers alone),
# and a "tool" item naming no security tool at all (a warning line
# over the full diff). The notes are whatever diffData() worded - the
# page renders them as text, it never re-derives them.
FOCUS_DATA = copy.deepcopy(DIFF_DATA)
FOCUS_DATA["focusTool"] = {
    "key": "secureDns",
    "name": "Secure DNS (DNS-over-HTTPS)",
    "note": "Showing the changes for Secure DNS (DNS-over-HTTPS).",
}

FOCUS_QUIET_DATA = copy.deepcopy(DIFF_DATA)
FOCUS_QUIET_DATA["focusTool"] = {
    "key": "threatBlock",
    "name": "Malicious site protection",
    "note": "Malicious site protection is already at the baseline's settings.",
}

UNKNOWN_TOOL_DATA = copy.deepcopy(DIFF_DATA)
UNKNOWN_TOOL_DATA["unknownTool"] = "teleportation"

I18N = {
    "pill_changes_none": "changes nothing here",
    "pill_changes_one": "would change 1 setting",
    "pill_changes_many": "would change %1 settings",
    "preset_open": "Preview the diff",
    "banner_changes": 'The baseline "%1" would change %2 settings across %3 of the 7 security tools.',
    "banner_changes_single": 'The baseline "%1" would change 1 setting in %2 of the 7 security tools.',
    "banner_none": 'The baseline "%1" changes nothing that is set right now.',
    "banner_skipped_one": "1 section would be skipped, listed below with the reason.",
    "banner_skipped_many": "%1 sections would be skipped, listed below with the reasons.",
    "banner_preset_source": "A ready-made configuration of the Osza project.",
    "heading_skipped": "Would be skipped, the rest still applies",
    "heading_unchanged": "Not in the baseline, left unchanged",
    "heading_quiet": "Already at the baseline's settings",
    "unknown_title": "Unknown baseline",
    "unknown_text": '"%1" is not one of the built-in presets.',
    "unknown_tool_text": '"%1" is not one of the security tools - the whole diff follows.',
    "tool_link_title": "Copy a link to this tool's part of the diff",
    "tool_link_copied_title": "Link copied to the clipboard",
    "tool_link_copy_failed_title": "Could not copy the link - the context menu's Copy link address still works",
    "broken_text": "The baseline's document did not pass validation: %1",
}


def substitute(data):
    """The page exactly as buildPage() serves it: the data and the
    i18n strings as compact JSON with '<' escaped, the placeholders
    the C++ builder replaces filled in the same way."""
    page = script
    page = page.replace("%DATA-JSON%",
                        json.dumps(data, separators=(",", ":")).replace("<", "\\u003c"))
    page = page.replace("%I18N-JSON%",
                        json.dumps(I18N, separators=(",", ":")).replace("<", "\\u003c"))
    page = page.replace("%OVERVIEW-HEADING%", "Recommended baselines")
    page = page.replace("%OVERVIEW-INTRO%", "Pick a baseline to see what it would change here right now.")
    page = page.replace("%CHANGES-HEADING%", "Changes")
    page = page.replace("%DETAIL-HEADING%", "Details")
    page = page.replace("%COLUMN-CURRENT%", "Now")
    page = page.replace("%COLUMN-AFTER%", "With the baseline")
    return page


harness = r'''
const vm = require('vm');

function makeElement(tag, id) {
    // The mock DOM refuses innerHTML: the page must build its nodes
    // and set every dynamic string through textContent. textContent
    // aggregates like the real DOM: own text, then the children's.
    // scrollIntoView records that it ran, so a focused section's
    // landing can be asserted; select() and removeChild() let the
    // copy action's legacy fallback run the same way it runs in a
    // browser.
    const node = {
        tag: tag,
        id: id || '',
        children: [],
        style: { setProperty: function (k, v) { this[k] = v; } },
        className: '',
        attrs: {},
        listeners: {},
        scrolledIntoView: false,
        appendChild: function (c) { this.children.push(c); return c; },
        removeChild: function (c) {
            const i = this.children.indexOf(c);
            if (i !== -1) {
                this.children.splice(i, 1);
            }
            return c;
        },
        setAttribute: function (k, v) { this.attrs[k] = String(v); },
        addEventListener: function (type, fn) { this.listeners[type] = fn; },
        scrollIntoView: function () { this.scrolledIntoView = true; },
        select: function () { this.selected = true; },
        set innerHTML(v) { throw new Error('innerHTML is forbidden on this page'); },
        get innerHTML() { throw new Error('innerHTML is forbidden on this page'); }
    };
    let ownText = '';
    Object.defineProperty(node, 'textContent', {
        get: function () {
            let out = ownText;
            for (let i = 0; i < node.children.length; i++) {
                out += node.children[i].textContent;
            }
            return out;
        },
        set: function (v) { ownText = String(v); }
    });
    return node;
}

function makeSandbox(options) {
    // options.clipboard: 'async-ok' (the async API answers with a
    //   resolved promise), 'async-fail' (it refuses) or absent (no
    //   async API at all); options.execCommand: whether the legacy
    //   copy path succeeds. Everything the copy action needs is
    //   recorded - the texts written, the commands run, the timers
    //   scheduled - so the scenarios assert what really happened.
    options = options || {};

    const elements = {};
    const timers = [];
    const state = { clipboardWrites: [], execCommandCalls: [] };

    const document = {
        createElement: function (tag) { return makeElement(tag); },
        getElementById: function (id) {
            if (!elements[id]) {
                elements[id] = makeElement('div', id);
            }
            return elements[id];
        },
        body: makeElement('body'),
        execCommand: function (command) {
            state.execCommandCalls.push(command);
            return !!options.execCommand;
        }
    };

    let reloaded = false;
    let timerId = 0;
    const sandbox = {
        document: document,
        location: { reload: function () { reloaded = true; } },
        matchMedia: function (q) { return { matches: false }; },
        requestAnimationFrame: function () {},
        performance: {},
        encodeURIComponent: encodeURIComponent,
        String: String,
        Math: Math,
        setTimeout: function (fn, delay) { timerId += 1; timers.push({id: timerId, fn: fn}); return timerId; },
        clearTimeout: function (id) {
            for (let i = 0; i < timers.length; i++) {
                if (timers[i].id === id) {
                    timers.splice(i, 1);
                    return;
                }
            }
        }
    };

    if (options.clipboard === 'async-ok' || options.clipboard === 'async-fail') {
        sandbox.navigator = {
            clipboard: {
                writeText: function (text) {
                    state.clipboardWrites.push(text);
                    return options.clipboard === 'async-ok'
                        ? Promise.resolve()
                        : Promise.reject(new Error('write refused'));
                }
            }
        };
    }

    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    return {
        ctx: vm.createContext(sandbox),
        sandbox: sandbox,
        elements: elements,
        state: state,
        timers: timers,
        runTimers: function () { while (timers.length) { timers.shift().fn(); } },
        get reloaded() { return reloaded; }
    };
}

let failures = 0;
function check(label, ok) {
    console.log((ok ? '  PASS ' : '  FAIL ') + label);
    if (!ok) failures++;
}

function runPage(pageScript, options) {
    const run = makeSandbox(options);
    vm.runInContext(pageScript, run.ctx);
    return run;
}

function collect(root, cls, out) {
    // Class matching the way the browser does it: whole tokens, not
    // substrings - 'sd-change__arrow' is not 'sd-change'.
    out = out || [];
    for (let i = 0; i < root.children.length; i++) {
        const child = root.children[i];
        const classes = (child.className || '').split(/\s+/);
        if (classes.indexOf(cls) !== -1) {
            out.push(child);
        }
        collect(child, cls, out);
    }
    return out;
}

function texts(nodes) {
    return nodes.map(function (n) { return n.textContent; });
}
'''

# The Python harness hands its scenarios to the Node program as a
# JSON blob; the Node side runs them and prints PASS/FAIL lines.
node_program = harness + r'''
const SCENARIOS = SCENARIO_BLOB;

const results = [];

function scenarioDiff() {
    const run = runPage(SCENARIOS.diff.script);
    const root = run.elements['sd-content'];
    const sd = run.sandbox.window.__oszaSettingsDiff;
    const data = SCENARIOS.diff.data;

    const banners = collect(root, 'sd-banner');
    const sections = collect(root, 'sd-tool');
    const changes = collect(root, 'sd-change');
    const summaries = collect(root, 'sd-change__summary');
    const skipped = collect(root, 'sd-plainlist--skipped');
    const unchanged = collect(root, 'sd-plainlist--unchanged');
    const quiet = collect(root, 'sd-plainlist--quiet');

    check('mode is diff', sd.mode === 'diff');
    check('one banner, the changes one', banners.length === 1 && banners[0].className.indexOf('sd-banner--changes') !== -1);
    check('the banner names the baseline and the numbers',
          banners[0].children.length === 1 &&
          banners[0].children[0].textContent.indexOf('Recommended baseline') !== -1 &&
          banners[0].children[0].textContent.indexOf('4 settings') !== -1 &&
          banners[0].children[0].textContent.indexOf('3 of the 7') !== -1);
    check('one section per changed tool', sections.length === 3);
    check('sections are marked with the stable tool key',
          sections.map(function (s) { return s.attrs['data-tool']; }).join(',') === 'adblock,httpsOnly,secureDns');
    check('one row per changed field', changes.length === 4);
    check('counts agree with the data', sd.counts.changeRows === 4 && sd.counts.toolSections === 3);
    check('the exclusions change carries both summary lines', summaries.length === 2 &&
          texts(summaries).join('|') === 'Clears the exception for: bank.example|Adds an exception for: legacy.example');
    check('values are the data, as text',
          texts(collect(changes[0], 'sd-change__val')).join(',') === 'off,on');
    check('the current value leads, the baseline follows',
          changes[0].children[1].children[0].textContent === 'off' &&
          changes[0].children[1].children[2].textContent === 'on');
    check('the field row names the field with the display name',
          changes[1].children[0].textContent === 'Enabled');
    check('one skipped entry, rendered with its reason',
          skipped.length === 1 && skipped[0].children.length === 1 &&
          texts(skipped[0].children).join('') === 'Fingerprint protection: a field is missing or has the wrong type');
    check('one unchanged entry', unchanged.length === 1 && unchanged[0].children.length === 1);
    check('the quiet list renders', quiet.length === 1 && quiet[0].children.length === 1);
    check('the reload button is wired', typeof run.elements['sd-reload'].listeners['click'] === 'function');
    run.elements['sd-reload'].listeners['click']();
    check('the reload button reloads', run.reloaded === true);
    check('the overview link stays visible', run.elements['sd-overview-link'].style.display !== 'none');
}

function scenarioOverview() {
    const run = runPage(SCENARIOS.overview.script);
    const root = run.elements['sd-content'];
    const sd = run.sandbox.window.__oszaSettingsDiff;

    const cards = collect(root, 'sd-preset');
    const pills = collect(root, 'sd-pill');

    check('mode is overview', sd.mode === 'overview');
    check('one card per baseline', cards.length === SCENARIOS.overview.data.presets.length);
    check('counts agree with the data', sd.counts.presetCards === cards.length);
    check('every card links to its diff', cards.every(function (card) {
        return card.attrs && String(card.href).indexOf('osza:settings-diff?preset=') === 0;
    }));
    check('the pill counts come from the data',
          pills.map(function (p) { return p.textContent; }).join('|') ===
          SCENARIOS.overview.data.presets.map(function (p) {
              return p.changes === 1 ? 'would change 1 setting'
                                     : 'would change ' + p.changes + ' settings';
          }).join('|'));
    check('the overview link hides on the overview', run.elements['sd-overview-link'].style.display === 'none');
}

function scenarioUnknown() {
    const run = runPage(SCENARIOS.unknown.script);
    const root = run.elements['sd-content'];
    const sd = run.sandbox.window.__oszaSettingsDiff;

    const warn = collect(root, 'sd-banner--warn');
    const cards = collect(root, 'sd-preset');

    check('mode is unknown', sd.mode === 'unknown');
    check('one warning banner', warn.length === 1);
    check('the banner names the requested id', warn[0].children[0].textContent.indexOf('no-such-baseline') !== -1);
    check('the baselines to go back to', cards.length === SCENARIOS.unknown.data.presets.length);
}

function scenarioNoChange() {
    const run = runPage(SCENARIOS.nochange.script);
    const root = run.elements['sd-content'];

    const banners = collect(root, 'sd-banner');
    const sections = collect(root, 'sd-tool');
    const quiet = collect(root, 'sd-plainlist--quiet');
    const legend = collect(root, 'sd-legend');

    check('the plain banner, not the changes one',
          banners.length === 1 && banners[0].className.indexOf('sd-banner--changes') === -1);
    check('no tool sections', sections.length === 0);
    check('no legend without changes', legend.length === 0);
    check('the quiet list has every tool', quiet.length === 1 && quiet[0].children.length === 7);
}

function scenarioFocus() {
    const run = runPage(SCENARIOS.focus.script);
    const root = run.elements['sd-content'];
    const sd = run.sandbox.window.__oszaSettingsDiff;

    const sections = collect(root, 'sd-tool');
    const notes = collect(root, 'sd-focus-note');
    const links = collect(root, 'sd-tool__link');
    const focused = sections.filter(function (s) {
        return s.className.indexOf('sd-tool--focus') !== -1;
    });

    check('the focus data carries through',
          sd.data.focusTool && sd.data.focusTool.key === 'secureDns');
    check('exactly the focused tool\'s section is marked',
          focused.length === 1 && focused[0].attrs['data-tool'] === 'secureDns');
    check('the focused section scrolled into view', focused[0].scrolledIntoView === true);
    check('the other sections did not scroll',
          sections.every(function (s) {
              return s === focused[0] || s.scrolledIntoView === false;
          }));
    check('the note renders as text, exactly as worded',
          notes.length === 1 && notes[0].textContent === SCENARIOS.focus.data.focusTool.note);
    check('one deep link per section', links.length === sections.length);
    check('the deep links carry the preset and a tool',
          links.every(function (l) {
              return String(l.href).indexOf('osza:settings-diff?preset=recommended-baseline&tool=') === 0;
          }));
    check('each section\'s link names its own tool',
          sections.map(function (s) { return s.attrs['data-tool']; }).join(',')
              === links.map(function (l) { return String(l.href).split('&tool=')[1]; }).join(','));
    check('the deep links are titled',
          links.every(function (l) {
              return l.attrs['title'] === "Copy a link to this tool's part of the diff";
          }));
}

function scenarioFocusQuiet() {
    const run = runPage(SCENARIOS.focusquiet.script);
    const root = run.elements['sd-content'];

    const sections = collect(root, 'sd-tool');
    const focused = collect(root, 'sd-tool--focus');
    const notes = collect(root, 'sd-focus-note');

    check('a tool without changes has no section',
          sections.every(function (s) { return s.attrs['data-tool'] !== 'threatBlock'; }));
    check('nothing is marked or scrolled',
          focused.length === 0
          && sections.every(function (s) { return s.scrolledIntoView === false; }));
    check('the note still answers',
          notes.length === 1 && notes[0].textContent === SCENARIOS.focusquiet.data.focusTool.note);
}

function scenarioUnknownTool() {
    const run = runPage(SCENARIOS.unknowntool.script);
    const root = run.elements['sd-content'];
    const sd = run.sandbox.window.__oszaSettingsDiff;

    const warn = collect(root, 'sd-banner--warn');
    const sections = collect(root, 'sd-tool');
    const changes = collect(root, 'sd-change');
    const notes = collect(root, 'sd-focus-note');

    check('the unknown tool is carried through', sd.data.unknownTool === 'teleportation');
    check('one warning banner, naming the requested id',
          warn.length === 1 && warn[0].children[0].textContent.indexOf('teleportation') !== -1
          && warn[0].children[0].textContent.indexOf('not one of the security tools') !== -1);
    check('the whole diff still renders', sections.length === 3 && changes.length === 4);
    check('no focus without a tool to focus', notes.length === 0);
}

function scenarioBroken() {
    const run = runPage(SCENARIOS.broken.script);
    const root = run.elements['sd-content'];

    const fail = collect(root, 'sd-banner--fail');
    check('the broken preview is a loud dead end',
          fail.length === 1 && fail[0].children[0].textContent.indexOf('The tools section is malformed.') !== -1);
}

function afterMicrotasks(fn) {
    // The copy action settles its promises on the microtask queue,
    // so the assertions about its answers run one turn later.
    return Promise.resolve().then(function () {
        return Promise.resolve();
    }).then(fn);
}

function scenarioCopyLink() {
    // A section anchor's plain click copies the deep link instead of
    // following it. The copy goes through the async Clipboard API
    // when the page has one, falls back to the legacy execCommand
    // path when the API refuses or is missing, says "copied" with a
    // checkmark while the address sits in the clipboard and reverts
    // after a moment, says the honest thing when nothing could be
    // copied, and leaves modified clicks to the browser.
    const run = runPage(SCENARIOS.copylink.script, {clipboard: 'async-ok'});
    const links = collect(run.elements['sd-content'], 'sd-tool__link');

    check('the anchors are wired for copying', links.length === 3
          && links.every(function (l) {
              return typeof l.listeners['click'] === 'function';
          }));

    let prevented = false;
    links[0].listeners['click']({button: 0, preventDefault: function () { prevented = true; }});

    const link = links[0];

    return afterMicrotasks(function () {
        check('a plain click does not follow the anchor', prevented === true);
        check('the deep link is written to the clipboard',
              run.state.clipboardWrites.length === 1
              && run.state.clipboardWrites[0] === String(link.href)
              && String(link.href).indexOf('osza:settings-diff?preset=recommended-baseline&tool=adblock') === 0);
        check('the legacy path was not needed', run.state.execCommandCalls.length === 0);
        check('the checkmark shows while the link is copied',
              link.className.indexOf('sd-tool__link--copied') !== -1
              && link.textContent === '\u2713');
        check('the title says the link was copied',
              link.attrs['title'] === 'Link copied to the clipboard'
              && link.attrs['aria-label'] === 'Link copied to the clipboard');
        check('the revert is scheduled with the answer, not the click',
              run.timers.length === 1);

        run.runTimers();
        check('the anchor says "#" again after the revert',
              link.className.indexOf('sd-tool__link--copied') === -1
              && link.textContent === '#'
              && link.attrs['title'] === "Copy a link to this tool's part of the diff");

        // The async API refuses: the legacy path answers instead.
        const fallback = runPage(SCENARIOS.copylink.script, {clipboard: 'async-fail', execCommand: true});
        const fallbackLinks = collect(fallback.elements['sd-content'], 'sd-tool__link');
        let fallbackPrevented = false;
        fallbackLinks[1].listeners['click']({button: 0, preventDefault: function () { fallbackPrevented = true; }});

        return afterMicrotasks(function () {
            check('the refused write falls back to the legacy path',
                  fallback.state.execCommandCalls.length === 1
                  && fallback.state.execCommandCalls[0] === 'copy');
            check('the fallback copies the same address',
                  fallback.state.clipboardWrites.length === 1
                  && fallbackLinks[1].textContent === '\u2713');
            check('the anchor was not followed either', fallbackPrevented === true);

            fallback.runTimers();
            check('the fallback reverts too',
                  fallbackLinks[1].textContent === '#'
                  && fallbackLinks[1].className.indexOf('sd-tool__link--copied') === -1);

            // A double click: the address is written twice, but the
            // copied state is appended once and exactly one revert
            // stays pending - the second answer replaces the first.
            const double = runPage(SCENARIOS.copylink.script, {clipboard: 'async-ok'});
            const doubleLinks = collect(double.elements['sd-content'], 'sd-tool__link');
            doubleLinks[0].listeners['click']({button: 0, preventDefault: function () {}});
            doubleLinks[0].listeners['click']({button: 0, preventDefault: function () {}});

            return afterMicrotasks(function () {
                check('a double click writes the address twice',
                      double.state.clipboardWrites.length === 2);
                check('the copied state is appended once',
                      doubleLinks[0].className.split('sd-tool__link--copied').length - 1 === 1);
                check('exactly one revert stays pending',
                      double.timers.length === 1);

                // No async API, and the legacy path refuses too: the
                // anchor says so - the context menu's "Copy link
                // address" still works.
                const failed = runPage(SCENARIOS.copylink.script, {execCommand: false});
                const failedLinks = collect(failed.elements['sd-content'], 'sd-tool__link');
                let failedPrevented = false;
                failedLinks[2].listeners['click']({button: 0, preventDefault: function () { failedPrevented = true; }});

                check('without any clipboard the anchor is honest',
                      failedLinks[2].attrs['title'] === "Could not copy the link - the context menu's Copy link address still works"
                      && failedLinks[2].attrs['aria-label'] === "Could not copy the link - the context menu's Copy link address still works");
                check('no checkmark without a copy', failedLinks[2].textContent === '#');
                check('the anchor was still not followed', failedPrevented === true);

                // A modified click keeps the browser's own meaning:
                // nothing copied, nothing prevented.
                const modified = runPage(SCENARIOS.copylink.script, {clipboard: 'async-ok'});
                const modifiedLinks = collect(modified.elements['sd-content'], 'sd-tool__link');
                let ctrlPrevented = false;
                let middlePrevented = false;
                modifiedLinks[0].listeners['click']({button: 0, ctrlKey: true, preventDefault: function () { ctrlPrevented = true; }});
                modifiedLinks[0].listeners['click']({button: 1, preventDefault: function () { middlePrevented = true; }});

                return afterMicrotasks(function () {
                    check('a ctrl-click is left to the browser',
                          ctrlPrevented === false && modified.state.clipboardWrites.length === 0);
                    check('a middle click is left to the browser',
                          middlePrevented === false && modified.state.execCommandCalls.length === 0);
                    check('the anchor keeps its href for everything else',
                          String(modifiedLinks[0].href).indexOf('osza:settings-diff?preset=recommended-baseline&tool=adblock') === 0);
                });
            });
        });
    });
}

Promise.resolve()
    .then(scenarioDiff)
    .then(scenarioOverview)
    .then(scenarioUnknown)
    .then(scenarioNoChange)
    .then(scenarioBroken)
    .then(scenarioFocus)
    .then(scenarioFocusQuiet)
    .then(scenarioUnknownTool)
    .then(scenarioCopyLink)
    .then(function () {
        console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
        process.exit(failures === 0 ? 0 : 1);
    });
'''

print("== page script, mocked DOM, every shape ==")
blob = {
    "diff": {"data": DIFF_DATA, "script": substitute(DIFF_DATA)},
    "overview": {"data": OVERVIEW_DATA, "script": substitute(OVERVIEW_DATA)},
    "unknown": {"data": UNKNOWN_DATA, "script": substitute(UNKNOWN_DATA)},
    "nochange": {"data": NO_CHANGE_DATA, "script": substitute(NO_CHANGE_DATA)},
    "broken": {"data": BROKEN_DATA, "script": substitute(BROKEN_DATA)},
    "focus": {"data": FOCUS_DATA, "script": substitute(FOCUS_DATA)},
    "focusquiet": {"data": FOCUS_QUIET_DATA, "script": substitute(FOCUS_QUIET_DATA)},
    "unknowntool": {"data": UNKNOWN_TOOL_DATA, "script": substitute(UNKNOWN_TOOL_DATA)},
    "copylink": {"data": DIFF_DATA, "script": substitute(DIFF_DATA)},
}
node_program = node_program.replace("SCENARIO_BLOB", json.dumps(blob))

with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
    f.write(node_program)
    path = f.name

try:
    r = subprocess.run(["node", path], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        failures += 1
        sys.stderr.write(r.stderr)
    else:
        checks += r.stdout.count("PASS ")
finally:
    os.unlink(path)

print()
if failures == 0:
    print("self-test passed: %d checks, page %s" % (checks, PAGE_URL))
    sys.exit(0)
print("SELF-TEST FAILED: %d failure(s)" % failures)
sys.exit(1)
