#!/usr/bin/env python3
# ============================================================
# Osza - security self-test page verifier
#
# Standalone behavioural verification of the osza:selftest page
# (src/lib/data/html/selftest.html), without a Qt build: the page
# script is extracted from the document, the placeholders are
# substituted the way SelfTestPage::buildPage() does it, and the
# result runs in a Node VM context with a mocked DOM, canvas, WebGL
# and OfflineAudioContext.
#
# Scenarios:
#   A. protections on, guard live (window.__oszaFingerprintGuard
#      preset): every check settles, the digest-bearing checks pass,
#      three noise tiles render (this page + two demo hosts), the
#      summary banner is the "verified" one, and the digest is stable
#      across two runs sharing a localStorage (the reload check)
#   B. fingerprint protection off: the guard check reports "off",
#      the demo tiles disappear, the summary banner is the "off" one
#   C. GPC on but navigator.globalPrivacyControl missing: the GPC
#      check fails loudly (integration-bug detection), and passes
#      again once the signal is reported
# Plus the page's self-contained SHA-256 against the published test
# vectors, and the demo-pattern digits against the same siteNoise
# mirror as tools/security/verify_fingerprint_guard.py.
#
# Usage:
#   python3 tools/security/verify_selftest_page.py
#   (requires node >= 12 on PATH)
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   os.pardir, os.pardir,
                   "src", "lib", "data", "html", "selftest.html")
PAGE_CPP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, os.pardir,
                        "src", "lib", "security", "selftestpage.cpp")
HANDLER_CPP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           os.pardir, os.pardir,
                           "src", "lib", "network", "schemehandlers",
                           "oszaschemehandler.cpp")

import re
import json
import subprocess
import tempfile

html = open(SRC, encoding="utf-8").read()
script = re.search(r"<script>(.*?)</script>", html, re.DOTALL).group(1)
page_cpp = open(PAGE_CPP, encoding="utf-8").read()
handler_cpp = open(HANDLER_CPP, encoding="utf-8").read()


# ------------------------------------------------------------------
# 0. The section deep links: the URL shape and its landing, pinned
#    statically on every side that spells it
# ------------------------------------------------------------------
print("== section deep links: the URL shape, on every side ==")

checks = [0]
def static_check(label, ok):
    print(("  PASS " if ok else "  FAIL ") + label)
    checks[0] += 0 if ok else 1

static_check("pageUrl() spells the one address shape",
      'url.setPath(QSL("selftest"))' in page_cpp
      and 'query.addQueryItem(QSL("section")' in page_cpp)
static_check("pageUrl() drops an empty section, keeping the plain address",
      re.search(r"const QString trimmed = sectionId\.trimmed\(\);\s*\n\s*if \(!trimmed\.isEmpty\(\)\)",
                page_cpp) is not None)
static_check("sectionIdFromUrl() reads the same item back",
      'queryItemValue(QSL("section")).trimmed()' in page_cpp)
static_check("the scheme handler hands the item to the page",
      re.search(r"SelfTestPage::buildPage\(SelfTestPage::sectionIdFromUrl\(requestUrl\)\)",
                handler_cpp) is not None)
static_check("the page script spells the same URL shape",
      "'osza:selftest?section=' + encodeURIComponent(sectionId)" in script)
static_check("the four sections carry their stable ids in order",
      re.findall(r'data-section="([a-z]+)"', html)
      == ["protections", "fingerprint", "noise", "verify"])
static_check("every heading keeps its translated text in the name span",
      len(re.findall(r'<span class="st-h__text">%[A-Z-]+%</span>', html)) == 4)
static_check("the focus note has its dedicated element",
      'id="st-focus-note"' in html)
static_check("the anchors are wired into the headings",
      "wireCopyLink(deepLink, deepLinkHref)" in script
      and "heading.appendChild(deepLink)" in script)
static_check("the focus lands before the checks run",
      re.search(r"function run\(\) \{\s*\n\s*wireSectionLinks\(\);\s*\n\s*focusRequestedSection\(\);\s*\n\s*runStatuses\(\);",
                script) is not None)
static_check("the link titles and focus notes are translated in the page class",
      all(key in page_cpp for key in (
          'QSL("section_link_title")', 'QSL("section_link_copied_title")',
          'QSL("section_link_copy_failed_title")',
          'QSL("focus_note")', 'QSL("focus_unknown")')))
if checks[0]:
    print("STATIC CHECK(S) FAILED")
    exit(1)


# Mirror of FingerprintManager::siteNoisePattern(), used to build the
# demo-pattern digits exactly like SelfTestPage::demoPatternsJson().
# Keep in sync with fingerprintmanager.cpp (see also
# tools/security/verify_fingerprint_guard.py).
def site_noise_pattern(master_seed, host, size, channel=0):
    name = host.lower()
    h = master_seed & 0xFFFFFFFF
    for ch in name:
        h ^= ord(ch)
        h = (h * 0x01000193) & 0xFFFFFFFF
    site_key = h

    def mix(seed, value):
        x = (seed ^ ((value * 0x85EBCA77) & 0xFFFFFFFF)) & 0xFFFFFFFF
        x ^= x >> 13
        x = (x * 0xC2B2AE3D) & 0xFFFFFFFF
        x ^= x >> 16
        return x

    out = []
    for y in range(size):
        for x in range(size):
            value = (((x + 1) * 0x9E3779B1) & 0xFFFFFFFF) \
                ^ (((y + 1) * 0x85EBCA77) & 0xFFFFFFFF) \
                ^ ((channel * 0x27D4EB2F) & 0xFFFFFFFF)
            out.append(mix(site_key, value) % 3 - 1)
    return out


def digits(pattern):
    return "".join(str(d + 1) for d in pattern)


def build_statuses(fingerprint_on, gpc_on):
    return [
        {"id": "adblock", "label": "AdBlock", "on": True, "detail": "d"},
        {"id": "httpsonly", "label": "HTTPS-Only mode", "on": False, "detail": "d"},
        {"id": "striptracking", "label": "Strip tracking parameters", "on": True, "detail": "d"},
        {"id": "doh", "label": "Secure DNS", "on": False, "detail": "d"},
        {"id": "threatblock", "label": "Malicious site protection", "on": True, "detail": "d"},
        {"id": "fingerprint", "label": "Fingerprint protection", "on": fingerprint_on, "detail": "d"},
        {"id": "gpc", "label": "Global Privacy Control", "on": gpc_on, "detail": "d"},
    ]


def build_demo():
    return [
        {"host": "example.com", "data": digits(site_noise_pattern(1234567890, "example.com", 64))},
        {"host": "example.org", "data": digits(site_noise_pattern(1234567890, "example.org", 64))},
    ]


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
        style: {},
        className: '',
        attrs: {},
        listeners: {},
        scrolledIntoView: false,
        selected: false,
        appendChild: function (c) { this.children.push(c); return c; },
        removeChild: function (c) {
            const i = this.children.indexOf(c);
            if (i !== -1) {
                this.children.splice(i, 1);
            }
            return c;
        },
        setAttribute: function (k, v) { this.attrs[k] = String(v); },
        getAttribute: function (k) { return (k in this.attrs) ? this.attrs[k] : null; },
        addEventListener: function (type, fn) { this.listeners[type] = fn; },
        scrollIntoView: function () { this.scrolledIntoView = true; },
        select: function () { this.selected = true; }
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

// A 2D canvas faithful enough for the page: solid full-canvas fills
// are readable back through getImageData (with guard-like +-1 noise
// for the 64x64 middle-gray probe), everything else returns a
// deterministic pattern so digests are stable across runs.
// Installs getContext() on the given canvas object.
function makeCanvas2d(canvas) {
    let lastFill = '';
    let fullCover = false;
    const noise = [];
    let s = 0x1234;
    for (let i = 0; i < 64 * 64; i++) {
        s = (s * 1103515245 + 12345) & 0x7fffffff;
        noise.push((s % 3) - 1);
    }
    const ctx = {
        strokeStyle: '',
        lineWidth: 1,
        font: '',
        createLinearGradient: function () { return { addColorStop: function () {} }; },
        fillRect: function (x, y, w, h) { if (x === 0 && y === 0 && w === canvas.width && h === canvas.height) fullCover = true; },
        beginPath: function () {}, arc: function () {}, stroke: function () {},
        moveTo: function () {}, lineTo: function () {}, closePath: function () {}, fill: function () {},
        fillText: function () {},
        clearRect: function () {},
        getImageData: function (sx, sy, w, h) {
            const data = new Uint8ClampedArray(w * h * 4);
            const grayProbe = canvas.width === 64 && canvas.height === 64 && fullCover && lastFill === 'rgb(128, 128, 128)';
            for (let p = 0; p < w * h; p++) {
                for (let c = 0; c < 4; c++) {
                    let v;
                    if (grayProbe) {
                        v = c === 3 ? 255 : 128 + noise[(sy * w + sx + p) % noise.length];
                    } else {
                        v = (p * 7 + c * 29) % 256;
                    }
                    data[p * 4 + c] = v;
                }
            }
            return { width: w, height: h, data: data };
        },
        createImageData: function (w, h) {
            return { width: w, height: h, data: new Uint8ClampedArray(w * h * 4) };
        },
        putImageData: function () {},
        fillStyle: ''
    };
    Object.defineProperty(ctx, 'fillStyle', {
        get: function () { return lastFill; },
        set: function (v) { lastFill = String(v); fullCover = false; }
    });
    return ctx;
}

// A WebGL context reporting the generic strings the guard spoofs to.
function makeWebgl(canvas) {
    const gl = {
        VENDOR: 0x1F00, RENDERER: 0x1F01, RGBA: 0x1908, UNSIGNED_BYTE: 0x1401,
        COLOR_BUFFER_BIT: 0x4000, SCISSOR_TEST: 0x0C11,
        UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246,
        getExtension: function (name) {
            if (name === 'WEBGL_debug_renderer_info') {
                return { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
            }
            return null;
        },
        getParameter: function (p) {
            if (p === 0x9245) return 'Intel Inc.';
            if (p === 0x9246) return 'Apple GPU';
            if (p === 0x1F00) return 'WebKit';
            return 'generic-' + p;
        },
        enable: function () {}, disable: function () {},
        scissor: function () {}, clearColor: function () {}, clear: function () {},
        readPixels: function (x, y, w, h, f, t, px) {
            for (let i = 0; i < px.length; i++) px[i] = (i * 11) % 256;
        }
    };
    return gl;
}

class FakeOfflineAudioContext {
    constructor(channels, length, sampleRate) { this._length = length; }
    createOscillator() { return { type: '', frequency: { value: 0 }, connect: function () {}, start: function () {} }; }
    createDynamicsCompressor() {
        return { threshold: { value: 0 }, knee: { value: 0 }, ratio: { value: 0 },
                 attack: { value: 0 }, release: { value: 0 }, connect: function () {} };
    }
    get destination() { return {}; }
    startRendering() {
        const data = new Float32Array(this._length);
        for (let i = 0; i < data.length; i++) data[i] = Math.sin(i * 0.001) * 0.5;
        return Promise.resolve({ getChannelData: function () { return data; } });
    }
}

function makeSandbox(options) {
    // options.clipboard: 'async-ok' (the async API answers with a
    //   resolved promise), 'async-fail' (it refuses) or absent (no
    //   async API at all); options.execCommand: whether the legacy
    //   copy path succeeds. Everything the copy action needs is
    //   recorded - the texts written, the commands run, the timers
    //   scheduled - so the scenarios assert what really happened.
    const storage = options.storage;
    const state = { clipboardWrites: [], execCommandCalls: [] };
    const timers = [];
    let timerId = 0;

    const elements = {};
    for (const id of ['st-summary', 'st-summary-text', 'st-focus-note', 'st-reload']) {
        elements[id] = makeElement(null, id);
    }

    // The four sections the static template carries, mocked with
    // the same shape the page's own script looks for: a wrapper with
    // data-section, a heading row, the translated name in its span,
    // and the section's content container (which the checks render
    // into through the ids they already know).
    const sections = [];
    const sectionSpecs = [
        ['protections', 'Protections', 'st-statuses'],
        ['fingerprint', 'Fingerprint randomization', 'st-tests'],
        ['noise', 'The invisible noise', 'st-tiles'],
        ['verify', 'Verify on a real site', null]
    ];
    for (const spec of sectionSpecs) {
        const section = makeElement('section');
        section.setAttribute('data-section', spec[0]);
        const heading = makeElement('h2');
        heading.className = 'vx-h st-h';
        const text = makeElement('span');
        text.className = 'st-h__text';
        text.textContent = spec[1];
        heading.appendChild(text);
        section.appendChild(heading);
        if (spec[2]) {
            const content = makeElement(null, spec[2]);
            content.id = spec[2];
            elements[spec[2]] = content;
            section.appendChild(content);
        }
        sections.push(section);
    }

    const document = {
        getElementById: function (id) { return elements[id] || null; },
        querySelectorAll: function (selector) {
            if (selector === '.st-sec') {
                return sections.slice();
            }
            return [];
        },
        createElement: function (tag) {
            if (tag === 'canvas') {
                const c = { width: 0, height: 0 };
                const ctx2d = makeCanvas2d(c);
                c.getContext = function (type) {
                    if (type === '2d') return ctx2d;
                    if (type === 'webgl2' || type === 'webgl' || type === 'experimental-webgl') return makeWebgl(c);
                    return null;
                };
                return c;
            }
            return makeElement(tag);
        },
        body: makeElement('body'),
        execCommand: function (command) {
            state.execCommandCalls.push(command);
            return !!options.execCommand;
        }
    };
    const sandbox = {
        console: console,
        Math: Math, Object: Object, Array: Array, String: String, Promise: Promise,
        Uint8Array: Uint8Array, Uint8ClampedArray: Uint8ClampedArray,
        Int32Array: Int32Array, Float32Array: Float32Array, DataView: DataView,
        isFinite: isFinite, JSON: JSON,
        encodeURIComponent: encodeURIComponent,
        document: document,
        navigator: options.navigator,
        location: { reload: function () {} },
        localStorage: {
            getItem: function (k) { return (k in storage) ? storage[k] : null; },
            setItem: function (k, v) { storage[k] = String(v); }
        },
        matchMedia: function () { return { matches: true }; },
        requestAnimationFrame: function () {},
        performance: { now: function () { return 0; } },
        OfflineAudioContext: FakeOfflineAudioContext,
        setTimeout: function (fn, delay) {
            timerId += 1;
            timers.push({ id: timerId, fn: fn });
            return timerId;
        },
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
        const writes = state.clipboardWrites;
        const mode = options.clipboard;
        sandbox.navigator = {
            hardwareConcurrency: 4,
            deviceMemory: 8,
            clipboard: {
                writeText: function (text) {
                    writes.push(text);
                    return mode === 'async-ok'
                        ? Promise.resolve()
                        : Promise.reject(new Error('write refused'));
                }
            }
        };
    }
    if (options.guardLive) {
        sandbox.__oszaFingerprintGuard = 1;
    }
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;

    function runTimers() {
        const pending = timers.splice(0);
        for (let i = 0; i < pending.length; i++) {
            pending[i].fn();
        }
    }

    return { ctx: vm.createContext(sandbox), sandbox: sandbox, elements: elements,
             sections: sections, state: state, timers: timers, runTimers: runTimers };
}

let failures = 0;
function check(label, ok) {
    console.log((ok ? '  PASS ' : '  FAIL ') + label);
    if (!ok) failures++;
}

const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

// The copy action settles its promises on the microtask queue, so
// the assertions about its answers run one turn later.
function afterMicrotasks(fn) {
    return Promise.resolve().then(function () {
        return Promise.resolve();
    }).then(fn);
}

async function runScenario(name, pageScript, options) {
    console.log('== ' + name + ' ==');
    const run = makeSandbox(options);
    vm.runInContext(pageScript, run.ctx);
    await sleep(120);

    const st = run.sandbox.window.__oszaSelfTest;
    check('page script settled (done)', st && st.done === true);
    return { st: st, elements: run.elements, sandbox: run.sandbox,
             sections: run.sections, state: run.state, timers: run.timers,
             runTimers: run.runTimers };
}

// The section anchors, in document order, straight from the mocked
// headings the page wired them into.
function sectionLinks(run) {
    const out = [];
    for (const section of run.sections) {
        const heading = section.children[0];
        for (const child of heading.children) {
            if (child.className && child.className.indexOf('st-link') !== -1) {
                out.push(child);
            }
        }
    }
    return out;
}

(async function () {
    const scriptOn = PAGE_SCRIPT_ON;
    const scriptOff = PAGE_SCRIPT_OFF;

    // A: protection on, guard live, GPC on and reported.
    const sharedStorage = {};
    const navigatorOn = { hardwareConcurrency: 4, deviceMemory: 8, globalPrivacyControl: true };
    const a1 = await runScenario('A1: on, guard live, first load', scriptOn,
                                 { guardLive: true, navigator: navigatorOn, storage: sharedStorage });
    check('seven status rows', a1.elements['st-statuses'].children.length === 7);
    check('status rows carry ids', a1.elements['st-statuses'].children.every(function (r) { return r.attrs['data-id']; }));
    check('guard check passed', a1.st.results.guard.verdict === 'pass');
    check('canvas check passed', a1.st.results.canvas.verdict === 'pass');
    check('stability is the first measured load', a1.st.results.stability.verdict === 'first');
    check('webgl strings check passed', a1.st.results.webgl.verdict === 'pass');
    check('webgl pixels check passed', a1.st.results.webglpixels.verdict === 'pass');
    check('audio check passed', a1.st.results.audio.verdict === 'pass');
    check('hardware check passed', a1.st.results.hardware.verdict === 'pass');
    check('gpc check passed', a1.st.results.gpc.verdict === 'pass');
    check('canvas digest is 64 hex chars', /^[0-9a-f]{64}$/.test(a1.st.canvasHash));
    check('three noise tiles', a1.elements['st-tiles'].children.length === 3);
    check('summary is the verified banner', a1.elements['st-summary'].className.indexOf('st-banner--pass') !== -1
          && a1.elements['st-summary-text'].textContent === 'summary_verified');
    check('reload button wired', typeof a1.elements['st-reload'].listeners['click'] === 'function');
    check('sha256 vector (abc)', a1.st.sha256('abc') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    check('sha256 vector (empty)', a1.st.sha256('') === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    check('sha256 vector (long input)', a1.st.sha256('The quick brown fox jumps over the lazy dog') === 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');

    // A2: second load of the same page: the digest is unchanged.
    const a2 = await runScenario('A2: on, guard live, reload', scriptOn,
                                 { guardLive: true, navigator: navigatorOn, storage: sharedStorage });
    check('digest stable across reloads', a2.st.canvasHash === a1.st.canvasHash);
    check('stability check passed on reload', a2.st.results.stability.verdict === 'pass');

    // B: protection off, no guard.
    const b = await runScenario('B: protection off', scriptOff,
                                { guardLive: false, navigator: navigatorOn, storage: {} });
    check('guard check reports off', b.st.results.guard.verdict === 'off');
    check('canvas check reports off', b.st.results.canvas.verdict === 'off');
    check('only the live tile remains', b.elements['st-tiles'].children.length === 1);
    check('summary is the off banner', b.elements['st-summary'].className.indexOf('st-banner--pass') === -1
          && b.elements['st-summary-text'].textContent === 'summary_off');

    // C: GPC on, but the DOM signal is missing -> loud failure.
    const c = await runScenario('C: GPC on, signal missing', scriptOn,
                                { guardLive: true, navigator: { hardwareConcurrency: 4, deviceMemory: 8 }, storage: {} });
    check('gpc check fails loudly', c.st.results.gpc.verdict === 'fail');

    // D: a section deep link lands focused on its section.
    const focusI18n = {
        section_link_title: 'Copy a link to this section of the self-test',
        section_link_copied_title: 'Link copied to the clipboard',
        section_link_copy_failed_title: "Could not copy the link - the context menu's Copy link address still works",
        focus_note: 'Showing the %1 section of the self-test.',
        focus_unknown: 'The address asked for a section this page does not have; everything is shown from the top.'
    };
    const d = await runScenario('D: focused on the noise section',
                                buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                { guardLive: true, navigator: navigatorOn, storage: {} });
    check('the focused section is marked',
          d.sections[2].className.indexOf('st-sec--focus') !== -1);
    check('only the asked-for section is marked',
          d.sections.filter(function (s) { return s.className.indexOf('st-sec--focus') !== -1; }).length === 1);
    check('the focused section is scrolled to', d.sections[2].scrolledIntoView === true);
    check('the note names the section by its own heading',
          d.elements['st-focus-note'].style.display === 'block'
          && d.elements['st-focus-note'].textContent === 'Showing the The invisible noise section of the self-test.');
    check('every section carries a wired anchor',
          sectionLinks(d).length === 4
          && sectionLinks(d).every(function (l) { return typeof l.listeners['click'] === 'function'; }));
    check('the anchors carry the pageUrl() address shape',
          sectionLinks(d).every(function (l, i) {
              return String(l.href) === 'osza:selftest?section='
                     + ['protections', 'fingerprint', 'noise', 'verify'][i];
          }));

    // E: an address naming no section is answered, never an error.
    const e = await runScenario('E: unknown section in the address',
                                buildScript({ fingerprint: true, gpc: true, section: 'nosector', i18n: focusI18n }),
                                { guardLive: true, navigator: navigatorOn, storage: {} });
    check('nothing is marked for an unknown section',
          e.sections.every(function (s) { return s.className.indexOf('st-sec--focus') === -1; }));
    check('nothing is scrolled for an unknown section',
          e.sections.every(function (s) { return s.scrolledIntoView === false; }));
    check('the note says the address asked for too much',
          e.elements['st-focus-note'].style.display === 'block'
          && e.elements['st-focus-note'].textContent === focusI18n.focus_unknown);

    // F: a plain click on a section anchor copies the deep link; the
    // async Clipboard API first, the legacy path as the fallback,
    // the honest title when nothing copies, modified clicks left to
    // the browser.
    const f = await runScenario('F: copy link, async clipboard',
                                buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                { guardLive: true, storage: {}, clipboard: 'async-ok' });
    const fLinks = sectionLinks(f);
    let fPrevented = false;
    fLinks[2].listeners['click']({ button: 0, preventDefault: function () { fPrevented = true; } });

    await afterMicrotasks(function () {
        check('a plain click does not follow the anchor', fPrevented === true);
        check('the section address is written to the clipboard',
              f.state.clipboardWrites.length === 1
              && f.state.clipboardWrites[0] === 'osza:selftest?section=noise');
        check('the legacy path was not needed', f.state.execCommandCalls.length === 0);
        check('the checkmark shows while the address sits in the clipboard',
              fLinks[2].className.indexOf('st-link--copied') !== -1
              && fLinks[2].textContent === '\u2713');
        check('the title says the link was copied',
              fLinks[2].attrs['title'] === 'Link copied to the clipboard'
              && fLinks[2].attrs['aria-label'] === 'Link copied to the clipboard');
        check('the revert is scheduled with the answer, not the click',
              f.timers.length === 1);

        f.runTimers();
        check('the anchor says "#" again after the revert',
              fLinks[2].className.indexOf('st-link--copied') === -1
              && fLinks[2].textContent === '#'
              && fLinks[2].attrs['title'] === 'Copy a link to this section of the self-test');
    });

    // F2: the async API refuses; the legacy path answers instead.
    const f2 = await runScenario('F2: copy link, async refuses',
                                 buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                 { guardLive: true, storage: {}, clipboard: 'async-fail', execCommand: true });
    const f2Links = sectionLinks(f2);
    let f2Prevented = false;
    f2Links[0].listeners['click']({ button: 0, preventDefault: function () { f2Prevented = true; } });

    await afterMicrotasks(function () {
        check('the refused write falls back to the legacy path',
              f2.state.execCommandCalls.length === 1
              && f2.state.execCommandCalls[0] === 'copy');
        check('the fallback copies the same address',
              f2Links[0].textContent === '\u2713');
        check('the anchor was not followed either', f2Prevented === true);

        f2.runTimers();
        check('the fallback reverts too',
              f2Links[0].textContent === '#'
              && f2Links[0].className.indexOf('st-link--copied') === -1);
    });

    // F3: nothing can copy: the anchor is honest about it.
    const f3 = await runScenario('F3: copy link, nothing copies',
                                 buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                 { guardLive: true, storage: {}, execCommand: false });
    const f3Links = sectionLinks(f3);
    let f3Prevented = false;
    f3Links[3].listeners['click']({ button: 0, preventDefault: function () { f3Prevented = true; } });

    await afterMicrotasks(function () {
        check('without any clipboard the anchor is honest',
              f3Links[3].attrs['title'] === focusI18n.section_link_copy_failed_title
              && f3Links[3].attrs['aria-label'] === focusI18n.section_link_copy_failed_title);
        check('no checkmark without a copy', f3Links[3].textContent === '#');
        check('the anchor was still not followed', f3Prevented === true);
    });

    // F4: a modified click keeps the browser's own meaning.
    const f4 = await runScenario('F4: modified clicks',
                                 buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                 { guardLive: true, storage: {}, clipboard: 'async-ok' });
    const f4Links = sectionLinks(f4);
    let ctrlPrevented = false;
    let middlePrevented = false;
    f4Links[1].listeners['click']({ button: 0, ctrlKey: true, preventDefault: function () { ctrlPrevented = true; } });
    f4Links[1].listeners['click']({ button: 1, preventDefault: function () { middlePrevented = true; } });

    await afterMicrotasks(function () {
        check('a ctrl-click is left to the browser',
              ctrlPrevented === false && f4.state.clipboardWrites.length === 0);
        check('a middle click is left to the browser',
              middlePrevented === false && f4.state.execCommandCalls.length === 0);
        check('the anchor keeps its href for everything else',
              String(f4Links[1].href) === 'osza:selftest?section=fingerprint');
    });

    // F5: a double click writes the address twice, appends the copied
    // state once, and exactly one revert stays pending.
    const f5 = await runScenario('F5: double click',
                                 buildScript({ fingerprint: true, gpc: true, section: 'noise', i18n: focusI18n }),
                                 { guardLive: true, storage: {}, clipboard: 'async-ok' });
    const f5Links = sectionLinks(f5);
    f5Links[0].listeners['click']({ button: 0, preventDefault: function () {} });
    f5Links[0].listeners['click']({ button: 0, preventDefault: function () {} });

    await afterMicrotasks(function () {
        check('a double click writes the address twice',
              f5.state.clipboardWrites.length === 2);
        check('the copied state is appended once',
              f5Links[0].className.split('st-link--copied').length - 1 === 1);
        check('exactly one revert stays pending',
              f5.timers.length === 1);
    });

    console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
    process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) {
    console.error('HARNESS ERROR:', e);
    process.exit(1);
});
'''

full = "const RAW_SCRIPT = %s;\n" % json.dumps(script)
full += "const STATUSES_ON = %s;\n" % json.dumps(build_statuses(True, True))
full += "const STATUSES_OFF = %s;\n" % json.dumps(build_statuses(False, True))
full += "const DEMO = %s;\n" % json.dumps(build_demo())
full += r'''
function buildScript(opts) {
    opts = opts || {};
    let page = RAW_SCRIPT;
    page = page.replace("%STATUS-JSON%", JSON.stringify(opts.fingerprint === false ? STATUSES_OFF : STATUSES_ON));
    page = page.replace("%DEMO-PATTERNS%", JSON.stringify(DEMO));
    page = page.replace("%FOCUS-JSON%", JSON.stringify({ section: opts.section || "" }));
    page = page.replace("%I18N-JSON%", JSON.stringify(opts.i18n || {}));
    return page;
}
const PAGE_SCRIPT_ON = buildScript({ fingerprint: true, gpc: true });
const PAGE_SCRIPT_OFF = buildScript({ fingerprint: false, gpc: true });
'''
full += harness

with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
    f.write(full)
    path = f.name

r = subprocess.run(["node", path], capture_output=True, text=True)
print(r.stdout)
if r.stderr:
    print("STDERR:", r.stderr[:2000])
os.unlink(path)
exit(r.returncode)
