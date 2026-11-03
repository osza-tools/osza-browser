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

import re
import json
import subprocess
import tempfile

html = open(SRC, encoding="utf-8").read()
script = re.search(r"<script>(.*?)</script>", html, re.DOTALL).group(1)


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


def build_page_script(fingerprint_on, gpc_on):
    statuses = [
        {"id": "adblock", "label": "AdBlock", "on": True, "detail": "d"},
        {"id": "httpsonly", "label": "HTTPS-Only mode", "on": False, "detail": "d"},
        {"id": "striptracking", "label": "Strip tracking parameters", "on": True, "detail": "d"},
        {"id": "doh", "label": "Secure DNS", "on": False, "detail": "d"},
        {"id": "threatblock", "label": "Malicious site protection", "on": True, "detail": "d"},
        {"id": "fingerprint", "label": "Fingerprint protection", "on": fingerprint_on, "detail": "d"},
        {"id": "gpc", "label": "Global Privacy Control", "on": gpc_on, "detail": "d"},
    ]
    demo = [
        {"host": "example.com", "data": digits(site_noise_pattern(1234567890, "example.com", 64))},
        {"host": "example.org", "data": digits(site_noise_pattern(1234567890, "example.org", 64))},
    ]
    page = script
    page = page.replace("%STATUS-JSON%", json.dumps(statuses))
    page = page.replace("%DEMO-PATTERNS%", json.dumps(demo))
    page = page.replace("%I18N-JSON%", "{}")
    return page


harness = r'''
const vm = require('vm');

function makeElement(id) {
    return {
        id: id,
        children: [],
        style: {},
        className: '',
        textContent: '',
        attrs: {},
        listeners: {},
        appendChild: function (c) { this.children.push(c); return c; },
        setAttribute: function (k, v) { this.attrs[k] = v; },
        addEventListener: function (type, fn) { this.listeners[type] = fn; }
    };
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
    const storage = options.storage;
    const elements = {};
    for (const id of ['st-summary', 'st-summary-text', 'st-statuses', 'st-tests', 'st-tiles', 'st-reload']) {
        elements[id] = makeElement(id);
    }
    const document = {
        getElementById: function (id) { return elements[id] || null; },
        querySelectorAll: function () { return []; },
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
            return makeElement(null);
        }
    };
    const sandbox = {
        console: console,
        Math: Math, Object: Object, Array: Array, String: String, Promise: Promise,
        Uint8Array: Uint8Array, Uint8ClampedArray: Uint8ClampedArray,
        Int32Array: Int32Array, Float32Array: Float32Array, DataView: DataView,
        isFinite: isFinite, JSON: JSON,
        document: document,
        navigator: options.navigator,
        location: { reload: function () {} },
        localStorage: {
            getItem: function (k) { return (k in storage) ? storage[k] : null; },
            setItem: function (k, v) { storage[k] = String(v); }
        },
        matchMedia: function () { return { matches: true }; },
        requestAnimationFrame: function (fn) { return setTimeout(fn, 0); },
        performance: { now: function () { return 0; } },
        OfflineAudioContext: FakeOfflineAudioContext,
        setTimeout: setTimeout
    };
    if (options.guardLive) {
        sandbox.__oszaFingerprintGuard = 1;
    }
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    return { ctx: vm.createContext(sandbox), sandbox: sandbox, elements: elements };
}

let failures = 0;
function check(label, ok) {
    console.log((ok ? '  PASS ' : '  FAIL ') + label);
    if (!ok) failures++;
}

const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

async function runScenario(name, pageScript, options) {
    console.log('== ' + name + ' ==');
    const run = makeSandbox(options);
    vm.runInContext(pageScript, run.ctx);
    await sleep(120);

    const st = run.sandbox.window.__oszaSelfTest;
    check('page script settled (done)', st && st.done === true);
    return { st: st, elements: run.elements, sandbox: run.sandbox };
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

    console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
    process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) {
    console.error('HARNESS ERROR:', e);
    process.exit(1);
});
'''

full = "const PAGE_SCRIPT_ON = %s;\nconst PAGE_SCRIPT_OFF = %s;\n" % (
    json.dumps(build_page_script(True, True)),
    json.dumps(build_page_script(False, True)),
)
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
