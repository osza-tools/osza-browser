#!/usr/bin/env python3
# ============================================================
# Osza - fingerprint guard verifier
#
# Standalone behavioural verification of the injected guard
# script (src/lib/security/fingerprintmanager.cpp), without a
# Qt build: the script template is extracted from the source,
# the placeholders are substituted like the browser would, and
# the result runs in isolated Node VM contexts (one fresh
# global per "site", exactly like a real browser gives every
# document).
#
# Checks, per protected site:
#   - canvas 2D getImageData: deterministic +-1 RGB noise,
#     alpha untouched, stable across calls
#   - toDataURL keeps returning a string (never throws)
#   - WebGL readPixels perturbed (alpha untouched),
#     UNMASKED_VENDOR/RENDERER spoofed, every other
#     getParameter value passes through
#   - AnalyserNode and AudioBuffer readouts perturbed
#     (float noise above float32 resolution, idempotent
#     getChannelData), deterministic across calls
#   - navigator.hardwareConcurrency/deviceMemory report common
#     values
# and on sites excluded via "*.domain" entries: the original,
# completely untouched behaviour.
# Plus uniqueness: same seed on different hosts and different
# seeds on the same host produce different noise, while the
# same host + seed reproduce identical noise (stable identity).
#
# Usage:
#   python3 tools/security/verify_fingerprint_guard.py
#   (requires node >= 12 on PATH)
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   os.pardir, os.pardir,
                   "src", "lib", "security", "fingerprintmanager.cpp")

import re
import json
import subprocess
import tempfile

src = open(SRC, encoding="utf-8").read()
js = re.search(r'R"JS\((.*?)\)JS"', src, re.DOTALL).group(1)


def build(hostname, exclusions, seed):
    return js.replace("%EXCLUSIONS%", json.dumps(exclusions)).replace("%MASTER_SEED%", str(seed))


harness = r'''
const vm = require('vm');

function FakeImageData(w, h) {
    this.width = w; this.height = h;
    this.data = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < this.data.length; i++) this.data[i] = (i * 7) % 256;
}

function makeContext(hostname) {
    const ctx2d = {
        canvas: { width: 8, height: 4 },
        getImageData: function (sx, sy, w, h) { return new FakeImageData(w, h); },
        drawImage: function () {},
        putImageData: function () {}
    };
    const htmlCanvasProto = {
        toDataURL: function () { return 'data:image/png;base64,ORIGINAL'; },
        toBlob: function (cb) { cb('blob-original'); }
    };
    const navProto = { hardwareConcurrency: 32, deviceMemory: 16 };
    const analyserProto = {
        getFloatFrequencyData: function (arr) { for (let i = 0; i < arr.length; i++) arr[i] = -100 + i; },
        getByteFrequencyData: function (arr) { for (let i = 0; i < arr.length; i++) arr[i] = 200; },
        getFloatTimeDomainData: function (arr) { for (let i = 0; i < arr.length; i++) arr[i] = 0.5 + i * 0.125; },
        getByteTimeDomainData: function (arr) { for (let i = 0; i < arr.length; i++) arr[i] = 128; }
    };
    const webglProto = {
        readPixels: function (x, y, w, h, f, t, pixels) { for (let i = 0; i < pixels.length; i++) pixels[i] = 100; },
        getParameter: function (p) { return 'REAL-' + p; }
    };
    const channelData = new Float32Array(16);
    for (let i = 0; i < channelData.length; i++) channelData[i] = 0.25 + i * 0.125;
    const audioBufferProto = {
        getChannelData: function () { return channelData; },
        copyFromChannel: function (dest) { for (let i = 0; i < dest.length; i++) dest[i] = 0.25 + i * 0.125; }
    };

    const sandbox = {
        Uint8Array, Uint8ClampedArray, Float32Array, WeakSet,
        Math, isFinite, String, Object, Array,
        console,
        location: { hostname: hostname },
        document: {
            createElement: function () {
                const c = { width: 0, height: 0 };
                c.getContext = function () { return ctx2d; };
                return c;
            }
        },
        CanvasRenderingContext2D: { prototype: ctx2d },
        HTMLCanvasElement: { prototype: htmlCanvasProto },
        Navigator: { prototype: navProto },
        AnalyserNode: { prototype: analyserProto },
        AudioBuffer: { prototype: audioBufferProto },
        WebGLRenderingContext: { prototype: webglProto },
        OffscreenCanvas: undefined
    };
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    const ctx = vm.createContext(sandbox);
    return { ctx, ctx2d, htmlCanvasProto, navProto, analyserProto, audioBufferProto, webglProto, sandbox };
}

function runGuard(env, jsBody) {
    vm.runInContext(jsBody, env.ctx);
}

function readout(env) {
    return env.ctx2d.getImageData(0, 0, 8, 4);
}

let failures = 0;
function check(label, ok) {
    console.log((ok ? '  PASS ' : '  FAIL ') + label);
    if (!ok) failures++;
}

function verify(label, hostname, jsBody, expectProtected) {
    console.log('== ' + label + ' ==');
    const env = makeContext(hostname);
    runGuard(env, jsBody);

    const a = readout(env);
    const b = readout(env);
    let changed = 0, same = true, alphaOK = true, maxDelta = 0;
    for (let p = 0; p < 32; p++) {
        const i = p * 4;
        const orig = [(i*7)%256, (i+1)*7%256, (i+2)*7%256, (i+3)*7%256];
        if (a.data[i] !== orig[0] || a.data[i+1] !== orig[1] || a.data[i+2] !== orig[2]) changed++;
        if (a.data[i+3] !== orig[3]) alphaOK = false;
        for (let c = 0; c < 4; c++) {
            if (a.data[i+c] !== b.data[i+c]) same = false;
            maxDelta = Math.max(maxDelta, Math.abs(a.data[i+c] - orig[c]));
        }
    }
    if (expectProtected) {
        check('canvas RGB noise applied (' + changed + '/32 px)', changed > 0 && changed <= 32);
    } else {
        check('canvas fully untouched on excluded site', changed === 0);
    }
    check('noise deterministic across calls', same);
    check('alpha untouched', alphaOK);
    if (expectProtected) {
        check('max delta is +-1', maxDelta === 1);
    }
    check('marker is non-enumerable', Object.keys(env.sandbox).indexOf('__oszaFingerprintGuard') === -1);

    const url = env.htmlCanvasProto.toDataURL.call({ width: 8, height: 4, getContext: () => env.ctx2d });
    check('toDataURL returns a string', typeof url === 'string' && url.length > 0);

    const px = new Uint8Array(16);
    env.webglProto.readPixels(0, 0, 4, 4, 0x1908, 0x1401, px);
    check('webgl readPixels RGB perturbed', px.some((v, i) => i % 4 !== 3 && v !== 100) === expectProtected);
    check('webgl readPixels alpha untouched', px.every((v, i) => i % 4 !== 3 || v === 100));

    check('UNMASKED_VENDOR spoofed', (env.webglProto.getParameter(0x9245) !== 'REAL-37445') === expectProtected);
    check('UNMASKED_RENDERER spoofed', (env.webglProto.getParameter(0x9246) !== 'REAL-37446') === expectProtected);
    check('other getParameter values pass through', env.webglProto.getParameter(0x1F02) === 'REAL-7938');

    const fa = new Float32Array(10);
    env.analyserProto.getFloatFrequencyData(fa);
    check('float audio perturbed within tolerance', fa.every((v, i) => Math.abs(v - (-100 + i)) < 1e-3) && fa.some((v, i) => v !== -100 + i) === expectProtected);
    const fa2 = new Float32Array(10);
    env.analyserProto.getFloatFrequencyData(fa2);
    check('float audio deterministic', fa.every((v, i) => v === fa2[i]));
    const ba = new Uint8Array(10);
    env.analyserProto.getByteFrequencyData(ba);
    check('byte audio perturbed', ba.some(v => v !== 200) === expectProtected);
    const ft = new Float32Array(10);
    env.analyserProto.getFloatTimeDomainData(ft);
    check('time-domain audio perturbed', ft.some((v, i) => v !== 0.5 + i * 0.125) === expectProtected);

    const cpu = env.navProto.hardwareConcurrency;
    check('hardwareConcurrency value (' + cpu + ')', ([2, 4, 6, 8].indexOf(cpu) !== -1) === expectProtected && (expectProtected || cpu === 32));
    const mem = env.navProto.deviceMemory;
    check('deviceMemory value (' + mem + ')', ([4, 8].indexOf(mem) !== -1) === expectProtected && (expectProtected || mem === 16));

    // AudioBuffer readouts: farbled once, idempotent on repeat calls
    const ch1 = env.audioBufferProto.getChannelData.call({}, 0);
    const ch1copy = Float32Array.from(ch1);
    const ch2 = env.audioBufferProto.getChannelData.call({}, 0);
    const anyChanged = ch1.some((v, i) => v !== 0.25 + i * 0.125);
    const changedOnce = ch1.every((v, i) => v === ch2[i]);
    check('AudioBuffer getChannelData farbled once, idempotent', (anyChanged && changedOnce) === expectProtected);
    const dest = new Float32Array(16);
    env.audioBufferProto.copyFromChannel.call({}, dest, 0);
    check('AudioBuffer copyFromChannel farbled', dest.some((v, i) => v !== 0.25 + i * 0.125) === expectProtected);
    return { env, a };
}

const rA = verify('site A: sub.TestSite.example, seed 1234567890, no exclusions',
                  'sub.TestSite.example', JS_A, true);

const rB = verify('site B: evil.example.org excluded via ["*.example.org"]',
                  'evil.example.org', JS_B, false);

// excluded: canvas data must equal the pristine original
const orig = new Uint8ClampedArray(8 * 4 * 4);
for (let i = 0; i < orig.length; i++) orig[i] = (i * 7) % 256;
check('excluded site canvas fully untouched', Array.from(rB.a.data).every((v, i) => v === orig[i]));
check('excluded site vendor not spoofed', rB.env.webglProto.getParameter(0x9245) === 'REAL-37445');
check('excluded site cpu not spoofed', rB.env.navProto.hardwareConcurrency === 32);

// cross-host uniqueness (same master seed)
const envA2 = makeContext('site-one.example');
runGuard(envA2, JS_A);
const ra = readout(envA2);
const envB2 = makeContext('site-two.example');
runGuard(envB2, JS_A);
const rb = readout(envB2);
console.log('== uniqueness ==');
check('same seed, different hosts -> different noise', Array.from(ra.data).some((v, i) => v !== rb.data[i]));

// cross-profile uniqueness (same host, different seed)
const envC = makeContext('site-one.example');
runGuard(envC, JS_ALT_SEED);
const rc = readout(envC);
check('same host, different seed -> different noise', Array.from(ra.data).some((v, i) => v !== rc.data[i]));

// same host + seed on both -> identical (stability across reloads)
const envD = makeContext('site-one.example');
runGuard(envD, JS_A);
const rd = readout(envD);
check('same host + seed -> identical noise (stable identity)', Array.from(ra.data).every((v, i) => v === rd.data[i]));

console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
process.exit(failures === 0 ? 0 : 1);
'''

full = "const JS_A = %s;\nconst JS_B = %s;\nconst JS_ALT_SEED = %s;\n" % (
    json.dumps(build("sub.TestSite.example", [], 1234567890)),
    json.dumps(build("evil.example.org", ["*.example.org"], 1234567890)),
    json.dumps(build("site-one.example", [], 987654321)),
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
