/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2026 Osza Tools contributors
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#include "fingerprintmanager.h"
#include "mainapplication.h"
#include "settings.h"
#include "webpage.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QRandomGenerator>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>

Q_GLOBAL_STATIC(FingerprintManager, qz_fingerprint_manager)

namespace {

// Name of the injected QWebEngineScript. Scripts are looked up and
// removed by name, so it must stay unique in the profile.
const char kScriptName[] = "_osza_fingerprint_guard";

/*
 * The guard script. It runs in the main world at document creation in
 * every frame, before any page script, so the patched prototypes are
 * what the page (and every fingerprinting script) ends up calling.
 *
 * Design constraints, in order: never break the page, stay
 * deterministic for a given site (a fingerprint that changes on every
 * reload is itself fingerprintable), and differ between sites and
 * between browser profiles. Everything is therefore derived from
 * three inputs only: the per-profile master seed, the frame host and
 * the pixel position.
 */
const char kScriptTemplate[] = R"JS((function () {
    'use strict';

    // Osza Browser fingerprint guard.

    try {
        if (window.__oszaFingerprintGuard) {
            return;
        }
        Object.defineProperty(window, '__oszaFingerprintGuard', {
            value: 1,
            writable: false,
            enumerable: false,
            configurable: false
        });
    } catch (e) {
        return;
    }

    var EXCLUSIONS = %EXCLUSIONS%;
    var MASTER_SEED = %MASTER_SEED% >>> 0;

    function hostExcluded() {
        try {
            var host = location.hostname.toLowerCase();
            if (!host) {
                return false;
            }
            for (var i = 0; i < EXCLUSIONS.length; i++) {
                var entry = EXCLUSIONS[i];
                if (!entry) {
                    continue;
                }
                if (entry.charCodeAt(0) === 42) {
                    if (host.endsWith(entry.slice(1).toLowerCase())) {
                        return true;
                    }
                    continue;
                }
                if (host === entry.toLowerCase() || host.endsWith('.' + entry.toLowerCase())) {
                    return true;
                }
            }
        } catch (e) {
        }
        return false;
    }

    if (hostExcluded()) {
        return;
    }

    // Per-site key: FNV-1a over the host name, seeded with the master seed.
    function siteKey(host) {
        var h = MASTER_SEED;
        var name = String(host).toLowerCase();
        for (var i = 0; i < name.length; i++) {
            h ^= name.charCodeAt(i);
            h = Math.imul(h, 0x01000193);
        }
        return h >>> 0;
    }

    var SITE_KEY = siteKey(location.hostname);

    // MurmurHash3 finalizer steps, used as the mixing primitive below.
    function mix(seed, value) {
        var h = (seed ^ Math.imul(value, 0x85EBCA77)) >>> 0;
        h ^= h >>> 13;
        h = Math.imul(h, 0xC2B2AE3D);
        h ^= h >>> 16;
        return h >>> 0;
    }

    // Deterministic per-pixel perturbation of one channel: -1, 0 or +1.
    // Invisible to the eye, but it changes every digest of the readout.
    function perturb(x, y, channel, value) {
        var h = mix(SITE_KEY, Math.imul(x + 1, 0x9E3779B1) ^ Math.imul(y + 1, 0x85EBCA77) ^ Math.imul(channel, 0x27D4EB2F));
        var out = value + ((h % 3) - 1);
        return out < 0 ? 0 : (out > 255 ? 255 : out);
    }

    // Applies the per-site noise to the RGB channels of a tightly packed
    // RGBA buffer (Uint8Array / Uint8ClampedArray). Alpha is untouched.
    // The noise is anchored to the pixel's absolute position on the
    // source - the readout's own origin (sx, sy of getImageData, x, y of
    // readPixels) rides along - so every view of one underlying pixel
    // carries the same perturbation: reading the same canvas whole or
    // through overlapping windows can never disagree, which is exactly
    // what a fingerprinting page checks first. A (0, 0)-anchored readout
    // sees the same values a region-local walk would have produced.
    function farbleRgbData(data, width, originX, originY) {
        var pixels = (data.length / 4) | 0;
        for (var p = 0; p < pixels; p++) {
            var x = originX + (p % width);
            var y = originY + ((p / width) | 0);
            var i = p * 4;
            data[i] = perturb(x, y, 0, data[i]);
            data[i + 1] = perturb(x, y, 1, data[i + 1]);
            data[i + 2] = perturb(x, y, 2, data[i + 2]);
        }
    }

    // Canvas 2D pixel readouts.
    var ctx2dProto = window.CanvasRenderingContext2D && window.CanvasRenderingContext2D.prototype;
    if (ctx2dProto && typeof ctx2dProto.getImageData === 'function') {
        var originalGetImageData = ctx2dProto.getImageData;
        ctx2dProto.getImageData = function () {
            var imageData = originalGetImageData.apply(this, arguments);
            try {
                if (imageData && imageData.data && imageData.width > 0 && imageData.height > 0) {
                    // The rectangle's own origin anchors the noise: the
                    // same source pixel read through any window of it is
                    // perturbed identically. (| 0 is the ToInt32 the
                    // native bindings would apply to these coordinates
                    // anyway; a missing argument anchors at 0.)
                    farbleRgbData(imageData.data, imageData.width, arguments[0] | 0, arguments[1] | 0);
                }
            } catch (e) {
            }
            return imageData;
        };
    }

    // Draws a canvas onto a fresh 2D canvas (works for 2D and WebGL
    // sources) and round-trips the pixels through the patched
    // getImageData, producing a copy that differs from the original by
    // the same deterministic per-site noise. Returns null whenever
    // anything unexpected happens; callers then fall back to the
    // original behaviour.
    function makeFarbledCopy(source) {
        try {
            var width = source.width;
            var height = source.height;
            if (!width || !height) {
                return null;
            }
            var copy;
            if (typeof OffscreenCanvas !== 'undefined' && source instanceof OffscreenCanvas) {
                copy = new OffscreenCanvas(width, height);
            } else {
                copy = document.createElement('canvas');
                copy.width = width;
                copy.height = height;
            }
            var ctx = copy.getContext('2d');
            if (!ctx) {
                return null;
            }
            ctx.drawImage(source, 0, 0);
            var image = ctx.getImageData(0, 0, width, height);
            ctx.putImageData(image, 0, 0);
            return copy;
        } catch (e) {
            return null;
        }
    }

    // Canvas serialization readouts (HTMLCanvasElement).
    var canvasProto = window.HTMLCanvasElement && window.HTMLCanvasElement.prototype;
    if (canvasProto) {
        if (typeof canvasProto.toDataURL === 'function') {
            var originalToDataURL = canvasProto.toDataURL;
            canvasProto.toDataURL = function () {
                var copy = makeFarbledCopy(this);
                if (copy) {
                    return originalToDataURL.apply(copy, arguments);
                }
                return originalToDataURL.apply(this, arguments);
            };
        }
        if (typeof canvasProto.toBlob === 'function') {
            var originalToBlob = canvasProto.toBlob;
            canvasProto.toBlob = function () {
                var copy = makeFarbledCopy(this);
                if (copy) {
                    return originalToBlob.apply(copy, arguments);
                }
                return originalToBlob.apply(this, arguments);
            };
        }
    }

    // Canvas serialization readouts (OffscreenCanvas).
    if (typeof OffscreenCanvas !== 'undefined' && OffscreenCanvas.prototype) {
        var offscreenProto = OffscreenCanvas.prototype;
        if (typeof offscreenProto.convertToBlob === 'function') {
            var originalConvertToBlob = offscreenProto.convertToBlob;
            offscreenProto.convertToBlob = function () {
                var copy = makeFarbledCopy(this);
                if (copy) {
                    return originalConvertToBlob.apply(copy, arguments);
                }
                return originalConvertToBlob.apply(this, arguments);
            };
        }
        if (typeof offscreenProto.toDataURL === 'function') {
            var originalOffscreenToDataURL = offscreenProto.toDataURL;
            offscreenProto.toDataURL = function () {
                var copy = makeFarbledCopy(this);
                if (copy) {
                    return originalOffscreenToDataURL.apply(copy, arguments);
                }
                return originalOffscreenToDataURL.apply(this, arguments);
            };
        }
    }

    // WebGL: pixel readouts and the high-entropy GPU strings.
    var GL_RGBA = 0x1908;
    var GL_UNSIGNED_BYTE = 0x1401;
    var GL_UNMASKED_VENDOR = 0x9245;
    var GL_UNMASKED_RENDERER = 0x9246;

    // Generic, per-site-stable values instead of the real GPU names.
    var VENDORS = ['Intel Inc.', 'Apple', 'ARM'];
    var RENDERERS = ['Intel Iris OpenGL Engine', 'Apple GPU', 'Mali-G78'];

    function pickFrom(list, salt) {
        return list[mix(SITE_KEY, salt) % list.length];
    }

    function patchWebgl(proto) {
        if (!proto) {
            return;
        }
        try {
            if (typeof proto.readPixels === 'function') {
                var originalReadPixels = proto.readPixels;
                proto.readPixels = function (x, y, width, height, format, type, pixels) {
                    originalReadPixels.apply(this, arguments);
                    try {
                        if (format === GL_RGBA && type === GL_UNSIGNED_BYTE && pixels && width > 0 &&
                            (pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray)) {
                            // Anchored like getImageData: the readout's
                            // framebuffer origin rides along, so the same
                            // pixel is perturbed identically however the
                            // readout window is placed.
                            farbleRgbData(pixels, width, x | 0, y | 0);
                        }
                    } catch (e) {
                    }
                };
            }
        } catch (e) {
        }
        try {
            if (typeof proto.getParameter === 'function') {
                var originalGetParameter = proto.getParameter;
                proto.getParameter = function (pname) {
                    if (pname === GL_UNMASKED_VENDOR) {
                        return pickFrom(VENDORS, 0x51ED270B);
                    }
                    if (pname === GL_UNMASKED_RENDERER) {
                        return pickFrom(RENDERERS, 0x2545F491);
                    }
                    return originalGetParameter.apply(this, arguments);
                };
            }
        } catch (e) {
        }
    }

    patchWebgl(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
    patchWebgl(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype);

    // Audio fingerprinting through AnalyserNode readouts.
    function patchAnalyserMethod(proto, name, byteData) {
        if (!proto || typeof proto[name] !== 'function') {
            return;
        }
        var original = proto[name];
        proto[name] = function () {
            original.apply(this, arguments);
            try {
                var array = arguments[0];
                if (array && array.length) {
                    for (var i = 0; i < array.length; i++) {
                        if (byteData) {
                            var out = array[i] + ((mix(SITE_KEY, Math.imul(i + 1, 0x9E3779B1)) % 3) - 1);
                            array[i] = out < 0 ? 0 : (out > 255 ? 255 : out);
                        } else if (isFinite(array[i]) && array[i] !== 0) {
                            // Magnitude-relative noise stays representable
                            // in a Float32Array and is far below the
                            // threshold of hearing.
                            array[i] = array[i] * (1 + ((mix(SITE_KEY, Math.imul(i + 1, 0x85EBCA77)) % 3) - 1) / 1e6);
                        }
                    }
                }
            } catch (e) {
            }
        };
    }

    if (window.AnalyserNode && window.AnalyserNode.prototype) {
        patchAnalyserMethod(window.AnalyserNode.prototype, 'getFloatFrequencyData', false);
        patchAnalyserMethod(window.AnalyserNode.prototype, 'getByteFrequencyData', true);
        patchAnalyserMethod(window.AnalyserNode.prototype, 'getFloatTimeDomainData', false);
        patchAnalyserMethod(window.AnalyserNode.prototype, 'getByteTimeDomainData', true);
    }

    // AudioBuffer readouts - the path taken by the classic
    // OfflineAudioContext fingerprint. getChannelData returns the very
    // same view object on every call for one channel, so already
    // farbled views are marked and left alone (hot read loops would
    // otherwise accumulate noise); copyFromChannel always overwrites
    // its destination first, so it can be farbled on every call.
    function farbleAudioArray(array) {
        for (var i = 0; i < array.length; i++) {
            if (isFinite(array[i]) && array[i] !== 0) {
                array[i] = array[i] * (1 + ((mix(SITE_KEY, Math.imul(i + 1, 0x85EBCA77)) % 3) - 1) / 1e6);
            }
        }
    }

    if (window.AudioBuffer && window.AudioBuffer.prototype) {
        var audioBufferProto = window.AudioBuffer.prototype;
        var farbledViews = new WeakSet();
        if (typeof audioBufferProto.getChannelData === 'function') {
            var originalGetChannelData = audioBufferProto.getChannelData;
            audioBufferProto.getChannelData = function () {
                var channel = originalGetChannelData.apply(this, arguments);
                try {
                    if (channel && channel.length && !farbledViews.has(channel)) {
                        farbledViews.add(channel);
                        farbleAudioArray(channel);
                    }
                } catch (e) {
                }
                return channel;
            };
        }
        if (typeof audioBufferProto.copyFromChannel === 'function') {
            var originalCopyFromChannel = audioBufferProto.copyFromChannel;
            audioBufferProto.copyFromChannel = function () {
                originalCopyFromChannel.apply(this, arguments);
                try {
                    if (arguments[0] && arguments[0].length) {
                        farbleAudioArray(arguments[0]);
                    }
                } catch (e) {
                }
            };
        }
    }

    // Cheap high-entropy JS hints, replaced with per-site-stable values.
    var CPU_VALUES = [2, 4, 6, 8];
    var MEMORY_VALUES = [4, 8];

    function spoofNavigatorProperty(name, values, salt) {
        try {
            if (!(window.Navigator && window.Navigator.prototype && (name in window.Navigator.prototype))) {
                return;
            }
            Object.defineProperty(window.Navigator.prototype, name, {
                get: function () {
                    return values[mix(SITE_KEY, salt) % values.length];
                },
                configurable: true,
                enumerable: true
            });
        } catch (e) {
        }
    }

    spoofNavigatorProperty('hardwareConcurrency', CPU_VALUES, 0x68BC21EB);
    spoofNavigatorProperty('deviceMemory', MEMORY_VALUES, 0x3C6EF372);
})();)JS";

} // namespace

FingerprintManager::FingerprintManager(QObject *parent)
    : QObject(parent)
    , m_enabled(true)
    , m_masterSeed(0)
    , m_exclusions()
{
}

FingerprintManager *FingerprintManager::instance()
{
    return qz_fingerprint_manager();
}

void FingerprintManager::loadSettings()
{
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    m_enabled = settings.value(QSL("FingerprintProtection"), true).toBool();
    m_exclusions = settings.value(QSL("FingerprintExclusions"), QStringList()).toStringList();
    settings.endGroup();

    settings.beginGroup(QSL("Security-Tools"));
    uint seed = 0;
    if (mApp->isPrivate()) {
        // Off the record: the profile's seed is neither read nor
        // written - a private instance shares the profile's settings
        // file, and noise drawn from that seed would be the normal
        // session's noise, letting a tracker merge the two by the
        // fingerprints they show the same site. Instead the session
        // draws its own seed, once, and keeps it: the noise is as
        // stable within the private session as it is everywhere,
        // and unique against the profile and every other private
        // session.
        if (m_masterSeed == 0) {
            m_masterSeed = QRandomGenerator::system()->generate();
            if (m_masterSeed == 0) {
                m_masterSeed = 1;
            }
        }
        seed = m_masterSeed;
    } else {
        seed = settings.value(QSL("FingerprintSeed"), 0).toUInt();
        if (seed == 0) {
            // First use: derive the per-profile master seed. It is what
            // makes every profile's noise unique, so trackers cannot
            // merge fingerprints across users.
            seed = QRandomGenerator::system()->generate();
            if (seed == 0) {
                seed = 1;
            }
            settings.setValue(QSL("FingerprintSeed"), seed);
        }
        m_masterSeed = seed;
    }
    settings.endGroup();

    updateScript();
}

bool FingerprintManager::isEnabled() const
{
    return m_enabled;
}

quint32 FingerprintManager::masterSeed() const
{
    return m_masterSeed;
}

bool FingerprintManager::isExcluded(const QString &host) const
{
    const QString normalized = host.trimmed().toLower();

    if (normalized.isEmpty()) {
        return false;
    }

    for (const QString &entry : m_exclusions) {
        if (hostMatchesEntry(normalized, entry)) {
            return true;
        }
    }

    return false;
}

void FingerprintManager::addExclusion(const QString &host)
{
    const QString trimmed = host.trimmed().toLower();

    if (trimmed.isEmpty()) {
        return;
    }

    if (!m_exclusions.contains(trimmed, Qt::CaseInsensitive)) {
        m_exclusions.append(trimmed);
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("FingerprintExclusions"), m_exclusions);
    settings.endGroup();

    updateScript();
}

void FingerprintManager::removeExclusion(const QString &host)
{
    const QString trimmed = host.trimmed().toLower();

    if (trimmed.isEmpty()) {
        return;
    }

    for (int i = m_exclusions.size() - 1; i >= 0; --i) {
        if (m_exclusions.at(i).trimmed().compare(trimmed, Qt::CaseInsensitive) == 0) {
            m_exclusions.removeAt(i);
        }
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("FingerprintExclusions"), m_exclusions);
    settings.endGroup();

    updateScript();
}

void FingerprintManager::updateScript()
{
    QWebEngineProfile *profile = mApp->webProfile();

    if (!profile) {
        return;
    }

    const QString name = QString::fromLatin1(kScriptName);

    for (const QWebEngineScript &oldScript : profile->scripts()->find(name)) {
        profile->scripts()->remove(oldScript);
    }

    if (!m_enabled) {
        return;
    }

    QWebEngineScript script;
    script.setName(name);
    script.setInjectionPoint(QWebEngineScript::DocumentCreation);
    script.setWorldId(WebPage::UnsafeJsWorld);
    script.setRunsOnSubFrames(true);
    script.setSourceCode(buildScriptSource(m_masterSeed, m_exclusions));
    profile->scripts()->insert(script);
}

namespace {

/*
 * C++ mirrors of the guard script's per-site noise derivation
 * (siteKey, mix and perturb in kScriptTemplate). They reproduce the
 * JavaScript arithmetic exactly: every operation runs on 32-bit
 * unsigned values, so Math.imul's int32 multiply and the >>> shifts
 * are plain uint32 arithmetic here. Keep in sync with the script.
 */
quint32 mirrorSiteKey(quint32 masterSeed, const QString &host)
{
    const QString name = host.toLower();
    quint32 h = masterSeed;

    for (const QChar &c : name) {
        h ^= static_cast<quint32>(c.unicode());
        h *= 0x01000193u;
    }

    return h;
}

quint32 mirrorMix(quint32 seed, quint32 value)
{
    quint32 h = seed ^ (value * 0x85EBCA77u);
    h ^= h >> 13;
    h *= 0xC2B2AE3Du;
    h ^= h >> 16;
    return h;
}

int mirrorPerturbDeviation(quint32 siteKey, int x, int y, int channel)
{
    const quint32 value = static_cast<quint32>(x + 1) * 0x9E3779B1u
        ^ static_cast<quint32>(y + 1) * 0x85EBCA77u
        ^ static_cast<quint32>(channel) * 0x27D4EB2Fu;
    const quint32 h = mirrorMix(siteKey, value);
    return static_cast<int>(h % 3) - 1;
}

} // namespace

QVector<int> FingerprintManager::siteNoisePattern(quint32 masterSeed, const QString &host, int size)
{
    QVector<int> pattern;

    if (size <= 0) {
        return pattern;
    }

    pattern.reserve(size * size);

    const quint32 siteKey = mirrorSiteKey(masterSeed, host);

    // Row-major walk of a tightly packed RGBA buffer, exactly like
    // farbleRgbData() in the guard script for a (0, 0)-anchored readout:
    // x = p % width, y = p / width. (The script anchors the noise to
    // absolute pixel positions by passing the readout's own origin into
    // farbleRgbData(); the tiles this mirror serves and the self-test
    // page reads are all (0, 0)-anchored, so the walk stays the one
    // comparison both sides pin.)
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            pattern.append(mirrorPerturbDeviation(siteKey, x, y, 0));
        }
    }

    return pattern;
}

QString FingerprintManager::buildScriptSource(quint32 masterSeed, const QStringList &exclusions)
{
    QJsonArray array;

    for (const QString &entry : exclusions) {
        const QString trimmed = entry.trimmed();

        if (!trimmed.isEmpty()) {
            array.append(trimmed);
        }
    }

    const QString exclusionsJson = QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));

    QString source = QString::fromLatin1(kScriptTemplate);
    source.replace(QLatin1String("%EXCLUSIONS%"), exclusionsJson);
    source.replace(QLatin1String("%MASTER_SEED%"), QString::number(masterSeed));
    return source;
}

bool FingerprintManager::hostMatchesEntry(const QString &host, const QString &entry)
{
    const QString trimmed = entry.trimmed();

    if (trimmed.isEmpty() || host.isEmpty()) {
        return false;
    }

    // Wildcard pattern: *.example.com matches every subdomain.
    if (trimmed.startsWith(QSL("*"))) {
        return host.endsWith(trimmed.mid(1), Qt::CaseInsensitive);
    }

    // Exact host or any subdomain of the entry: example.com matches
    // example.com and www.example.com.
    return host.compare(trimmed, Qt::CaseInsensitive) == 0
        || host.endsWith(QSL(".") + trimmed, Qt::CaseInsensitive);
}
