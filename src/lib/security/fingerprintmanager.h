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
#ifndef FINGERPRINTMANAGER_H
#define FINGERPRINTMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include "qzcommon.h"

class QWebEngineProfile;

/*
 * Browser-fingerprint randomization ("fingerprint guard"), the
 * client-side part of the bundled security tools.
 *
 * When enabled, a small self-contained script is injected into every
 * frame at document creation, in the main world, before any page
 * script runs. It makes canvas, WebGL and audio readouts slightly but
 * deterministically noisy: the perturbation depends only on a
 * per-profile master seed, the frame host and the pixel's position on
 * the source (absolute, so overlapping readouts of one pixel agree),
 * so a site sees a stable fingerprint across reloads while different
 * sites (and different browser profiles) see different values. A
 * private instance draws its own session seed instead of the
 * profile's, so off-the-record noise cannot be linked to the normal
 * session's. The high
 * entropy WebGL vendor/renderer strings and the navigator.hardware-
 * Concurrency / deviceMemory hints are replaced with per-site-stable
 * generic values as well. Page scripts are never broken on purpose:
 * every hook falls back to the original behaviour when anything goes
 * wrong.
 *
 * Individual sites can be excluded from the protection (from the
 * padlock menu in the location bar). Exclusion entries match the
 * listed host and its subdomains; "*.domain" wildcard entries are
 * supported, like the HTTPS-Only exceptions.
 *
 * siteNoisePattern() is a C++ mirror of the guard script's
 * perturbation; the security self-test page uses it to show the
 * per-site noise of other hosts. It must stay in sync with the
 * script (siteKey/mix/perturb in kScriptTemplate) - the
 * selfTestNoiseEquivalenceTest autotest and
 * tools/security/verify_fingerprint_guard.py verify the two
 * implementations produce identical values.
 *
 * All methods run on the UI thread; nothing here is called from the
 * WebEngine IO thread.
 */
class OSZA_EXPORT FingerprintManager : public QObject
{
    Q_OBJECT

public:
    static FingerprintManager *instance();

    explicit FingerprintManager(QObject *parent = nullptr);

    // Reads the persisted configuration (enabled flag, exclusions and
    // the master seed, generated on first use) and refreshes the
    // injected script. Must be called after the web profile exists.
    void loadSettings();

    bool isEnabled() const;

    // The per-profile master seed the per-site noise is derived
    // from. Valid after loadSettings(); 0 before it.
    quint32 masterSeed() const;

    // True when the host matches an exclusion entry (the listed host,
    // any of its subdomains, or a "*.domain" wildcard entry).
    bool isExcluded(const QString &host) const;

    // Per-site opt-out, persisted immediately. The injected script is
    // refreshed so the change applies to newly loaded pages.
    void addExclusion(const QString &host);
    void removeExclusion(const QString &host);

    // Regenerates and reinserts the injected script in the current
    // web profile (no-op bookkeeping when disabled).
    void updateScript();

    // The script source for the given master seed and exclusions.
    static QString buildScriptSource(quint32 masterSeed, const QStringList &exclusions);

    // Deviation (-1, 0 or +1) the guard applies to the red channel
    // of every pixel of a tightly packed RGBA buffer on the given
    // host: the per-site noise pattern, size x size values in row
    // major order. Mirrors perturb(x, y, 0, value) of the injected
    // script; used by the security self-test page.
    static QVector<int> siteNoisePattern(quint32 masterSeed, const QString &host, int size);

private:
    static bool hostMatchesEntry(const QString &host, const QString &entry);

    bool m_enabled;
    quint32 m_masterSeed;
    QStringList m_exclusions;
};

#endif // FINGERPRINTMANAGER_H
