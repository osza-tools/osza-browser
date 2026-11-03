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
#ifndef SECURITYSETTINGSPORTER_H
#define SECURITYSETTINGSPORTER_H

#include <QString>
#include <QStringList>

#include "qzcommon.h"

class QJsonObject;

/*
 * Import and export of the security-tools settings.
 *
 * The bundled security suite (AdBlock, HTTPS-Only mode, tracking
 * parameter stripping, secure DNS, malicious site protection,
 * fingerprint protection and the Global Privacy Control signal) is
 * configured through a dozen keys in two settings groups. This class
 * serializes that configuration into one portable JSON document and
 * applies such a document back into a profile, so a hardened setup
 * can be backed up, moved between machines and profiles, or shared
 * as a recommended baseline.
 *
 * The document format ("osza-security-settings", version 1):
 *
 * {
 *   "format": "osza-security-settings",
 *   "version": 1,
 *   "exportedAt": "2026-01-31T12:00:00Z",
 *   "checksum": { "algorithm": "sha256",
 *                 "tools": "<sha-256 of the canonical tools object>" },
 *   "tools": {
 *     "adblock":                { "enabled": true },
 *     "httpsOnly":              { "enabled": true,
 *                                 "exclusions": ["legacy.example"] },
 *     "trackingParameters":     { "enabled": true },
 *     "secureDns":              { "mode": 1,
 *                                 "servers": ["https://dns.example/dns-query{?dns}"] },
 *     "threatBlock":            { "enabled": true,
 *                                 "sourceUrl": "https://..." },
 *     "fingerprintProtection":  { "enabled": true,
 *                                 "exclusions": ["bank.example"] },
 *     "globalPrivacyControl":   { "enabled": true }
 *   }
 * }
 *
 * The checksum is tamper evidence for the settings payload: it is
 * computed over the compact (no whitespace) serialization of the
 * tools object - the exact bytes an import re-derives after parsing,
 * so it pins the semantic content, not the raw file: reformatting,
 * reordering keys or writing 1.0 for 1 keeps it valid, while any
 * changed value breaks it. A document whose checksum does not match
 * was hand-edited or corrupted after it was exported; importing it is
 * refused unless the caller explicitly allows it (the UI asks first).
 * Documents without a checksum - exports of older versions and
 * intentional hand edits - import as before.
 *
 * Deliberate scope decisions:
 *
 *  - The fingerprint master seed is never exported. It is the
 *    per-profile secret that makes every user's noise unique;
 *    copying it to another machine would give two browsers the
 *    identical fingerprint, the exact opposite of the protection.
 *  - The protection counters are usage history, not settings.
 *  - Unknown tools and unknown fields are ignored on import, so
 *    documents from newer versions degrade instead of failing.
 *  - Every tool section is optional and validated on its own; a
 *    malformed section is skipped with a reason, the remaining
 *    sections still apply.
 *  - Import goes through the live manager APIs, so scripts,
 *    interceptors and engine configuration update immediately,
 *    exactly like the corresponding toggle in the dashboard.
 */
class OSZA_EXPORT SecuritySettingsPorter
{
public:
    // Identity of the exported document.
    static QString formatIdentifier();
    static int formatVersion();

    // Outcome of an import. ok is false only for fatal problems
    // (unreadable file, not JSON, wrong format, newer version, or a
    // checksum mismatch that was not explicitly allowed);
    // skippedTools then stays empty and nothing was applied.
    struct ImportResult
    {
        bool ok = false;
        QString error;
        int appliedTools = 0;
        QStringList skippedTools; // "tool: reason" entries

        // True when the document carried a checksum that did not
        // match its tools section. With ChecksumPolicy::Reject the
        // import was refused (ok is false); with Allow it went
        // through after the caller asked the user.
        bool checksumMismatch = false;
    };

    // State of the document's checksum field.
    enum class ChecksumState
    {
        NoChecksum, // the document does not carry one (older exports)
        Valid,      // matches the tools section
        Mismatch    // wrong, or present but malformed
    };

    // What importFromFile()/applyDocument() do when the checksum does
    // not match. Reject is the default: a mismatch is fatal. Allow is
    // for the UI path after the user explicitly confirmed importing a
    // hand-edited file.
    enum class ChecksumPolicy
    {
        Reject,
        Allow
    };

    // Snapshot of the current configuration. Reads the live managers
    // (not stale settings) wherever a manager owns the state.
    static QJsonObject buildDocument();

    // Name of the hash used for the checksum field.
    static QString checksumAlgorithm();

    // Computes the checksum of a tools object: the SHA-256 of its
    // compact (canonical) JSON serialization, as lowercase hex.
    static QString checksumForTools(const QJsonObject &tools);

    // Checks the checksum field of a document against its tools
    // section. A malformed checksum field counts as a mismatch -
    // fail safe, never fail open.
    static ChecksumState checkChecksum(const QJsonObject &document);

    // Serializes buildDocument() and writes it atomically. Returns
    // false and fills error when the file cannot be written.
    static bool exportToFile(const QString &path, QString *error = nullptr);

    // Reads, validates and applies a document in one step. A checksum
    // mismatch is fatal unless policy allows it.
    static ImportResult importFromFile(const QString &path,
                                       ChecksumPolicy policy = ChecksumPolicy::Reject);

    // Validates and applies an already-parsed document. The same
    // rules as importFromFile(); exposed for the autotests and the
    // recommended-baseline presets.
    static ImportResult applyDocument(const QJsonObject &document,
                                      ChecksumPolicy policy = ChecksumPolicy::Reject);

    // Checks the format identifier and version only. Returns false
    // and fills error when the document cannot be an Osza security
    // settings file at all.
    static bool validateDocumentHeader(const QJsonObject &document, QString *error = nullptr);

private:
    SecuritySettingsPorter() = default;
};

#endif // SECURITYSETTINGSPORTER_H
