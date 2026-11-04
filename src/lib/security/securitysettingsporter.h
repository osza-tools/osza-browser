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
 *   "preset": "recommended-baseline",       // optional provenance
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
 * Imports are informed, not blind: previewDocument() reports, per
 * tool and per field, what a document would change in this profile
 * (and what it would skip, with the reason) without touching
 * anything, so the UI can show a diff before the first setting
 * moves. For the site-exception lists the preview also names the
 * entries it would clear and the entries it would add - the sites
 * whose treatment changes are the point of the decision, not the
 * raw lists on either side of the arrow. The preview is computed by
 * the very same validation the import applies - there is no second,
 * weaker code path that could disagree with the apply step.
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
 *  - A preview can predict every skip reason except one: the secure
 *    DNS engine may still reject a configuration at apply time (the
 *    preview shows the values that would be persisted; the import
 *    summary reports the rejection, and the engine keeps running
 *    with system DNS).
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

    // One field of one tool that an import would change: the human
    // readable current live value against the value after the
    // import. Values are formatted for display; the stable keys
    // (tool, field) are the ones toolDisplayName() and
    // fieldDisplayName() translate.
    struct PreviewChange
    {
        QString tool;          // stable tool key, e.g. "httpsOnly"
        QString field;         // stable field key, e.g. "exclusions"
        QString currentValue;  // live value, for display
        QString nextValue;     // value after the import, for display

        // For the site-exception lists only: the entries this import
        // clears (in the current live list, gone after the import)
        // and the entries it newly adds, each in the order of the
        // list it comes from. Compared the way the tools themselves
        // match hosts - case-insensitively - so an entry that only
        // changes case is neither cleared nor added, and a duplicate
        // entry is reported once. Computed here, once, so every
        // consumer shows the same one-line summary without parsing
        // display strings. Empty for non-list fields and for changes
        // that clear and add nothing.
        QStringList clearedEntries;
        QStringList addedEntries;
    };

    // What a document would do to this profile, without doing it.
    // ok is false only when the document cannot be imported at all
    // (wrong format, newer version, malformed tools container);
    // changes/skippedTools/unchangedTools are then empty.
    struct Preview
    {
        bool ok = false;
        QString error;

        // State of the document's checksum field. A mismatch does
        // not stop the preview - the point is to judge a changed
        // file on its content before deciding - but the import still
        // needs the explicit ChecksumPolicy::Allow.
        ChecksumState checksum = ChecksumState::NoChecksum;

        // Provenance the document states about itself: the id of the
        // built-in preset it was saved from (the "preset" field a
        // preset export carries), empty when the document does not
        // name one. Reported verbatim, known or not, so every import
        // UI can say where a file came from; whether the id is one
        // of the built-ins is the preset catalog's judgment
        // (SecurityPresets::presetById), not the porter's.
        QString presetId;

        int configuredTools = 0;    // sections the document carries
        QList<PreviewChange> changes;         // only actual differences
        QStringList skippedTools;   // "tool: reason", like ImportResult
        QStringList unchangedTools; // tool keys without a section
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

    // Reads a file and parses it as JSON, without validating or
    // applying anything. The companion of previewDocument(): load
    // first, show the diff, then applyDocument() the very same object
    // the user has seen. Returns false and fills error when the file
    // does not exist, cannot be read or is not a JSON object.
    static bool loadDocument(const QString &path, QJsonObject *document, QString *error = nullptr);

    // Computes what the document would change in this profile, tool
    // by tool and field by field, through the same validation an
    // import applies. Never touches any manager or setting.
    static Preview previewDocument(const QJsonObject &document);

    // Serializes buildDocument() and writes it atomically. Returns
    // false and fills error when the file cannot be written.
    static bool exportToFile(const QString &path, QString *error = nullptr);

    // Writes the given document (for example one of the built-in
    // presets) as a settings file, atomically. The output is a
    // regular export of the document's tools section: fresh
    // exportedAt stamp, fresh checksum - so a preset saved from the
    // picker is tamper-evident exactly like a live export and
    // imports on any profile without the mismatch warning. A
    // "preset" provenance field travels with the file when the
    // document carries one. Returns false and fills error when the
    // document is not an Osza security settings document or the
    // file cannot be written; a failed write never destroys an
    // existing file.
    static bool exportDocumentToFile(const QJsonObject &document,
                                     const QString &path,
                                     QString *error = nullptr);

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

    // Translated, human-readable name of a tool key ("httpsOnly" ->
    // "HTTPS-Only mode"); unknown keys come back unchanged. Shared
    // by the import preview UIs so a tool is called the same thing
    // everywhere.
    static QString toolDisplayName(const QString &tool);

    // Translated, human-readable name of a field of a tool
    // ("httpsOnly", "exclusions" -> "Site exceptions"); unknown
    // fields come back unchanged.
    static QString fieldDisplayName(const QString &tool, const QString &field);

    // The one-line summaries of a site-exception change, ready to
    // show under the field in a diff: "Clears the exception for:
    // bank.example, shop.example" and "Adds an exception for:
    // legacy.example" - at most one line per direction, cleared
    // first, translated here so every preview UI says the same
    // thing. Empty for changes that neither clear nor add anything
    // and for every change that is not a site-exception list.
    static QStringList exceptionSummaryLines(const PreviewChange &change);

private:
    SecuritySettingsPorter() = default;
};

#endif // SECURITYSETTINGSPORTER_H
