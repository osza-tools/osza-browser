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
    // (unreadable file, not JSON, wrong format, newer version);
    // skippedTools then stays empty and nothing was applied.
    struct ImportResult
    {
        bool ok = false;
        QString error;
        int appliedTools = 0;
        QStringList skippedTools; // "tool: reason" entries
    };

    // Snapshot of the current configuration. Reads the live managers
    // (not stale settings) wherever a manager owns the state.
    static QJsonObject buildDocument();

    // Serializes buildDocument() and writes it atomically. Returns
    // false and fills error when the file cannot be written.
    static bool exportToFile(const QString &path, QString *error = nullptr);

    // Reads, validates and applies a document in one step.
    static ImportResult importFromFile(const QString &path);

    // Validates and applies an already-parsed document. The same
    // rules as importFromFile(); exposed for the autotests.
    static ImportResult applyDocument(const QJsonObject &document);

    // Checks the format identifier and version only. Returns false
    // and fills error when the document cannot be an Osza security
    // settings file at all.
    static bool validateDocumentHeader(const QJsonObject &document, QString *error = nullptr);

private:
    SecuritySettingsPorter() = default;
};

#endif // SECURITYSETTINGSPORTER_H
