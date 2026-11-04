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
#include "securitysettingsporter.h"
#include "adblockmanager.h"
#include "dnsoverhttpsmanager.h"
#include "fingerprintmanager.h"
#include "gpcmanager.h"
#include "httpsonlyinterceptor.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "settings.h"
#include "threatblockmanager.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QUrl>

namespace {

// Translate through the shared "SecuritySettingsPorter" context; the
// class is a static utility and has no QObject of its own (the same
// pattern as QzTools).
inline QString porterTr(const char *source)
{
    return QCoreApplication::translate("SecuritySettingsPorter", source);
}

QStringList sanitizeHostList(const QStringList &hosts)
{
    QStringList result;

    for (const QString &host : hosts) {
        const QString trimmed = host.trimmed();
        if (!trimmed.isEmpty()) {
            result.append(trimmed);
        }
    }

    return result;
}

QStringList sanitizeTemplateList(const QStringList &templates)
{
    QStringList result;

    for (const QString &entry : templates) {
        const QString trimmed = entry.trimmed();
        if (!trimmed.isEmpty()) {
            result.append(trimmed);
        }
    }

    return result;
}

// A blocklist source is accepted under the same rule the downloader
// applies later: parsed with a plain QUrl (no fromUserInput
// leniency), it must be valid and use an http(s) or file scheme.
bool isValidThreatSource(const QString &url)
{
    const QUrl parsed = QUrl(url.trimmed());

    if (!parsed.isValid()) {
        return false;
    }

    const QString scheme = parsed.scheme();
    return scheme == QSL("https") || scheme == QSL("http") || scheme == QSL("file");
}

bool boolFieldValue(const QJsonObject &tool, bool *ok)
{
    const QJsonValue value = tool.value(QSL("enabled"));
    if (!value.isBool()) {
        *ok = false;
        return false;
    }
    *ok = true;
    return value.toBool();
}

QStringList stringListFieldValue(const QJsonObject &tool, bool *ok)
{
    const QJsonValue value = tool.value(QSL("exclusions"));
    if (!value.isArray()) {
        *ok = false;
        return {};
    }
    QStringList result;
    const QJsonArray array = value.toArray();
    for (const QJsonValue &entry : array) {
        if (!entry.isString()) {
            *ok = false;
            return {};
        }
        result.append(entry.toString());
    }
    *ok = true;
    return result;
}

// Parsed, validated intent for one tool section. buildPlans() is the
// single validation path: applyDocument() applies what it computes,
// previewDocument() reports what it computes, so a preview can never
// drift from what the import actually does. One plan exists for every
// known tool, in the fixed order the sections are applied in.
struct ToolPlan
{
    QString key;          // stable section name, e.g. "httpsOnly"
    bool present = false; // the document carries something for this tool
    bool apply = false;   // validation passed and this build can use it
    QString reason;       // skip reason when present && !apply

    bool enabled = false;          // the "enabled" field (every tool but secureDns)
    QStringList exclusions;        // httpsOnly / fingerprintProtection; the
                                   // effective list after the import - a
                                   // missing field resets it, like the apply step
    bool statedExclusions = false; // the document stated the field itself
    DnsOverHttpsManager::Mode mode = DnsOverHttpsManager::Disabled; // secureDns
    QStringList servers;           // secureDns; sanitized
    QString sourceUrl;             // threatBlock; the effective source after the
                                   // import - a missing field keeps the current one
    bool statedSourceUrl = false;  // the document stated the field itself
};

QList<ToolPlan> buildPlans(const QJsonObject &tools)
{
    QList<ToolPlan> plans;

    // AdBlock
    {
        ToolPlan plan;
        plan.key = QSL("adblock");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            plan.enabled = boolFieldValue(tool, &fieldOk);
            if (fieldOk) {
                plan.apply = true;
            } else {
                plan.reason = porterTr("the enabled field is missing or not a boolean");
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // HTTPS-Only mode
    {
        ToolPlan plan;
        plan.key = QSL("httpsOnly");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();

            bool enabledOk = false;
            plan.enabled = boolFieldValue(tool, &enabledOk);

            bool exclusionsOk = true;
            QStringList exclusions;
            if (tool.contains(QSL("exclusions"))) {
                plan.statedExclusions = true;
                exclusions = stringListFieldValue(tool, &exclusionsOk);
            }

            if (enabledOk && exclusionsOk) {
                plan.apply = true;
                plan.exclusions = sanitizeHostList(exclusions);
            } else {
                plan.reason = porterTr("a field is missing or has the wrong type");
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // Tracking parameter stripping
    {
        ToolPlan plan;
        plan.key = QSL("trackingParameters");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            plan.enabled = boolFieldValue(tool, &fieldOk);
            if (fieldOk) {
                plan.apply = true;
            } else {
                plan.reason = porterTr("the enabled field is missing or not a boolean");
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // Secure DNS
    {
        ToolPlan plan;
        plan.key = QSL("secureDns");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();

            const QJsonValue modeValue = tool.value(QSL("mode"));
            const QJsonValue serversValue = tool.value(QSL("servers"));

            bool fieldOk = modeValue.isDouble()
                && modeValue.toInt() >= DnsOverHttpsManager::Disabled
                && modeValue.toInt() <= DnsOverHttpsManager::SecureOnly;

            QStringList servers;
            if (fieldOk && serversValue.isArray()) {
                const QJsonArray array = serversValue.toArray();
                for (const QJsonValue &entry : array) {
                    if (!entry.isString()) {
                        fieldOk = false;
                        break;
                    }
                    servers.append(entry.toString());
                }
            } else if (fieldOk) {
                fieldOk = false;
            }

            if (!fieldOk) {
                plan.reason = porterTr("a field is missing or has the wrong type");
            } else {
                plan.mode = static_cast<DnsOverHttpsManager::Mode>(modeValue.toInt());
                plan.servers = sanitizeTemplateList(servers);

                if (!DnsOverHttpsManager::isSupported()) {
                    plan.reason = porterTr("this build cannot use secure DNS");
                } else if (plan.mode != DnsOverHttpsManager::Disabled && plan.servers.isEmpty()) {
                    plan.reason = porterTr("a secure mode needs at least one server");
                } else {
                    // Whether the engine accepts the configuration is
                    // only known at apply time; everything up to that
                    // point is settled here, and identically for the
                    // preview.
                    plan.apply = true;
                }
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // Malicious site protection
    {
        ToolPlan plan;
        plan.key = QSL("threatBlock");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();

            const QJsonValue enabledValue = tool.value(QSL("enabled"));
            const QJsonValue sourceValue = tool.value(QSL("sourceUrl"));

            const bool hasSource = tool.contains(QSL("sourceUrl"));
            const QString source = sourceValue.toString();

            if (!enabledValue.isBool() || (hasSource && (!sourceValue.isString() || !isValidThreatSource(source)))) {
                plan.reason = porterTr("a field is missing or has the wrong type");
            } else {
                plan.apply = true;
                plan.enabled = enabledValue.toBool();
                plan.statedSourceUrl = hasSource;
                if (hasSource) {
                    plan.sourceUrl = source.trimmed();
                }
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // Fingerprint protection
    {
        ToolPlan plan;
        plan.key = QSL("fingerprintProtection");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();

            bool enabledOk = false;
            plan.enabled = boolFieldValue(tool, &enabledOk);

            bool exclusionsOk = true;
            QStringList exclusions;
            if (tool.contains(QSL("exclusions"))) {
                plan.statedExclusions = true;
                exclusions = stringListFieldValue(tool, &exclusionsOk);
            }

            if (enabledOk && exclusionsOk) {
                plan.apply = true;
                plan.exclusions = sanitizeHostList(exclusions);
            } else {
                plan.reason = porterTr("a field is missing or has the wrong type");
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    // Global Privacy Control
    {
        ToolPlan plan;
        plan.key = QSL("globalPrivacyControl");

        const QJsonValue value = tools.value(plan.key);
        plan.present = !value.isUndefined();

        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            plan.enabled = boolFieldValue(tool, &fieldOk);
            if (fieldOk) {
                plan.apply = true;
            } else {
                plan.reason = porterTr("the enabled field is missing or not a boolean");
            }
        } else if (plan.present) {
            plan.reason = porterTr("the section is not an object");
        }

        plans.append(plan);
    }

    return plans;
}

// Display labels shared by the preview and its dialog. Translated
// here so both import UIs show the same words for the same value.

QString onOffLabel(bool value)
{
    return value ? porterTr("on") : porterTr("off");
}

QString listLabel(const QStringList &values)
{
    return values.isEmpty() ? porterTr("none") : values.join(QSL(", "));
}

QString listLabel(const QJsonArray &values)
{
    QStringList list;
    for (const QJsonValue &entry : values) {
        list.append(entry.toString());
    }
    return listLabel(list);
}

QString modeLabel(DnsOverHttpsManager::Mode mode)
{
    switch (mode) {
    case DnsOverHttpsManager::SecureOnly:
        return porterTr("on, secure DNS only");
    case DnsOverHttpsManager::SecureWithFallback:
        return porterTr("on, with fallback to the system resolver");
    case DnsOverHttpsManager::Disabled:
    default:
        return porterTr("off");
    }
}

} // namespace

QString SecuritySettingsPorter::formatIdentifier()
{
    return QSL("osza-security-settings");
}

int SecuritySettingsPorter::formatVersion()
{
    return 1;
}

QString SecuritySettingsPorter::checksumAlgorithm()
{
    return QSL("sha256");
}

QString SecuritySettingsPorter::checksumForTools(const QJsonObject &tools)
{
    // The canonical form is the compact serialization of the tools
    // object: no whitespace, keys in sorted order (QJsonObject keeps
    // them sorted), UTF-8. Numbers written as 1.0 parse to the same
    // double and re-serialize as 1, so the checksum follows the
    // parsed content, never the raw bytes of the file.
    const QByteArray canonical = QJsonDocument(tools).toJson(QJsonDocument::Compact);
    const QByteArray digest = QCryptographicHash::hash(canonical, QCryptographicHash::Sha256);

    return QString::fromLatin1(digest.toHex());
}

SecuritySettingsPorter::ChecksumState SecuritySettingsPorter::checkChecksum(const QJsonObject &document)
{
    const QJsonValue value = document.value(QSL("checksum"));

    if (value.isUndefined()) {
        return ChecksumState::NoChecksum;
    }

    // A malformed checksum field counts as a mismatch: fail safe.
    if (!value.isObject()) {
        return ChecksumState::Mismatch;
    }

    const QJsonObject checksum = value.toObject();

    if (checksum.value(QSL("algorithm")).toString() != checksumAlgorithm()) {
        return ChecksumState::Mismatch;
    }

    // A SHA-256 digest is 32 bytes, 64 hexadecimal characters.
    const QString expected = checksum.value(QSL("tools")).toString().toLower();

    if (expected.size() != 2 * QCryptographicHash::hashLength(QCryptographicHash::Sha256)) {
        return ChecksumState::Mismatch;
    }

    return checksumForTools(document.value(QSL("tools")).toObject()) == expected
        ? ChecksumState::Valid
        : ChecksumState::Mismatch;
}

QJsonObject SecuritySettingsPorter::buildDocument()
{
    QJsonObject tools;

    {
        QJsonObject tool;
        tool.insert(QSL("enabled"), AdBlockManager::instance()->isEnabled());
        tools.insert(QSL("adblock"), tool);
    }

    {
        QJsonObject tool;
        tool.insert(QSL("enabled"), mApp->networkManager()->httpsOnlyInterceptor()->isEnabled());

        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        tool.insert(QSL("exclusions"),
                    QJsonArray::fromStringList(settings.value(QSL("HttpsOnlyExclusions"), QStringList()).toStringList()));
        settings.endGroup();

        tools.insert(QSL("httpsOnly"), tool);
    }

    {
        QJsonObject tool;

        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        tool.insert(QSL("enabled"), settings.value(QSL("StripTrackingQuery"), true).toBool());
        settings.endGroup();

        tools.insert(QSL("trackingParameters"), tool);
    }

    {
        auto *doh = mApp->networkManager()->dnsOverHttpsManager();

        QJsonObject tool;
        tool.insert(QSL("mode"), static_cast<int>(doh->mode()));
        tool.insert(QSL("servers"), QJsonArray::fromStringList(doh->serverTemplates()));
        tools.insert(QSL("secureDns"), tool);
    }

    {
        auto *threatBlock = mApp->networkManager()->threatBlockManager();

        QJsonObject tool;
        tool.insert(QSL("enabled"), threatBlock->isEnabled());
        tool.insert(QSL("sourceUrl"), threatBlock->sourceUrl());
        tools.insert(QSL("threatBlock"), tool);
    }

    {
        QJsonObject tool;
        tool.insert(QSL("enabled"), FingerprintManager::instance()->isEnabled());

        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        tool.insert(QSL("exclusions"),
                    QJsonArray::fromStringList(settings.value(QSL("FingerprintExclusions"), QStringList()).toStringList()));
        settings.endGroup();

        tools.insert(QSL("fingerprintProtection"), tool);
    }

    {
        QJsonObject tool;
        tool.insert(QSL("enabled"), GpcManager::instance()->isEnabled());
        tools.insert(QSL("globalPrivacyControl"), tool);
    }

    QJsonObject document;
    document.insert(QSL("format"), formatIdentifier());
    document.insert(QSL("version"), formatVersion());
    document.insert(QSL("exportedAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));

    // Tamper evidence for exactly the payload below: reformatting
    // the file keeps the checksum valid, changing any setting breaks
    // it, and an import refuses the file until the user says yes.
    QJsonObject checksum;
    checksum.insert(QSL("algorithm"), checksumAlgorithm());
    checksum.insert(QSL("tools"), checksumForTools(tools));
    document.insert(QSL("checksum"), checksum);

    document.insert(QSL("tools"), tools);

    return document;
}

bool SecuritySettingsPorter::exportDocumentToFile(const QJsonObject &document, const QString &path, QString *error)
{
    if (path.isEmpty()) {
        if (error) {
            *error = porterTr("No destination file was given.");
        }
        return false;
    }

    if (!validateDocumentHeader(document, error)) {
        return false;
    }

    const QJsonValue toolsValue = document.value(QSL("tools"));

    if (!toolsValue.isObject() && !toolsValue.isUndefined()) {
        if (error) {
            *error = porterTr("The tools section is malformed.");
        }
        return false;
    }

    const QJsonObject tools = toolsValue.toObject();

    QJsonObject output;
    output.insert(QSL("format"), formatIdentifier());
    output.insert(QSL("version"), formatVersion());
    output.insert(QSL("exportedAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));

    // Provenance travels with the file when the document carries it:
    // a preset saved from the picker still names itself after a
    // round trip, without the importer ever depending on the field.
    const QJsonValue presetId = document.value(QSL("preset"));
    if (!presetId.isUndefined()) {
        output.insert(QSL("preset"), presetId);
    }

    QJsonObject checksum;
    checksum.insert(QSL("algorithm"), checksumAlgorithm());
    checksum.insert(QSL("tools"), checksumForTools(tools));
    output.insert(QSL("checksum"), checksum);

    output.insert(QSL("tools"), tools);

    const QByteArray data = QJsonDocument(output).toJson(QJsonDocument::Indented);

    // QSaveFile keeps the previous file when the write fails partway
    // (disk full, no space for the rename), so a failed export can
    // never destroy an existing backup.
    QSaveFile file(path);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }

    if (file.write(data) != data.size() || !file.commit()) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }

    return true;
}

bool SecuritySettingsPorter::exportToFile(const QString &path, QString *error)
{
    return exportDocumentToFile(buildDocument(), path, error);
}

bool SecuritySettingsPorter::loadDocument(const QString &path, QJsonObject *document, QString *error)
{
    if (document) {
        *document = QJsonObject();
    }

    QFile file(path);

    if (!file.exists()) {
        if (error) {
            *error = porterTr("The file does not exist.");
        }
        return false;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument parsed = QJsonDocument::fromJson(file.readAll(), &parseError);

    if (parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
        if (error) {
            *error = porterTr("The file is not a valid security settings document.");
        }
        return false;
    }

    if (document) {
        *document = parsed.object();
    }

    return true;
}

SecuritySettingsPorter::ImportResult SecuritySettingsPorter::importFromFile(const QString &path, ChecksumPolicy policy)
{
    ImportResult result;

    QJsonObject document;

    if (!loadDocument(path, &document, &result.error)) {
        return result;
    }

    return applyDocument(document, policy);
}

bool SecuritySettingsPorter::validateDocumentHeader(const QJsonObject &document, QString *error)
{
    if (document.value(QSL("format")).toString() != formatIdentifier()) {
        if (error) {
            *error = porterTr("The file is not an Osza security settings document.");
        }
        return false;
    }

    const QJsonValue version = document.value(QSL("version"));

    if (!version.isDouble()) {
        if (error) {
            *error = porterTr("The document does not state a format version.");
        }
        return false;
    }

    if (version.toInt() > formatVersion()) {
        if (error) {
            *error = porterTr("The document was written by a newer version of Osza.");
        }
        return false;
    }

    return true;
}

SecuritySettingsPorter::ImportResult SecuritySettingsPorter::applyDocument(const QJsonObject &document, ChecksumPolicy policy)
{
    ImportResult result;

    if (!validateDocumentHeader(document, &result.error)) {
        return result;
    }

    // A checksum that does not match means the document changed after
    // it was exported - by hand or by corruption. Refuse it unless
    // the caller explicitly allows it (the UI asks the user first).
    if (checkChecksum(document) == ChecksumState::Mismatch) {
        result.checksumMismatch = true;

        if (policy == ChecksumPolicy::Reject) {
            result.error = porterTr("The file's checksum does not match its contents. It was changed or corrupted after it was exported.");
            return result;
        }
    }

    const QJsonValue toolsValue = document.value(QSL("tools"));

    // "tools" is the only mandatory container; a document without it
    // is formally valid but has nothing to say.
    if (!toolsValue.isObject() && !toolsValue.isUndefined()) {
        result.error = porterTr("The tools section is malformed.");
        return result;
    }

    result.ok = true;

    // One validation for both consumers: the plans below are exactly
    // what previewDocument() shows. Applying walks them in the fixed
    // order the sections have always been applied in.
    const QList<ToolPlan> plans = buildPlans(toolsValue.toObject());

    for (const ToolPlan &plan : plans) {
        if (!plan.present) {
            continue;
        }

        if (!plan.apply) {
            result.skippedTools.append(QSL("%1: %2").arg(plan.key, plan.reason));
            continue;
        }

        if (plan.key == QSL("adblock")) {
            AdBlockManager::instance()->setEnabled(plan.enabled);
        } else if (plan.key == QSL("httpsOnly")) {
            Settings settings;
            settings.beginGroup(QSL("Web-Browser-Settings"));
            settings.setValue(QSL("HttpsOnlyMode"), plan.enabled);
            settings.setValue(QSL("HttpsOnlyExclusions"), plan.exclusions);
            settings.endGroup();

            mApp->networkManager()->httpsOnlyInterceptor()->loadSettings();
        } else if (plan.key == QSL("trackingParameters")) {
            Settings settings;
            settings.beginGroup(QSL("Web-Browser-Settings"));
            settings.setValue(QSL("StripTrackingQuery"), plan.enabled);
            settings.endGroup();

            mApp->networkManager()->loadSettings();
        } else if (plan.key == QSL("secureDns")) {
            // The one judgment only the engine can make: it may
            // reject a syntactically valid configuration. The
            // configuration is still persisted; the engine keeps
            // running with system DNS and the summary says so.
            if (!mApp->networkManager()->dnsOverHttpsManager()->setConfiguration(plan.mode, plan.servers)) {
                result.skippedTools.append(QSL("%1: %2").arg(plan.key, porterTr("the engine rejected the configuration")));
                continue;
            }
        } else if (plan.key == QSL("threatBlock")) {
            auto *manager = mApp->networkManager()->threatBlockManager();
            manager->setEnabled(plan.enabled);
            if (plan.statedSourceUrl && !plan.sourceUrl.isEmpty()) {
                manager->setSourceUrl(plan.sourceUrl);
            }
        } else if (plan.key == QSL("fingerprintProtection")) {
            Settings settings;
            settings.beginGroup(QSL("Web-Browser-Settings"));
            settings.setValue(QSL("FingerprintProtection"), plan.enabled);
            settings.setValue(QSL("FingerprintExclusions"), plan.exclusions);
            settings.endGroup();

            // Regenerates the guard script with the new list.
            FingerprintManager::instance()->loadSettings();
        } else if (plan.key == QSL("globalPrivacyControl")) {
            // setEnabled persists the preference and installs or
            // removes the DOM signal script; reloading the network
            // stack makes the Sec-GPC header follow immediately.
            GpcManager::instance()->setEnabled(plan.enabled);
            mApp->networkManager()->loadSettings();
        }

        ++result.appliedTools;
    }

    return result;
}

SecuritySettingsPorter::Preview SecuritySettingsPorter::previewDocument(const QJsonObject &document)
{
    Preview preview;

    if (!validateDocumentHeader(document, &preview.error)) {
        return preview;
    }

    // A mismatching checksum does not stop the preview: the whole
    // point is to see what such a file would do before deciding. The
    // dialog calls the mismatch out, and the import still requires
    // the explicit ChecksumPolicy::Allow.
    preview.checksum = checkChecksum(document);

    const QJsonValue toolsValue = document.value(QSL("tools"));

    if (!toolsValue.isObject() && !toolsValue.isUndefined()) {
        preview.error = porterTr("The tools section is malformed.");
        return preview;
    }

    preview.ok = true;

    const QList<ToolPlan> plans = buildPlans(toolsValue.toObject());

    // The current values come from the same live reads an export
    // uses, so the diff is against exactly what a backup would
    // contain right now - never against stale settings keys.
    const QJsonObject current = buildDocument().value(QSL("tools")).toObject();

    for (const ToolPlan &plan : plans) {
        if (!plan.present) {
            preview.unchangedTools.append(plan.key);
            continue;
        }

        ++preview.configuredTools;

        if (!plan.apply) {
            preview.skippedTools.append(QSL("%1: %2").arg(plan.key, plan.reason));
            continue;
        }

        const QJsonObject currentTool = current.value(plan.key).toObject();

        auto addChange = [&preview](const QString &tool, const QString &field,
                                    const QString &currentValue, const QString &nextValue) {
            if (currentValue != nextValue) {
                PreviewChange change;
                change.tool = tool;
                change.field = field;
                change.currentValue = currentValue;
                change.nextValue = nextValue;
                preview.changes.append(change);
            }
        };

        if (plan.key == QSL("adblock")
            || plan.key == QSL("trackingParameters")
            || plan.key == QSL("globalPrivacyControl")) {
            addChange(plan.key, QSL("enabled"),
                      onOffLabel(currentTool.value(QSL("enabled")).toBool()),
                      onOffLabel(plan.enabled));
        } else if (plan.key == QSL("httpsOnly") || plan.key == QSL("fingerprintProtection")) {
            addChange(plan.key, QSL("enabled"),
                      onOffLabel(currentTool.value(QSL("enabled")).toBool()),
                      onOffLabel(plan.enabled));
            addChange(plan.key, QSL("exclusions"),
                      listLabel(currentTool.value(QSL("exclusions")).toArray()),
                      listLabel(plan.exclusions));
        } else if (plan.key == QSL("secureDns")) {
            addChange(plan.key, QSL("mode"),
                      modeLabel(static_cast<DnsOverHttpsManager::Mode>(currentTool.value(QSL("mode")).toInt())),
                      modeLabel(plan.mode));
            addChange(plan.key, QSL("servers"),
                      listLabel(currentTool.value(QSL("servers")).toArray()),
                      listLabel(plan.servers));
        } else if (plan.key == QSL("threatBlock")) {
            addChange(plan.key, QSL("enabled"),
                      onOffLabel(currentTool.value(QSL("enabled")).toBool()),
                      onOffLabel(plan.enabled));
            // A missing sourceUrl field keeps the current source, so
            // it is no change and never shows up in the diff.
            if (plan.statedSourceUrl) {
                addChange(plan.key, QSL("sourceUrl"),
                          currentTool.value(QSL("sourceUrl")).toString(),
                          plan.sourceUrl);
            }
        }
    }

    return preview;
}

QString SecuritySettingsPorter::toolDisplayName(const QString &tool)
{
    if (tool == QSL("adblock")) {
        return porterTr("AdBlock");
    }
    if (tool == QSL("httpsOnly")) {
        return porterTr("HTTPS-Only mode");
    }
    if (tool == QSL("trackingParameters")) {
        return porterTr("Tracking parameter stripping");
    }
    if (tool == QSL("secureDns")) {
        return porterTr("Secure DNS (DNS-over-HTTPS)");
    }
    if (tool == QSL("threatBlock")) {
        return porterTr("Malicious site protection");
    }
    if (tool == QSL("fingerprintProtection")) {
        return porterTr("Fingerprint protection");
    }
    if (tool == QSL("globalPrivacyControl")) {
        return porterTr("Global Privacy Control (Sec-GPC)");
    }
    return tool;
}

// The tool argument names the field's owner ("httpsOnly",
// "exclusions" -> "Site exceptions"); the labels are shared between
// the tools that have the field, so it is not consulted today - it
// stays in the signature so per-tool labels can be added without
// touching every call site.
QString SecuritySettingsPorter::fieldDisplayName(const QString & /*tool*/, const QString &field)
{
    if (field == QSL("enabled")) {
        return porterTr("Enabled");
    }
    if (field == QSL("exclusions")) {
        return porterTr("Site exceptions");
    }
    if (field == QSL("mode")) {
        return porterTr("Mode");
    }
    if (field == QSL("servers")) {
        return porterTr("Server templates");
    }
    if (field == QSL("sourceUrl")) {
        return porterTr("Blocklist source");
    }
    return field;
}
