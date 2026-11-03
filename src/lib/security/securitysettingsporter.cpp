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

} // namespace

QString SecuritySettingsPorter::formatIdentifier()
{
    return QSL("osza-security-settings");
}

int SecuritySettingsPorter::formatVersion()
{
    return 1;
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
    document.insert(QSL("tools"), tools);

    return document;
}

bool SecuritySettingsPorter::exportToFile(const QString &path, QString *error)
{
    if (path.isEmpty()) {
        if (error) {
            *error = porterTr("No destination file was given.");
        }
        return false;
    }

    const QByteArray data = QJsonDocument(buildDocument()).toJson(QJsonDocument::Indented);

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

SecuritySettingsPorter::ImportResult SecuritySettingsPorter::importFromFile(const QString &path)
{
    ImportResult result;

    QFile file(path);

    if (!file.exists()) {
        result.error = porterTr("The file does not exist.");
        return result;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        result.error = file.errorString();
        return result;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);

    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        result.error = porterTr("The file is not a valid security settings document.");
        return result;
    }

    return applyDocument(document.object());
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

SecuritySettingsPorter::ImportResult SecuritySettingsPorter::applyDocument(const QJsonObject &document)
{
    ImportResult result;

    if (!validateDocumentHeader(document, &result.error)) {
        return result;
    }

    const QJsonValue toolsValue = document.value(QSL("tools"));

    // "tools" is the only mandatory container; a document without it
    // is formally valid but has nothing to say.
    if (!toolsValue.isObject() && !toolsValue.isUndefined()) {
        result.error = porterTr("The tools section is malformed.");
        return result;
    }

    const QJsonObject tools = toolsValue.toObject();
    result.ok = true;

    auto skip = [&result](const char *tool, const QString &reason) {
        result.skippedTools.append(QSL("%1: %2").arg(QString::fromLatin1(tool), reason));
    };

    auto boolField = [](const QJsonObject &tool, bool *ok) -> bool {
        const QJsonValue value = tool.value(QSL("enabled"));
        if (!value.isBool()) {
            *ok = false;
            return false;
        }
        *ok = true;
        return value.toBool();
    };

    auto stringListField = [](const QJsonObject &tool, bool *ok) -> QStringList {
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
    };

    // AdBlock
    {
        const QJsonValue value = tools.value(QSL("adblock"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            const bool enabled = boolField(tool, &fieldOk);
            if (fieldOk) {
                AdBlockManager::instance()->setEnabled(enabled);
                ++result.appliedTools;
            } else {
                skip("adblock", porterTr("the enabled field is missing or not a boolean"));
            }
        } else if (!value.isUndefined()) {
            skip("adblock", porterTr("the section is not an object"));
        }
    }

    // HTTPS-Only mode
    {
        const QJsonValue value = tools.value(QSL("httpsOnly"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool enabledOk = false;
            const bool enabled = boolField(tool, &enabledOk);
            bool exclusionsOk = true;
            QStringList exclusions;
            if (tool.contains(QSL("exclusions"))) {
                exclusions = stringListField(tool, &exclusionsOk);
            }
            if (enabledOk && exclusionsOk) {
                Settings settings;
                settings.beginGroup(QSL("Web-Browser-Settings"));
                settings.setValue(QSL("HttpsOnlyMode"), enabled);
                settings.setValue(QSL("HttpsOnlyExclusions"), sanitizeHostList(exclusions));
                settings.endGroup();

                mApp->networkManager()->httpsOnlyInterceptor()->loadSettings();
                ++result.appliedTools;
            } else {
                skip("httpsOnly", porterTr("a field is missing or has the wrong type"));
            }
        } else if (!value.isUndefined()) {
            skip("httpsOnly", porterTr("the section is not an object"));
        }
    }

    // Tracking parameter stripping
    {
        const QJsonValue value = tools.value(QSL("trackingParameters"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            const bool enabled = boolField(tool, &fieldOk);
            if (fieldOk) {
                Settings settings;
                settings.beginGroup(QSL("Web-Browser-Settings"));
                settings.setValue(QSL("StripTrackingQuery"), enabled);
                settings.endGroup();

                mApp->networkManager()->loadSettings();
                ++result.appliedTools;
            } else {
                skip("trackingParameters", porterTr("the enabled field is missing or not a boolean"));
            }
        } else if (!value.isUndefined()) {
            skip("trackingParameters", porterTr("the section is not an object"));
        }
    }

    // Secure DNS
    {
        const QJsonValue value = tools.value(QSL("secureDns"));
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

            const auto mode = static_cast<DnsOverHttpsManager::Mode>(modeValue.toInt());
            servers = sanitizeTemplateList(servers);

            if (!fieldOk) {
                skip("secureDns", porterTr("a field is missing or has the wrong type"));
            } else if (!DnsOverHttpsManager::isSupported()) {
                skip("secureDns", porterTr("this build cannot use secure DNS"));
            } else if (mode != DnsOverHttpsManager::Disabled && servers.isEmpty()) {
                skip("secureDns", porterTr("a secure mode needs at least one server"));
            } else if (!mApp->networkManager()->dnsOverHttpsManager()->setConfiguration(mode, servers)) {
                skip("secureDns", porterTr("the engine rejected the configuration"));
            } else {
                ++result.appliedTools;
            }
        } else if (!value.isUndefined()) {
            skip("secureDns", porterTr("the section is not an object"));
        }
    }

    // Malicious site protection
    {
        const QJsonValue value = tools.value(QSL("threatBlock"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();

            const QJsonValue enabledValue = tool.value(QSL("enabled"));
            const QJsonValue sourceValue = tool.value(QSL("sourceUrl"));

            const bool hasSource = tool.contains(QSL("sourceUrl"));
            const QString source = sourceValue.toString();

            if (!enabledValue.isBool() || (hasSource && (!sourceValue.isString() || !isValidThreatSource(source)))) {
                skip("threatBlock", porterTr("a field is missing or has the wrong type"));
            } else {
                auto *manager = mApp->networkManager()->threatBlockManager();
                manager->setEnabled(enabledValue.toBool());
                if (hasSource && !source.trimmed().isEmpty()) {
                    manager->setSourceUrl(source.trimmed());
                }
                ++result.appliedTools;
            }
        } else if (!value.isUndefined()) {
            skip("threatBlock", porterTr("the section is not an object"));
        }
    }

    // Fingerprint protection
    {
        const QJsonValue value = tools.value(QSL("fingerprintProtection"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool enabledOk = false;
            const bool enabled = boolField(tool, &enabledOk);
            bool exclusionsOk = true;
            QStringList exclusions;
            if (tool.contains(QSL("exclusions"))) {
                exclusions = stringListField(tool, &exclusionsOk);
            }
            if (enabledOk && exclusionsOk) {
                Settings settings;
                settings.beginGroup(QSL("Web-Browser-Settings"));
                settings.setValue(QSL("FingerprintProtection"), enabled);
                settings.setValue(QSL("FingerprintExclusions"), sanitizeHostList(exclusions));
                settings.endGroup();

                // Regenerates the guard script with the new list.
                FingerprintManager::instance()->loadSettings();
                ++result.appliedTools;
            } else {
                skip("fingerprintProtection", porterTr("a field is missing or has the wrong type"));
            }
        } else if (!value.isUndefined()) {
            skip("fingerprintProtection", porterTr("the section is not an object"));
        }
    }

    // Global Privacy Control
    {
        const QJsonValue value = tools.value(QSL("globalPrivacyControl"));
        if (value.isObject()) {
            const QJsonObject tool = value.toObject();
            bool fieldOk = false;
            const bool enabled = boolField(tool, &fieldOk);
            if (fieldOk) {
                // setEnabled persists the preference and installs or
                // removes the DOM signal script; reloading the network
                // stack makes the Sec-GPC header follow immediately.
                GpcManager::instance()->setEnabled(enabled);
                mApp->networkManager()->loadSettings();
                ++result.appliedTools;
            } else {
                skip("globalPrivacyControl", porterTr("the enabled field is missing or not a boolean"));
            }
        } else if (!value.isUndefined()) {
            skip("globalPrivacyControl", porterTr("the section is not an object"));
        }
    }

    return result;
}
