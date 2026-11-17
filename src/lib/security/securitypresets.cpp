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
#include "securitypresets.h"
#include "cookielifecyclemanager.h"
#include "dnsoverhttpsmanager.h"
#include "securitysettingsporter.h"
#include "threatblockmanager.h"

#include <QCoreApplication>
#include <QJsonArray>

namespace {

// Translate through the shared "SecurityPresets" context; the class
// is a static utility and has no QObject of its own (the same pattern
// as SecuritySettingsPorter).
inline QString presetsTr(const char *source)
{
    return QCoreApplication::translate("SecurityPresets", source);
}

QJsonObject boolTool(bool enabled)
{
    QJsonObject tool;
    tool.insert(QSL("enabled"), enabled);
    return tool;
}

QJsonObject exclusionsTool(bool enabled)
{
    QJsonObject tool = boolTool(enabled);
    tool.insert(QSL("exclusions"), QJsonArray());
    return tool;
}

QJsonObject secureDnsTool(DnsOverHttpsManager::Mode mode)
{
    QJsonObject tool;
    tool.insert(QSL("mode"), static_cast<int>(mode));

    QJsonArray servers;
    if (mode != DnsOverHttpsManager::Disabled) {
        servers.append(DnsOverHttpsManager::defaultServerTemplate());
    }
    tool.insert(QSL("servers"), servers);

    return tool;
}

QJsonObject threatBlockTool(bool enabled, const QString &sourceUrl)
{
    QJsonObject tool = boolTool(enabled);
    tool.insert(QSL("sourceUrl"), sourceUrl);
    return tool;
}

QJsonObject referrerGuardTool(int mode)
{
    QJsonObject tool;
    tool.insert(QSL("mode"), mode);
    tool.insert(QSL("exclusions"), QJsonArray());
    return tool;
}

QJsonObject cookieLifecycleTool(int mode)
{
    QJsonObject tool;
    tool.insert(QSL("mode"), mode);
    tool.insert(QSL("keepSites"), QJsonArray());
    return tool;
}

// Wraps the shared tools object into a finished preset document.
// Every preset states all nine tool sections explicitly - including
// the ones it turns off - so a preset replaces the whole
// configuration and is never silently merged with whatever was
// configured before.
QJsonObject wrapDocument(const QJsonObject &tools, const QString &id)
{
    QJsonObject document;
    document.insert(QSL("format"), SecuritySettingsPorter::formatIdentifier());
    document.insert(QSL("version"), SecuritySettingsPorter::formatVersion());

    // Provenance, for humans reading a re-exported file; imports
    // ignore the field (unknown fields are ignored by design).
    document.insert(QSL("preset"), id);

    document.insert(QSL("tools"), tools);

    return document;
}

} // namespace

QList<SecurityPresets::Preset> SecurityPresets::presets()
{
    QList<Preset> result;

    {
        Preset preset;
        preset.id = QSL("essentials");
        preset.name = presetsTr("Essentials");
        preset.description = presetsTr("AdBlock, HTTPS-Only mode, tracking-parameter stripping, malicious-site protection and cross-site referrer trimming on; secure DNS, fingerprint randomization, the Global Privacy Control signal and the cookie exit sweep off. For networks and sites where the deeper tools cause trouble.");

        QJsonObject tools;
        tools.insert(QSL("adblock"), boolTool(true));
        tools.insert(QSL("httpsOnly"), exclusionsTool(true));
        tools.insert(QSL("trackingParameters"), boolTool(true));
        tools.insert(QSL("secureDns"), secureDnsTool(DnsOverHttpsManager::Disabled));
        tools.insert(QSL("threatBlock"), threatBlockTool(true, ThreatBlockManager::defaultSourceUrl()));
        tools.insert(QSL("fingerprintProtection"), exclusionsTool(false));
        tools.insert(QSL("globalPrivacyControl"), exclusionsTool(false));
        tools.insert(QSL("referrerGuard"), referrerGuardTool(1));
        tools.insert(QSL("cookieLifecycle"), cookieLifecycleTool(0));
        preset.document = wrapDocument(tools, preset.id);

        result.append(preset);
    }

    {
        Preset preset;
        preset.id = QSL("recommended-baseline");
        preset.name = presetsTr("Recommended baseline");
        preset.description = presetsTr("The eight always-on protections at the project defaults: secure DNS with fallback to the system resolver, the default blocklist source, referrers trimmed to the site's address, and no site exceptions; the cookie exit sweep stays off, because it ends sessions on exit and is an opt-in discipline rather than a silent floor. The configuration recommended for everyday browsing.");

        QJsonObject tools;
        tools.insert(QSL("adblock"), boolTool(true));
        tools.insert(QSL("httpsOnly"), exclusionsTool(true));
        tools.insert(QSL("trackingParameters"), boolTool(true));
        tools.insert(QSL("secureDns"), secureDnsTool(DnsOverHttpsManager::SecureWithFallback));
        tools.insert(QSL("threatBlock"), threatBlockTool(true, ThreatBlockManager::defaultSourceUrl()));
        tools.insert(QSL("fingerprintProtection"), exclusionsTool(true));
        tools.insert(QSL("globalPrivacyControl"), exclusionsTool(true));
        tools.insert(QSL("referrerGuard"), referrerGuardTool(1));
        tools.insert(QSL("cookieLifecycle"), cookieLifecycleTool(0));
        preset.document = wrapDocument(tools, preset.id);

        result.append(preset);
    }

    {
        Preset preset;
        preset.id = QSL("maximum-protection");
        preset.name = presetsTr("Maximum protection");
        preset.description = presetsTr("The eight always-on protections at their strictest: name resolution through secure DNS only with no fallback to the system resolver, no referrer at all to other sites, and the cookie exit sweep on at its strict strength - no site is kept, so nothing a session picked up survives it. The strictest setting; on a network that blocks DoH, pages will not load, and every site starts each session fresh.");

        QJsonObject tools;
        tools.insert(QSL("adblock"), boolTool(true));
        tools.insert(QSL("httpsOnly"), exclusionsTool(true));
        tools.insert(QSL("trackingParameters"), boolTool(true));
        tools.insert(QSL("secureDns"), secureDnsTool(DnsOverHttpsManager::SecureOnly));
        tools.insert(QSL("threatBlock"), threatBlockTool(true, ThreatBlockManager::defaultSourceUrl()));
        tools.insert(QSL("fingerprintProtection"), exclusionsTool(true));
        tools.insert(QSL("globalPrivacyControl"), exclusionsTool(true));
        tools.insert(QSL("referrerGuard"), referrerGuardTool(2));
        tools.insert(QSL("cookieLifecycle"), cookieLifecycleTool(2));
        preset.document = wrapDocument(tools, preset.id);

        result.append(preset);
    }

    return result;
}

SecurityPresets::Preset SecurityPresets::presetById(const QString &id)
{
    const QList<Preset> builtIn = presets();

    for (const Preset &preset : builtIn) {
        if (preset.id == id) {
            return preset;
        }
    }

    return Preset();
}
