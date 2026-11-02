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
#include "dnsoverhttpsmanager.h"
#include "settings.h"

#include <QDebug>

#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 6, 0)
#include <QWebEngineGlobalSettings>
#endif

namespace {

const char kSettingsGroup[] = "Web-Browser-Settings";
const char kModeKey[] = "DnsOverHttpsMode";
const char kServersKey[] = "DnsOverHttpsServers";

QStringList normalizeTemplates(const QStringList &templates)
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

} // namespace

DnsOverHttpsManager::DnsOverHttpsManager(QObject *parent)
    : QObject(parent)
{
}

bool DnsOverHttpsManager::isSupported()
{
#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    return true;
#else
    return false;
#endif
}

QList<DnsOverHttpsManager::Provider> DnsOverHttpsManager::knownProviders()
{
    return {
        {QSL("Cloudflare"), QSL("https://cloudflare-dns.com/dns-query{?dns}")},
        {QSL("Cloudflare (family)"), QSL("https://family.cloudflare-dns.com/dns-query{?dns}")},
        {QSL("Google"), QSL("https://dns.google/dns-query{?dns}")},
        {QSL("Quad9"), QSL("https://dns.quad9.net/dns-query{?dns}")},
        {QSL("AdGuard"), QSL("https://dns.adguard-dns.com/dns-query{?dns}")}
    };
}

void DnsOverHttpsManager::loadSettings()
{
    Settings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    const int mode = settings.value(QLatin1String(kModeKey), 0).toInt();
    m_serverTemplates = normalizeTemplates(settings.value(QLatin1String(kServersKey), QStringList()).toStringList());
    settings.endGroup();

    if (mode >= Disabled && mode <= SecureOnly) {
        m_mode = static_cast<Mode>(mode);
    } else {
        m_mode = Disabled;
    }

    // A secure mode without servers cannot work; keep the state honest.
    if (m_mode != Disabled && m_serverTemplates.isEmpty()) {
        qWarning() << "DNS-over-HTTPS: secure mode without server templates, disabling";
        m_mode = Disabled;
    }

    m_applied = applyConfiguration();

    Q_EMIT configurationChanged();
}

bool DnsOverHttpsManager::setConfiguration(Mode mode, const QStringList &serverTemplates)
{
    const QStringList templates = normalizeTemplates(serverTemplates);

    // Do not accept a secure mode without any server configured.
    if (mode != Disabled && templates.isEmpty()) {
        qWarning() << "DNS-over-HTTPS: no server templates configured for secure mode";
        m_applied = false;
        Q_EMIT configurationChanged();
        return false;
    }

    m_mode = mode;
    m_serverTemplates = templates;
    m_applied = applyConfiguration();

    if (!m_applied) {
        // Keep the desired values so the user can fix them in
        // Preferences; the engine keeps running with system DNS.
        qWarning() << "DNS-over-HTTPS: engine rejected the configuration";
    }

    Settings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    settings.setValue(QLatin1String(kModeKey), static_cast<int>(m_mode));
    settings.setValue(QLatin1String(kServersKey), m_serverTemplates);
    settings.endGroup();

    Q_EMIT configurationChanged();

    return m_applied;
}

bool DnsOverHttpsManager::applyConfiguration()
{
    if (!isSupported()) {
        if (m_mode != Disabled) {
            qWarning() << "DNS-over-HTTPS requires QtWebEngine 6.6 or newer";
        }
        return m_mode == Disabled;
    }

#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    using SecureDnsMode = QWebEngineGlobalSettings::SecureDnsMode;

    SecureDnsMode secureMode = SecureDnsMode::SystemOnly;
    switch (m_mode) {
    case SecureWithFallback:
        secureMode = SecureDnsMode::SecureWithFallback;
        break;
    case SecureOnly:
        secureMode = SecureDnsMode::SecureOnly;
        break;
    case Disabled:
    default:
        secureMode = SecureDnsMode::SystemOnly;
        break;
    }

    QWebEngineGlobalSettings::DnsMode dnsMode;
    dnsMode.secureMode = secureMode;
    dnsMode.serverTemplates = m_serverTemplates;

    return QWebEngineGlobalSettings::setDnsMode(dnsMode);
#else
    return m_mode == Disabled;
#endif
}

DnsOverHttpsManager::Mode DnsOverHttpsManager::mode() const
{
    return m_mode;
}

QStringList DnsOverHttpsManager::serverTemplates() const
{
    return m_serverTemplates;
}

bool DnsOverHttpsManager::isApplied() const
{
    return m_applied;
}
