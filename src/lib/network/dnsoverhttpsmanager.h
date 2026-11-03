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
#ifndef DNSOVERHTTPSMANAGER_H
#define DNSOVERHTTPSMANAGER_H

#include <QObject>
#include <QStringList>

#include "qzcommon.h"

/*
 * DNS-over-HTTPS plumbing for the WebEngine network service.
 *
 * QtWebEngine exposes DoH through QWebEngineGlobalSettings::setDnsMode()
 * (since Qt 6.6). The mode applies to all host resolution performed by
 * Chromium, which is what every page load goes through. This manager
 * owns the browser-wide configuration, validates the server templates
 * and exposes the current state to the security dashboard and
 * Preferences.
 */
class OSZA_EXPORT DnsOverHttpsManager : public QObject
{
    Q_OBJECT

public:
    enum Mode {
        Disabled = 0,          // SystemOnly - system DNS resolution
        SecureWithFallback = 1 // DoH with fallback to system DNS
        , SecureOnly = 2       // DoH only, no fallback
    };
    Q_ENUM(Mode)

    explicit DnsOverHttpsManager(QObject *parent = nullptr);

    void loadSettings();

    // Validates and applies a new configuration, then saves it.
    // Returns false if the server templates are invalid.
    bool setConfiguration(Mode mode, const QStringList &serverTemplates);

    Mode mode() const;
    QStringList serverTemplates() const;

    // Whether the last setConfiguration()/loadSettings() was accepted
    // by the engine. Always true while DoH is disabled.
    bool isApplied() const;

    // DoH requires QtWebEngine >= 6.6; older engines report unsupported.
    static bool isSupported();

    // The default server template (the first of the known providers).
    // The security dashboard's quick switch and the recommended-
    // baseline preset resolve their default from here.
    static QString defaultServerTemplate();

    // Built-in provider presets (name + RFC 8484 URI template).
    struct Provider
    {
        QString name;
        QString template_;
    };
    static QList<Provider> knownProviders();

Q_SIGNALS:
    void configurationChanged();

private:
    bool applyConfiguration();

    Mode m_mode = Disabled;
    QStringList m_serverTemplates;
    bool m_applied = true;
};

#endif // DNSOVERHTTPSMANAGER_H
