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
#include "gpcmanager.h"
#include "mainapplication.h"
#include "settings.h"
#include "webpage.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>

Q_GLOBAL_STATIC(GpcManager, qz_gpc_manager)

namespace {

// Name of the injected QWebEngineScript. Scripts are looked up and
// removed by name, so it must stay unique in the profile.
const char kScriptName[] = "_osza_gpc_signal";

/*
 * The signal script. It runs in the main world at document creation
 * in every frame, before any page script, so the property is already
 * in place when privacy-aware scripts first look at it.
 *
 * The only per-site input is the exclusion list: hosts whose frames
 * must be left exactly as a browser without GPC would leave them.
 * The list is substituted by buildScriptSource(), so the same
 * template serves every profile state.
 *
 * Everything fails closed to the unmodified environment, and the
 * marker is non-enumerable so the script adds no enumerable key to
 * window (the same discipline as the fingerprint guard).
 */
const char kScriptTemplate[] = R"JS((function () {
    'use strict';

    // Osza Browser Global Privacy Control signal.

    try {
        if (window.__oszaGpcSignal) {
            return;
        }
        Object.defineProperty(window, '__oszaGpcSignal', {
            value: 1,
            writable: false,
            enumerable: false,
            configurable: false
        });
    } catch (e) {
        return;
    }

    var EXCLUSIONS = %EXCLUSIONS%;

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

    try {
        if (window.Navigator && window.Navigator.prototype) {
            Object.defineProperty(window.Navigator.prototype, 'globalPrivacyControl', {
                get: function () {
                    return true;
                },
                set: undefined,
                enumerable: true,
                configurable: true
            });
        }
    } catch (e) {
    }
})();)JS";

} // namespace

GpcManager::GpcManager(QObject *parent)
    : QObject(parent)
    , m_enabled(true)
    , m_exclusions()
{
}

GpcManager *GpcManager::instance()
{
    return qz_gpc_manager();
}

void GpcManager::loadSettings()
{
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    m_enabled = settings.value(QSL("GlobalPrivacyControl"), true).toBool();
    m_exclusions = settings.value(QSL("GpcExclusions"), QStringList()).toStringList();
    settings.endGroup();

    updateScript();
}

bool GpcManager::isEnabled() const
{
    return m_enabled;
}

void GpcManager::setEnabled(bool enabled)
{
    if (m_enabled == enabled) {
        return;
    }

    m_enabled = enabled;

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("GlobalPrivacyControl"), enabled);
        settings.endGroup();
    }

    updateScript();

    Q_EMIT enabledChanged(enabled);
}

QString GpcManager::signalScriptSource()
{
    return buildScriptSource(QStringList());
}

void GpcManager::updateScript()
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
    script.setSourceCode(buildScriptSource(m_exclusions));
    profile->scripts()->insert(script);
}

bool GpcManager::isExcluded(const QString &host) const
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

QStringList GpcManager::exclusions() const
{
    return m_exclusions;
}

void GpcManager::addExclusion(const QString &host)
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
    settings.setValue(QSL("GpcExclusions"), m_exclusions);
    settings.endGroup();

    updateScript();
}

void GpcManager::removeExclusion(const QString &host)
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
    settings.setValue(QSL("GpcExclusions"), m_exclusions);
    settings.endGroup();

    updateScript();
}

void GpcManager::setExclusions(const QStringList &hosts)
{
    m_exclusions.clear();

    for (const QString &host : hosts) {
        const QString trimmed = host.trimmed().toLower();

        if (!trimmed.isEmpty() && !m_exclusions.contains(trimmed, Qt::CaseInsensitive)) {
            m_exclusions.append(trimmed);
        }
    }

    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    settings.setValue(QSL("GpcExclusions"), m_exclusions);
    settings.endGroup();

    updateScript();
}

QString GpcManager::buildScriptSource(const QStringList &exclusions)
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
    return source;
}

bool GpcManager::hostMatchesEntry(const QString &host, const QString &entry)
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
