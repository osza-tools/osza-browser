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
 * The script has no per-profile or per-site inputs: the signal is one
 * global user preference, so unlike the fingerprint guard there is
 * nothing to substitute and the source is a constant.
 *
 * Everything fails closed to the unmodified environment, and the
 * marker is non-enumerable so the script adds no enumerable key to
 * window (the same discipline as the fingerprint guard).
 */
const char kScriptSource[] = R"JS((function () {
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
    return QString::fromLatin1(kScriptSource);
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
    script.setSourceCode(signalScriptSource());
    profile->scripts()->insert(script);
}
