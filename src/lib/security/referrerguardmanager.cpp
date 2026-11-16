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
#include "referrerguardmanager.h"
#include "settings.h"

#include <QtWebEngineCoreVersion>

Q_GLOBAL_STATIC(ReferrerGuardManager, qz_referrer_guard_manager)

ReferrerGuardManager::ReferrerGuardManager(QObject *parent)
    : QObject(parent)
    , m_mode(OriginOnly)
    , m_exclusions()
{
}

ReferrerGuardManager *ReferrerGuardManager::instance()
{
    return qz_referrer_guard_manager();
}

bool ReferrerGuardManager::isSupported()
{
#if QTWEBENGINECORE_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    return true;
#else
    return false;
#endif
}

void ReferrerGuardManager::loadSettings()
{
    Settings settings;
    settings.beginGroup(QSL("Web-Browser-Settings"));
    const int mode = settings.value(QSL("ReferrerGuardMode"), static_cast<int>(OriginOnly)).toInt();
    m_exclusions = settings.value(QSL("ReferrerGuardExclusions"), QStringList()).toStringList();
    settings.endGroup();

    if (mode >= Off && mode <= NoReferrer) {
        m_mode = static_cast<Mode>(mode);
    } else {
        m_mode = OriginOnly;
    }
}

ReferrerGuardManager::Mode ReferrerGuardManager::mode() const
{
    return m_mode;
}

void ReferrerGuardManager::setMode(Mode mode)
{
    if (m_mode == mode) {
        return;
    }

    m_mode = mode;

    {
        Settings settings;
        settings.beginGroup(QSL("Web-Browser-Settings"));
        settings.setValue(QSL("ReferrerGuardMode"), static_cast<int>(mode));
        settings.endGroup();
    }

    Q_EMIT modeChanged(mode);
}

bool ReferrerGuardManager::isEnabled() const
{
    return m_mode != Off;
}

bool ReferrerGuardManager::isExcluded(const QString &host) const
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

QStringList ReferrerGuardManager::exclusions() const
{
    return m_exclusions;
}

void ReferrerGuardManager::addExclusion(const QString &host)
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
    settings.setValue(QSL("ReferrerGuardExclusions"), m_exclusions);
    settings.endGroup();

    Q_EMIT exclusionsChanged();
}

void ReferrerGuardManager::removeExclusion(const QString &host)
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
    settings.setValue(QSL("ReferrerGuardExclusions"), m_exclusions);
    settings.endGroup();

    Q_EMIT exclusionsChanged();
}

void ReferrerGuardManager::setExclusions(const QStringList &hosts)
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
    settings.setValue(QSL("ReferrerGuardExclusions"), m_exclusions);
    settings.endGroup();

    Q_EMIT exclusionsChanged();
}

bool ReferrerGuardManager::hostMatchesEntry(const QString &host, const QString &entry)
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
