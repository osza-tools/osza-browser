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
#include "securitymanager.h"
#include "settings.h"

#include <QMetaObject>
#include <QMutexLocker>

Q_GLOBAL_STATIC(SecurityManager, qz_security_manager)

namespace {

// Safety valve for the per-host table: a browsing session cannot visit
// anywhere near this many distinct first-party sites, and clearing the
// table keeps memory bounded on the odd long-running session.
const int kMaxTrackedHosts = 4096;

}

SecurityManager::SecurityManager(QObject *parent)
    : QObject(parent)
    , m_adsBlocked(0)
    , m_trackersStripped(0)
    , m_httpsUpgrades(0)
{
}

SecurityManager *SecurityManager::instance()
{
    return qz_security_manager();
}

QString SecurityManager::normalizeHost(const QString &host)
{
    return host.trimmed().toLower();
}

void SecurityManager::reportAdBlocked(const QString &host)
{
    m_adsBlocked.fetch_add(1, std::memory_order_relaxed);

    const QString key = normalizeHost(host);

    if (!key.isEmpty()) {
        QMutexLocker lock(&m_hostMutex);
        HostCounters &counters = m_hostCounters[key];
        counters.ads++;
        if (m_hostCounters.size() > kMaxTrackedHosts) {
            m_hostCounters.clear();
        }
    }
}

void SecurityManager::reportTrackerStripped(const QString &host)
{
    m_trackersStripped.fetch_add(1, std::memory_order_relaxed);

    const QString key = normalizeHost(host);

    if (!key.isEmpty()) {
        QMutexLocker lock(&m_hostMutex);
        HostCounters &counters = m_hostCounters[key];
        counters.trackers++;
        if (m_hostCounters.size() > kMaxTrackedHosts) {
            m_hostCounters.clear();
        }
    }
}

void SecurityManager::reportHttpsUpgrade(const QString &host)
{
    m_httpsUpgrades.fetch_add(1, std::memory_order_relaxed);

    const QString key = normalizeHost(host);

    if (!key.isEmpty()) {
        QMutexLocker lock(&m_hostMutex);
        HostCounters &counters = m_hostCounters[key];
        counters.upgrades++;
        if (m_hostCounters.size() > kMaxTrackedHosts) {
            m_hostCounters.clear();
        }
    }
}

quint64 SecurityManager::adsBlocked() const
{
    return m_adsBlocked.load(std::memory_order_relaxed);
}

quint64 SecurityManager::trackersStripped() const
{
    return m_trackersStripped.load(std::memory_order_relaxed);
}

quint64 SecurityManager::httpsUpgrades() const
{
    return m_httpsUpgrades.load(std::memory_order_relaxed);
}

quint64 SecurityManager::adsBlockedForHost(const QString &host) const
{
    QMutexLocker lock(&m_hostMutex);
    return m_hostCounters.value(normalizeHost(host)).ads;
}

quint64 SecurityManager::trackersStrippedForHost(const QString &host) const
{
    QMutexLocker lock(&m_hostMutex);
    return m_hostCounters.value(normalizeHost(host)).trackers;
}

quint64 SecurityManager::httpsUpgradesForHost(const QString &host) const
{
    QMutexLocker lock(&m_hostMutex);
    return m_hostCounters.value(normalizeHost(host)).upgrades;
}

void SecurityManager::loadCounters()
{
    Settings settings;
    settings.beginGroup(QSL("Security-Tools"));
    m_adsBlocked.store(settings.value(QSL("AdsBlocked"), 0).toULongLong(), std::memory_order_relaxed);
    m_trackersStripped.store(settings.value(QSL("TrackersStripped"), 0).toULongLong(), std::memory_order_relaxed);
    m_httpsUpgrades.store(settings.value(QSL("HttpsUpgrades"), 0).toULongLong(), std::memory_order_relaxed);
    settings.endGroup();

    Q_EMIT countersChanged();
}

void SecurityManager::saveCounters()
{
    Settings settings;
    settings.beginGroup(QSL("Security-Tools"));
    settings.setValue(QSL("AdsBlocked"), qulonglong(m_adsBlocked.load(std::memory_order_relaxed)));
    settings.setValue(QSL("TrackersStripped"), qulonglong(m_trackersStripped.load(std::memory_order_relaxed)));
    settings.setValue(QSL("HttpsUpgrades"), qulonglong(m_httpsUpgrades.load(std::memory_order_relaxed)));
    settings.endGroup();
}

void SecurityManager::resetCounters()
{
    m_adsBlocked.store(0, std::memory_order_relaxed);
    m_trackersStripped.store(0, std::memory_order_relaxed);
    m_httpsUpgrades.store(0, std::memory_order_relaxed);

    {
        QMutexLocker lock(&m_hostMutex);
        m_hostCounters.clear();
    }

    saveCounters();

    Q_EMIT countersChanged();
}
