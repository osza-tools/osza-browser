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
#ifndef SECURITYMANAGER_H
#define SECURITYMANAGER_H

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <atomic>

#include "qzcommon.h"

/*
 * Central hub for the bundled security tools.
 *
 * Two halves with different threading rules: the request
 * interceptors run on the WebEngine IO thread while the security
 * dashboard lives on the UI thread, so all counters are atomics
 * and the per-host counters are guarded by a mutex - both threads
 * can safely report and read them without locks around Qt APIs.
 * The per-site query below is the chrome's (location bar, padlock
 * surroundings) and runs on the UI thread only.
 */
class OSZA_EXPORT SecurityManager : public QObject
{
    Q_OBJECT

public:
    explicit SecurityManager(QObject *parent = nullptr);

    static SecurityManager *instance();

    // Called from the IO thread (interceptors) - never emit signals here.
    void reportAdBlocked(const QString &host);
    void reportTrackerStripped(const QString &host);
    void reportHttpsUpgrade(const QString &host);
    void reportThreatBlocked(const QString &host);

    quint64 adsBlocked() const;
    quint64 trackersStripped() const;
    quint64 httpsUpgrades() const;
    quint64 threatsBlocked() const;

    // Session counters for a single site (first-party host).
    quint64 adsBlockedForHost(const QString &host) const;
    quint64 trackersStrippedForHost(const QString &host) const;
    quint64 httpsUpgradesForHost(const QString &host) const;
    quint64 threatsBlockedForHost(const QString &host) const;

    // The one per-site query the chrome asks: which of the four
    // tools with per-site state is currently relaxed for this exact
    // site - an HTTPS-Only exclusion (the site is never upgraded), a
    // fingerprint or GPC exclusion (the site's readouts are not
    // randomized / the opt-out is not sent), or a threat-block
    // session allow ("proceed anyway"). A tool's entry only counts
    // while the tool itself is enabled: a global switch is not
    // per-site state, the padlock menu and Preferences own it.
    // Returns the porter's stable tool keys in the padlock menu's
    // row order; empty for schemes the tools do not cover.
    // UI thread only (Settings-backed managers, no locking).
    static QStringList relaxedProtections(const QUrl &url);

    void loadCounters();
    void saveCounters();

public Q_SLOTS:
    void resetCounters();

Q_SIGNALS:
    void countersChanged();

private:
    struct HostCounters
    {
        quint64 ads = 0;
        quint64 trackers = 0;
        quint64 upgrades = 0;
        quint64 threats = 0;
    };

    static QString normalizeHost(const QString &host);

    // Total counters, persisted between sessions.
    std::atomic<quint64> m_adsBlocked;
    std::atomic<quint64> m_trackersStripped;
    std::atomic<quint64> m_httpsUpgrades;
    std::atomic<quint64> m_threatsBlocked;

    // Per-host session counters, only exposed in the dashboard.
    mutable QMutex m_hostMutex;
    QHash<QString, HostCounters> m_hostCounters;
};

#endif // SECURITYMANAGER_H
