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
* but WITHOUT ANY WARRANTY; without even implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#ifndef THREATBLOCKMANAGER_H
#define THREATBLOCKMANAGER_H

#include <QDateTime>
#include <QMutex>
#include <QObject>
#include <QSet>
#include <QString>
#include <QUrl>

#include "qzcommon.h"

class QNetworkAccessManager;
class QNetworkReply;

/*
 * Malicious-site protection ("threat block"), the blocklist-driven part
 * of the bundled security tools.
 *
 * The manager owns a host blocklist that is periodically fetched from a
 * plain-text source (by default the curated StevenBlack hosts list),
 * persisted in the profile and queried on the WebEngine IO thread by
 * ThreatBlockInterceptor. Hosts on the list match the listed host and
 * its subdomains; a session-scoped allowlist implements the
 * "proceed anyway" choice from the interstitial page.
 *
 * All blocking queries are mutex-guarded (the list can be swapped by a
 * refresh on the UI thread while a request is being intercepted) and the
 * whole class is designed to be safe to call from the IO thread for the
 * read paths.
 */
class OSZA_EXPORT ThreatBlockManager : public QObject
{
    Q_OBJECT

public:
    explicit ThreatBlockManager(QObject *parent = nullptr);

    // Reads the persisted configuration and blocklist; schedules a
    // refresh when the list is missing or stale. Never fetches in test
    // mode. Must be called after Settings have been created.
    void loadSettings();

    // The default blocklist source (the curated StevenBlack hosts
    // list). Single source of truth for Preferences, the security
    // dashboard and the recommended-baseline preset.
    static QString defaultSourceUrl();

    bool isEnabled() const;

    // Persists the new state and starts/stops protecting.
    void setEnabled(bool enabled);

    // The blocklist source (a plain-text or hosts-format URL).
    QString sourceUrl() const;
    void setSourceUrl(const QString &url);

    QDateTime lastUpdate() const;
    int hostCount() const;
    bool isListLoaded() const;

    // True when a refresh is currently running.
    bool isUpdating() const;

    // Blocking queries - thread safe, may be called from the IO thread.
    // A host matches when the host itself or any parent domain is on
    // the list ("bad.example" is blocked by a "bad.example" and by an
    // "example" entry, but never by "xbad.example").
    bool isHostBlocked(const QString &host) const;

    // The complete decision used by the interceptor, under one lock:
    // protection enabled, host listed, no session exception.
    bool shouldBlock(const QString &host) const;

    // Session-scoped "proceed anyway" decisions.
    bool isSessionAllowed(const QString &host) const;
    void allowForSession(const QString &host);

    // List lifecycle. checkForUpdate() only fetches when the list is
    // missing or older than the refresh interval.
    void checkForUpdate();
    void updateNow();
    void abortUpdate();

    // Parses raw list data into normalized hosts. Understands three
    // line formats: full URLs ("http://bad.example/path", the URLhaus
    // text export), hosts-file lines ("0.0.0.0 bad.example") and bare
    // host names. Comment ("#") and empty lines are skipped. Returns
    // the number of hosts added.
    static int parseListData(const QByteArray &data, QSet<QString> *hosts);

    // Normalizes a host for the list and the lookups: lower case,
    // trailing dot removed, IDN names converted to their ACE form.
    static QString normalizeHost(const QString &host);

    // Adopts raw list data as the current blocklist (parsed with
    // parseListData) and persists it. Returns the number of hosts.
    // Used by the downloader and available for manual imports.
    int applyListData(const QByteArray &data);

    // The osza: URL shown instead of a blocked navigation, and the
    // inverse conversion used by the scheme handler and the tests.
    // With proceed set, the URL asks for a session exception instead
    // of the interstitial (the "Proceed anyway" choice).
    static QUrl blockPageUrl(const QUrl &blockedUrl, bool proceed = false);
    static QUrl blockedUrlFromPageUrl(const QUrl &pageUrl);
    static bool isProceedPageUrl(const QUrl &pageUrl);

    // Renders the interstitial page for a blocked URL.
    QString interstitialPage(const QUrl &blockedUrl) const;

Q_SIGNALS:
    void enabledChanged(bool enabled);
    void listUpdated(int hostCount);
    void updateFailed(const QString &error);

private:
    void applyList(const QSet<QString> &hosts, const QDateTime &when);
    bool saveList(const QSet<QString> &hosts, const QDateTime &when);
    bool loadList();
    void fetchList();
    QString listFilePath() const;
    bool isSessionAllowedLocked(const QString &host) const;

protected:
    void timerEvent(QTimerEvent *event) override;

    mutable QMutex m_mutex;
    bool m_enabled;
    QString m_sourceUrl;
    QDateTime m_lastUpdate;
    QSet<QString> m_blockedHosts;
    QSet<QString> m_sessionAllowed;

    // UI-thread only state
    QNetworkAccessManager *m_nam;
    QNetworkReply *m_reply;
    bool m_updating;
    int m_refreshTimerId;
};

#endif // THREATBLOCKMANAGER_H
