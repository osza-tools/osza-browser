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

    // True when a refresh is currently running. The interstitial is
    // rendered on the WebEngine IO thread, so the flag is read under
    // the mutex like every shared state - the answer is safe to ask
    // from any thread.
    bool isUpdating() const;

    // The error of the last refresh attempt, empty when the last
    // attempt succeeded (or none has run). The interstitial's and
    // the padlock row's "the last update failed" states read it, so
    // a failed refresh stays visible after the signal has come and
    // gone - a stale list the browser could not renew is exactly
    // the state that must not be papered over. Read under the
    // mutex; cleared when a new attempt starts or a list lands.
    QString lastUpdateError() const;

    // True when the list in place is empty or older than the
    // refresh interval - exactly the state the manager's own timer
    // refreshes through checkForUpdate(), and the state the
    // interstitial and the padlock row surface with a "refresh
    // now" action, so the evidence behind a warning can be renewed
    // deliberately instead of waiting for the timer. Thread safe.
    bool isListStale() const;

    // The age of a list update in relative terms - "less than a
    // minute ago", "3 hours ago", "2 days ago" - the phrasing the
    // surfaces that speak to a decision (the interstitial's
    // evidence rows, the padlock row, the sidebar's live status)
    // use, where "how old is this evidence" is the question being
    // answered; Preferences keeps the clock time, the place the
    // source is configured. An invalid timestamp falls back to
    // "unknown date", so the composed "%1 hosts, updated %2"
    // wording keeps its shape everywhere.
    static QString describeListAge(const QDateTime &since);

    // Blocking queries - thread safe, may be called from the IO thread.
    // A host matches when the host itself or any parent domain is on
    // the list ("bad.example" is blocked by a "bad.example" and by an
    // "example" entry, but never by "xbad.example").
    bool isHostBlocked(const QString &host) const;

    // The blocklist entry that matched the host: the host itself when
    // it is listed, else the closest listed parent domain - the exact
    // walk isHostBlocked answers through, so the entry the
    // interstitial shows can never disagree with the decision it
    // explains. Empty when nothing matched (and for every host while
    // no list is loaded). A pure list query: neither the enabled
    // switch nor a session allow changes the answer. Thread safe.
    QString matchingListEntry(const QString &host) const;

    // The complete decision used by the interceptor, under one lock:
    // protection enabled, host listed, no session exception.
    bool shouldBlock(const QString &host) const;

    // Session-scoped "proceed anyway" decisions. They are
    // deliberately never persisted: a standing allow for a host a
    // blocklist calls malicious must not survive a restart (or a
    // blocklist refresh) silently. The padlock menu surfaces the
    // paused state per site and revokes it through removeSessionAllow.
    bool isSessionAllowed(const QString &host) const;
    void allowForSession(const QString &host);
    void removeSessionAllow(const QString &host);

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

    // The osza: URL the interstitial's "refresh now" action
    // carries, and its recognizer: the scheme handler answers it by
    // starting updateNow() and re-serving the interstitial for the
    // same blocked URL, whose list-state row then reports the
    // refresh in flight. Shaped exactly like the proceed URL - one
    // percent-encoded blocked URL, one Osza-owned flag - so the
    // round trip through blockedUrlFromPageUrl() is the same one.
    static QUrl refreshListPageUrl(const QUrl &blockedUrl);
    static bool isRefreshListPageUrl(const QUrl &pageUrl);

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

    // Update-lifecycle state. Both are guarded by the mutex (the
    // interstitial reads them on the WebEngine IO thread, under the
    // one lock it already holds for the evidence rows) even though
    // they are written on the UI thread only - like the list itself,
    // which the IO thread's queries read under the same lock.
    bool m_updating;
    QString m_lastError;

    // UI-thread only state
    QNetworkAccessManager *m_nam;
    QNetworkReply *m_reply;
    int m_refreshTimerId;
};

#endif // THREATBLOCKMANAGER_H
