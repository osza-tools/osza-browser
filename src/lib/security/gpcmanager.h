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
#ifndef GPCMANAGER_H
#define GPCMANAGER_H

#include <QObject>
#include <QStringList>

#include "qzcommon.h"

/*
 * Global Privacy Control (GPC), the DOM half of the signal.
 *
 * The user's opt-out is expressed in two places, and both must agree:
 * every outgoing request carries the "Sec-GPC: 1" header (set by
 * NetworkUrlInterceptor) and every frame must report it to page
 * scripts through navigator.globalPrivacyControl. The header is what
 * servers and the law see; the DOM property is what privacy-aware
 * page scripts see. This manager owns the DOM half: a tiny script
 * injected into every frame at document creation, in the main world,
 * before any page script runs - the same placement rules as the
 * fingerprint guard.
 *
 * When the signal is disabled the script is removed entirely, so
 * navigator.globalPrivacyControl is simply absent, which is exactly
 * what a browser that does not support GPC reports.
 *
 * Individual sites can be excluded from the signal (from the padlock
 * menu in the location bar). On an excluded host the script leaves
 * the environment exactly as it found it - no property, no marker -
 * so the page sees the same browser it would see with the signal
 * globally off. Exclusion entries match the listed host and its
 * subdomains; "*.domain" wildcard entries are supported, like the
 * fingerprint and HTTPS-Only exceptions. The list is persisted and
 * embedded into the injected script, so the two halves of the signal
 * agree: NetworkUrlInterceptor holds its own copy of the same list
 * for the header half, anchored on the request's target host.
 */
class OSZA_EXPORT GpcManager : public QObject
{
    Q_OBJECT

public:
    static GpcManager *instance();

    explicit GpcManager(QObject *parent = nullptr);

    void loadSettings();

    bool isEnabled() const;
    void setEnabled(bool enabled);

    // The per-site exclusions, persisted like the fingerprint
    // exceptions. The injected script is rebuilt so the change
    // reaches newly loaded pages; the callers that change the list
    // refresh the network stack (mApp->networkManager()->
    // loadSettings()) so the Sec-GPC header half follows at once.
    bool isExcluded(const QString &host) const;
    QStringList exclusions() const;
    void addExclusion(const QString &host);
    void removeExclusion(const QString &host);

    // Replaces the whole list (the settings porter's import path:
    // the document's list is the complete effective list after the
    // import). Persists and rebuilds the script.
    void setExclusions(const QStringList &hosts);

    // The injected script source with the given exclusions embedded,
    // exposed for the autotests and the self-test page plumbing.
    static QString buildScriptSource(const QStringList &exclusions);

    // The script for a profile without exclusions - the shape every
    // build shares, with an empty list substituted.
    static QString signalScriptSource();

    // Reinserts (or removes) the injected script in the current web
    // profile. Public so the autotests can exercise the refresh path.
    void updateScript();

Q_SIGNALS:
    void enabledChanged(bool enabled);

private:
    static bool hostMatchesEntry(const QString &host, const QString &entry);

    bool m_enabled = true;
    QStringList m_exclusions;
};

#endif // GPCMANAGER_H
