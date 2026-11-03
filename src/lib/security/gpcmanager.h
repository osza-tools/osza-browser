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

    // The injected script source, exposed for the autotests.
    static QString signalScriptSource();

    // Reinserts (or removes) the injected script in the current web
    // profile. Public so the autotests can exercise the refresh path.
    void updateScript();

Q_SIGNALS:
    void enabledChanged(bool enabled);

private:

    bool m_enabled = true;
};

#endif // GPCMANAGER_H
