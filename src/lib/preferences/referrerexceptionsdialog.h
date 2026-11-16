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
#ifndef REFERREREXCEPTIONSDIALOG_H
#define REFERREREXCEPTIONSDIALOG_H

#include <QDialog>

#include "qzcommon.h"

class QListWidget;
class QLineEdit;

/*
 * Management dialog for the cross-site referrer protection's site
 * exceptions, the counterpart of the GPC and fingerprint exceptions
 * dialogs: sites whose outgoing requests keep whatever referrer the
 * site's own policy sends, instead of being trimmed for other sites
 * (typically because a site's flow needs the full referrer to work).
 * Entries are hosts; an entry also covers its subdomains, and
 * "*.domain" entries cover the subdomains only - the same matching
 * ReferrerGuardManager and the network interceptor apply, anchored
 * on the site whose URLs would leak.
 */
class OSZA_EXPORT ReferrerExceptionsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ReferrerExceptionsDialog(const QStringList &exclusions, QWidget *parent = nullptr);

    QStringList exclusions() const;

private:
    void addExclusion();
    void removeSelected();

    QListWidget *m_list;
    QLineEdit *m_edit;
    QStringList m_exclusions;
};

#endif // REFERREREXCEPTIONSDIALOG_H
