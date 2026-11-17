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
#ifndef COOKIEKEEPSITESDIALOG_H
#define COOKIEKEEPSITESDIALOG_H

#include <QDialog>

#include "qzcommon.h"

class QListWidget;
class QLineEdit;

/*
 * Management dialog for the cookie lifecycle tool's kept sites, the
 * counterpart of the referrer and GPC exceptions dialogs: sites whose
 * cookies survive the exit sweep (typically the sites you stay
 * logged in to), while every other site's persistent cookies are
 * deleted at exit. Entries are hosts; an entry also covers its
 * subdomains, and "*.domain" entries cover the subdomains only -
 * the same matching CookieLifecycleManager applies, anchored on the
 * site whose cookies survive.
 */
class OSZA_EXPORT CookieKeepSitesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CookieKeepSitesDialog(const QStringList &keepSites, QWidget *parent = nullptr);

    QStringList keepSites() const;

private:
    void addKeepSite();
    void removeSelected();

    QListWidget *m_list;
    QLineEdit *m_edit;
    QStringList m_keepSites;
};

#endif // COOKIEKEEPSITESDIALOG_H
