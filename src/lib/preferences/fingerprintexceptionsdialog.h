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
#ifndef FINGERPRINTEXCEPTIONSDIALOG_H
#define FINGERPRINTEXCEPTIONSDIALOG_H

#include <QDialog>

#include "qzcommon.h"

class QListWidget;
class QLineEdit;

/*
 * Management dialog for the fingerprint-protection exclusions, the
 * counterpart of the HTTPS-Only exceptions dialog: sites whose
 * fingerprint readouts stay original (typically because randomization
 * breaks them). Entries are hosts; an entry also covers its
 * subdomains, and "*.domain" entries cover the subdomains only.
 */
class OSZA_EXPORT FingerprintExceptionsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FingerprintExceptionsDialog(const QStringList &exclusions, QWidget *parent = nullptr);

    QStringList exclusions() const;

private:
    void addExclusion();
    void removeSelected();

    QListWidget *m_list;
    QLineEdit *m_edit;
    QStringList m_exclusions;
};

#endif // FINGERPRINTEXCEPTIONSDIALOG_H
