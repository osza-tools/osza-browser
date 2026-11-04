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
#ifndef SECURITYIMPORTPREVIEWDIALOG_H
#define SECURITYIMPORTPREVIEWDIALOG_H

#include <QDialog>

#include "qzcommon.h"
#include "securitysettingsporter.h"

class QDialogButtonBox;
class QLabel;
class QTreeWidget;
class QTreeWidgetItem;

/*
 * Per-tool diff preview before a security settings import.
 *
 * Security tool #12: an import should be an informed decision. The
 * dialog shows, for the osza-security-settings document the user
 * picked, what it would change in this profile - per tool and per
 * field, the current live value against the value after the import -
 * plus the tools the file does not mention (left unchanged) and the
 * sections that will be skipped, with their reasons. A mismatching
 * checksum is called out before anything else, and the confirmation
 * button says "Import anyway", so importing a file that was changed
 * after its export stays an explicit choice made with the diff in
 * view.
 *
 * The dialog itself never applies anything. The caller loads the
 * document (SecuritySettingsPorter::loadDocument), previews it
 * (previewDocument - the same validation the import applies), shows
 * this dialog, and only after acceptance runs applyDocument() on the
 * very same object the user has seen, with ChecksumPolicy::Allow
 * exactly when importDespiteChecksum() says the mismatch was
 * confirmed.
 */
class OSZA_EXPORT SecurityImportPreviewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SecurityImportPreviewDialog(const SecuritySettingsPorter::Preview &preview,
                                         const QString &fileName,
                                         QWidget *parent = nullptr);

    // True when the user accepted importing a document whose
    // checksum does not match. The caller must pass
    // SecuritySettingsPorter::ChecksumPolicy::Allow for exactly this
    // case - and only for it.
    bool importDespiteChecksum() const;

private:
    void buildUi(const QString &fileName);
    QTreeWidgetItem* toolItem(const QString &toolKey);

    SecuritySettingsPorter::Preview m_preview;

    QLabel* m_introLabel;
    QLabel* m_presetLabel;
    QTreeWidget* m_changesTree;
    QLabel* m_skipLabel;
    QLabel* m_unchangedLabel;
    QLabel* m_checksumLabel;
    QDialogButtonBox* m_buttons;
};

#endif // SECURITYIMPORTPREVIEWDIALOG_H
