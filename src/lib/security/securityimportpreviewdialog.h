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
#include <QUrl>

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
 *
 * The dialog is shown with open(), not exec(): window-modal, so the
 * profile it previews cannot change under it (its parent window is
 * blocked for input), while the page it can link to - the diff as
 * the browser renders it - opens in its own window and can be read
 * beside the decision. A file saved from a built-in preset with a
 * matching checksum is exactly that preset's document, so the
 * osza:settings-diff page for the preset shows the same diff as this
 * dialog; such a file gets a "view as page" link, which follows the
 * tree selection tool by tool and asks the caller (through
 * diffPageRequested) to open the deep link. Files that only name a
 * preset, or carry no checksum or a mismatching one, are not
 * guaranteed to be the preset they claim - for them the link would
 * promise a diff the page cannot honestly show, so there is none.
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

Q_SIGNALS:
    // The "view as page" link was used: the osza:settings-diff URL
    // of the preset this file was saved from, focused on the
    // selected tool's section when the tree selection names one. The
    // caller decides where it opens - the import flows open it in a
    // window of its own, readable beside this dialog.
    void diffPageRequested(const QUrl &url);

private:
    void buildUi(const QString &fileName);
    void updateDiffPageLink();
    QString selectedToolKey() const;
    QTreeWidgetItem* toolItem(const QString &toolKey);

    SecuritySettingsPorter::Preview m_preview;

    // The built-in preset this file verifiably came from (a known id
    // plus a matching checksum), or empty when there is no page that
    // honestly shows this file's diff.
    QString m_presetId;

    QLabel* m_introLabel;
    QLabel* m_presetLabel;
    QLabel* m_viewPageLabel;
    QTreeWidget* m_changesTree;
    QLabel* m_skipLabel;
    QLabel* m_unchangedLabel;
    QLabel* m_checksumLabel;
    QDialogButtonBox* m_buttons;
};

#endif // SECURITYIMPORTPREVIEWDIALOG_H
