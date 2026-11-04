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
#include "securityimportpreviewdialog.h"

#include <QDialogButtonBox>
#include <QFont>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {

// "secureDns: a secure mode needs at least one server" becomes
// "Secure DNS (DNS-over-HTTPS): a secure mode needs at least one
// server" - the skip list speaks the same names as the diff above.
QString displaySkipEntry(const QString &entry)
{
    const int separator = entry.indexOf(QSL(": "));

    if (separator < 0) {
        return entry;
    }

    return QSL("%1: %2").arg(SecuritySettingsPorter::toolDisplayName(entry.left(separator)),
                               entry.mid(separator + 2));
}

} // namespace

SecurityImportPreviewDialog::SecurityImportPreviewDialog(const SecuritySettingsPorter::Preview &preview,
                                                         const QString &fileName,
                                                         QWidget *parent)
    : QDialog(parent)
    , m_preview(preview)
{
    buildUi(fileName);
}

void SecurityImportPreviewDialog::buildUi(const QString &fileName)
{
    setWindowTitle(tr("Import Security Settings"));
    setModal(true);

    auto *layout = new QVBoxLayout(this);
    layout->setSpacing(8);

    // The headline: what the file is and what it does here, before
    // any detail. The numbers come from the preview, which used the
    // same validation the import will run.
    m_introLabel = new QLabel(this);
    m_introLabel->setWordWrap(true);

    if (m_preview.changes.isEmpty()) {
        m_introLabel->setText(m_preview.configuredTools > 0
            ? tr("The file %1 configures %2 of the 7 security tools, but changes nothing that is set right now.")
                  .arg(fileName, QString::number(m_preview.configuredTools))
            : tr("The file %1 does not configure any security tool.").arg(fileName));
    } else {
        m_introLabel->setText(tr("The file %1 configures %2 of the 7 security tools and would change the following:")
                                  .arg(fileName, QString::number(m_preview.configuredTools)));
    }

    layout->addWidget(m_introLabel);

    // The diff itself: one top-level row per tool, one child row per
    // changed field. Current and future value sit next to each
    // other; long lists are elided in the columns but complete in
    // the tooltips.
    m_changesTree = new QTreeWidget(this);
    m_changesTree->setColumnCount(3);
    m_changesTree->setHeaderLabels(QStringList{tr("Setting"), tr("Current"), tr("After import")});
    m_changesTree->setRootIsDecorated(true);
    m_changesTree->setAllColumnsShowFocus(true);
    m_changesTree->setUniformRowHeights(true);
    m_changesTree->header()->setStretchLastSection(false);
    m_changesTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_changesTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_changesTree->header()->setSectionResizeMode(2, QHeaderView::Stretch);

    QString lastTool;
    QTreeWidgetItem *toolRow = nullptr;
    const QList<SecuritySettingsPorter::PreviewChange> &changes = m_preview.changes;

    for (const SecuritySettingsPorter::PreviewChange &change : changes) {
        if (change.tool != lastTool) {
            lastTool = change.tool;
            toolRow = toolItem(change.tool);
        }

        auto *fieldRow = new QTreeWidgetItem(toolRow);
        fieldRow->setText(0, SecuritySettingsPorter::fieldDisplayName(change.tool, change.field));
        fieldRow->setText(1, change.currentValue);
        fieldRow->setText(2, change.nextValue);
        fieldRow->setToolTip(1, change.currentValue);
        fieldRow->setToolTip(2, change.nextValue);
    }

    m_changesTree->expandAll();
    if (!m_preview.changes.isEmpty()) {
        m_changesTree->setMinimumHeight(180);
    } else {
        m_changesTree->hide();
    }

    layout->addWidget(m_changesTree, 1);

    // Sections the import will not touch, with the reason - shown
    // before the buttons, because they are part of the decision.
    m_skipLabel = new QLabel(this);
    m_skipLabel->setWordWrap(true);
    if (!m_preview.skippedTools.isEmpty()) {
        QStringList entries;
        const QStringList &skipped = m_preview.skippedTools;
        for (const QString &entry : skipped) {
            entries.append(displaySkipEntry(entry));
        }
        m_skipLabel->setText(tr("Will be skipped, the rest still applies:\n%1")
                                 .arg(entries.join(QSL("\n"))));
    } else {
        m_skipLabel->hide();
    }
    layout->addWidget(m_skipLabel);

    m_unchangedLabel = new QLabel(this);
    m_unchangedLabel->setWordWrap(true);
    if (!m_preview.unchangedTools.isEmpty()) {
        QStringList names;
        const QStringList &unchanged = m_preview.unchangedTools;
        for (const QString &tool : unchanged) {
            names.append(SecuritySettingsPorter::toolDisplayName(tool));
        }
        m_unchangedLabel->setText(tr("Not in the file, left unchanged: %1").arg(names.join(QSL(", "))));
    } else {
        m_unchangedLabel->hide();
    }
    layout->addWidget(m_unchangedLabel);

    // The checksum verdict. A mismatch is the loudest line in the
    // dialog, and it changes what the confirmation button says.
    m_checksumLabel = new QLabel(this);
    m_checksumLabel->setWordWrap(true);
    switch (m_preview.checksum) {
    case SecuritySettingsPorter::ChecksumState::Valid:
        m_checksumLabel->hide();
        break;
    case SecuritySettingsPorter::ChecksumState::NoChecksum:
        m_checksumLabel->setText(tr("The file carries no checksum; it was hand-edited or written by an older version."));
        break;
    case SecuritySettingsPorter::ChecksumState::Mismatch:
    default:
        m_checksumLabel->setText(tr("Warning: the file's checksum does not match its contents. It was changed or corrupted after it was exported."));
        break;
    }
    layout->addWidget(m_checksumLabel);

    m_buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, this);
    m_buttons->button(QDialogButtonBox::Ok)->setText(m_preview.checksum == SecuritySettingsPorter::ChecksumState::Mismatch
        ? tr("Import anyway")
        : tr("Import"));
    connect(m_buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    // A file with a mismatching checksum is a decision to make, not
    // a decision to suggest: Cancel is where Enter lands.
    if (m_preview.checksum == SecuritySettingsPorter::ChecksumState::Mismatch) {
        m_buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
    } else {
        m_buttons->button(QDialogButtonBox::Ok)->setDefault(true);
    }

    layout->addWidget(m_buttons);

    setMinimumSize(QSize(560, 320));
    resize(QSize(620, 440));
}

QTreeWidgetItem* SecurityImportPreviewDialog::toolItem(const QString &toolKey)
{
    // Top-level rows are created on demand, in the preview's fixed
    // tool order, so the diff reads the same top to bottom as the
    // security dashboard.
    auto *row = new QTreeWidgetItem(m_changesTree);
    row->setText(0, SecuritySettingsPorter::toolDisplayName(toolKey));
    row->setFirstColumnSpanned(true);
    QFont boldFont = row->font(0);
    boldFont.setBold(true);
    row->setFont(0, boldFont);
    return row;
}

bool SecurityImportPreviewDialog::importDespiteChecksum() const
{
    // Accepted with a mismatching checksum is exactly the "import
    // anyway" the button promised; anything else is no import at
    // all, or an import that needs no exception.
    return m_preview.checksum == SecuritySettingsPorter::ChecksumState::Mismatch
        && result() == QDialog::Accepted;
}
