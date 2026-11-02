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
#include "httpsonlyexceptionsdialog.h"

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

HttpsOnlyExceptionsDialog::HttpsOnlyExceptionsDialog(const QStringList &exclusions, QWidget *parent)
    : QDialog(parent)
    , m_exclusions(exclusions)
{
    setWindowTitle(tr("HTTPS-Only exceptions"));
    setMinimumSize(420, 360);

    auto *description = new QLabel(tr("Sites on this list are never upgraded to HTTPS.\n"
                                      "Use it for servers that only work over plain HTTP."));
    description->setWordWrap(true);

    m_list = new QListWidget(this);
    m_list->setAlternatingRowColors(true);
    m_list->setSortingEnabled(true);

    for (const QString &exclusion : m_exclusions) {
        if (!exclusion.trimmed().isEmpty()) {
            m_list->addItem(exclusion.trimmed());
        }
    }

    m_edit = new QLineEdit(this);
    m_edit->setPlaceholderText(tr("example.com or *.example.com"));
    m_edit->setClearButtonEnabled(true);

    auto *addButton = new QPushButton(tr("Add"), this);
    auto *removeButton = new QPushButton(tr("Remove"), this);

    auto *editLayout = new QHBoxLayout;
    editLayout->addWidget(m_edit);
    editLayout->addWidget(addButton);
    editLayout->addWidget(removeButton);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);

    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(description);
    mainLayout->addWidget(m_list);
    mainLayout->addLayout(editLayout);
    mainLayout->addWidget(buttonBox);

    connect(m_edit, &QLineEdit::returnPressed, this, &HttpsOnlyExceptionsDialog::addExclusion);
    connect(addButton, &QAbstractButton::clicked, this, &HttpsOnlyExceptionsDialog::addExclusion);
    connect(removeButton, &QAbstractButton::clicked, this, &HttpsOnlyExceptionsDialog::removeSelected);
    connect(m_list, &QListWidget::itemSelectionChanged, this, [this, removeButton]() {
        removeButton->setEnabled(!m_list->selectedItems().isEmpty());
    });
    removeButton->setEnabled(false);

    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QStringList HttpsOnlyExceptionsDialog::exclusions() const
{
    QStringList result;

    for (int i = 0; i < m_list->count(); ++i) {
        const QString text = m_list->item(i)->text().trimmed();
        if (!text.isEmpty()) {
            result.append(text);
        }
    }

    return result;
}

void HttpsOnlyExceptionsDialog::addExclusion()
{
    const QString host = m_edit->text().trimmed();

    if (host.isEmpty()) {
        return;
    }

    for (int i = 0; i < m_list->count(); ++i) {
        if (m_list->item(i)->text().compare(host, Qt::CaseInsensitive) == 0) {
            m_edit->clear();
            return;
        }
    }

    m_list->addItem(host);
    m_edit->clear();
}

void HttpsOnlyExceptionsDialog::removeSelected()
{
    const auto selected = m_list->selectedItems();

    for (QListWidgetItem *item : selected) {
        delete m_list->takeItem(m_list->row(item));
    }
}
