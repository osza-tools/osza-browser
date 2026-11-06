/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2010-2014  David Rosca <nowrep@gmail.com>
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
#ifndef SITEINFOWIDGET_H
#define SITEINFOWIDGET_H

#include <QMenu>

#include "qzcommon.h"
#include <locationbarpopup.h>

class QLabel;

namespace Ui
{
class SiteInfoWidget;
}

class BrowserWindow;

class OSZA_EXPORT SiteInfoWidget : public LocationBarPopup
{
    Q_OBJECT
public:
    explicit SiteInfoWidget(BrowserWindow* window, QWidget* parent = nullptr);
    ~SiteInfoWidget();

private:
    void updateProtocolHandler();
    void protocolHandlerButtonClicked();
    void updateHttpsOnlyState();
    void httpsOnlyButtonClicked();
    void updateFingerprintState();
    void fingerprintButtonClicked();
    void updateGpcState();
    void gpcButtonClicked();
    void updateThreatBlockState();
    void threatBlockButtonClicked();
    void threatBlockUpdateButtonClicked();

    // Configure the "diff" link of a per-site entry: the same deep
    // link the security dashboard's tool rows carry - this tool's
    // part of the recommended baseline's diff, built only when it
    // can be honest (the porter's key list must know the key, the
    // catalog must carry the baseline), hidden otherwise.
    void setupToolDiffLink(QLabel *link, const QString &toolKey);

    Ui::SiteInfoWidget* ui;
    BrowserWindow* m_window;
};

#endif // SITEINFOWIDGET_H
