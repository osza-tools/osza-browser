/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2010-2018 David Rosca <nowrep@gmail.com>
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
#ifndef SITEICON_H
#define SITEICON_H

#include "qzcommon.h"
#include "toolbutton.h"

#include <QRectF>
#include <QStringList>

class QPainter;
class QTimer;

class LocationBar;
class WebView;
class BrowserWindow;

class OSZA_EXPORT SiteIcon : public ToolButton
{
    Q_OBJECT

public:
    explicit SiteIcon(LocationBar *parent);

    void setBrowserWindow(BrowserWindow *window);
    void setWebView(WebView* view);
    void setIcon(const QIcon &icon);

    // The protections-relaxed badge: pass the display names of the
    // tools that are relaxed for this site (SecurityManager::
    // relaxedProtections keys resolved through the porter's
    // toolDisplayName). An empty list hides the badge and restores
    // the default tooltip; an unchanged list is a no-op, so the
    // location bar can refresh it on every state change cheaply.
    void setRelaxedProtections(const QStringList &protections);
    QStringList relaxedProtections() const;

    // The one drawing code for the badge: the location bar
    // composites it into the 16 px icon, the popup's location bar
    // paints it over its own icon area, and the two can never drift
    // apart. iconArea is the square the icon occupies, in logical
    // coordinates.
    static void paintRelaxedBadge(QPainter *painter, const QRectF &iconArea);

    // The badge's tooltip: the relaxed protections by name, with
    // the review hint where clicking the icon opens the padlock
    // menu (the popup's location bar has no menu to open, so it
    // passes false).
    static QString relaxedProtectionsToolTip(const QStringList &protections, bool clickable);

Q_SIGNALS:
    // The padlock menu closed: the per-site state may have changed
    // behind it (an HTTPS-Only exception on an https page does not
    // even reload the page), so the location bar refreshes the
    // badge on this signal.
    void siteInfoClosed();

private Q_SLOTS:
    void updateIcon();
    void popupClosed();

private:
    void contextMenuEvent(QContextMenuEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;

    bool showPopup();
    QIcon composeBadgeIcon(const QIcon &icon) const;

    BrowserWindow* m_window;
    LocationBar* m_locationBar;
    WebView* m_view;
    QTimer* m_updateTimer;

    QPoint m_dragStartPosition;
    QIcon m_icon;
    QStringList m_relaxedProtections;
};

#endif // SITEICON_H
