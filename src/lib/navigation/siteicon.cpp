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
#include "siteicon.h"
#include "siteinfowidget.h"
#include "locationbar.h"
#include "tabbedwebview.h"
#include "qztools.h"
#include "siteinfo.h"

#include <QDrag>
#include <QPainter>
#include <QTimer>
#include <QMimeData>
#include <QApplication>
#include <QContextMenuEvent>

SiteIcon::SiteIcon(LocationBar *parent)
    : ToolButton(parent)
    , m_window(nullptr)
    , m_locationBar(parent)
    , m_view(nullptr)
    , m_listUpdating(false)
{
    setObjectName("locationbar-siteicon");
    setToolButtonStyle(Qt::ToolButtonIconOnly);
    setCursor(Qt::ArrowCursor);
    // The default tooltip - the string applyToolTip() restores when
    // neither the badge nor the pulse is in play, so it has exactly
    // one translation context.
    setToolTip(tr("Show information about this page"));
    setFocusPolicy(Qt::NoFocus);

    m_updateTimer = new QTimer(this);
    m_updateTimer->setInterval(100);
    m_updateTimer->setSingleShot(true);
    connect(m_updateTimer, &QTimer::timeout, this, &SiteIcon::updateIcon);

    // The breath: mid-cycle at the start (the indicator appears
    // decisively, then ebbs and swells), one phase step every tick,
    // recompositing through the one path every icon change takes.
    m_pulseTimer = new QTimer(this);
    m_pulseTimer->setInterval(80);
    m_pulsePhase = 0.5;
    connect(m_pulseTimer, &QTimer::timeout, this, &SiteIcon::advancePulse);
}

void SiteIcon::setBrowserWindow(BrowserWindow *window)
{
    m_window = window;
}

void SiteIcon::setWebView(WebView* view)
{
    m_view = view;
}

void SiteIcon::setRelaxedProtections(const QStringList &protections)
{
    if (m_relaxedProtections == protections) {
        return;
    }

    m_relaxedProtections = protections;

    applyToolTip();

    // The base icon is unchanged: only the badge rides on it, so
    // there is nothing to debounce - the new state shows at once.
    updateIcon();
}

QStringList SiteIcon::relaxedProtections() const
{
    return m_relaxedProtections;
}

void SiteIcon::setListUpdating(bool updating)
{
    if (m_listUpdating == updating) {
        return;
    }

    m_listUpdating = updating;

    if (m_listUpdating) {
        // Mid-breath at the onset: the glow arrives at its bright
        // center and ebbs from there, a decisive appearance rather
        // than a fade-in.
        m_pulsePhase = 0.5;
        m_pulseTimer->start();
    }
    else {
        m_pulseTimer->stop();
    }

    applyToolTip();

    // No debounce here either: the pulse is not the site's state
    // but the browser's activity, and it begins and ends at the
    // moment the manager says it does.
    updateIcon();
}

bool SiteIcon::listUpdating() const
{
    return m_listUpdating;
}

void SiteIcon::advancePulse()
{
    m_pulsePhase += 0.08;

    if (m_pulsePhase > 1.0) {
        m_pulsePhase -= 1.0;
    }

    updateIcon();
}

void SiteIcon::applyToolTip()
{
    // The tooltip of the moment: the standing per-site state first
    // (the relaxed protections, with the review hint), then the
    // pulse's note while a refresh runs - the two can speak side by
    // side, an exception standing while its evidence is renewed -
    // and the plain default when neither is in play.
    QStringList parts;

    if (!m_relaxedProtections.isEmpty()) {
        parts.append(relaxedProtectionsToolTip(m_relaxedProtections, true));
    }

    if (m_listUpdating) {
        parts.append(listUpdatingToolTip());
    }

    setToolTip(parts.isEmpty() ? tr("Show information about this page") : parts.join(QLatin1String(" ")));
}

void SiteIcon::setIcon(const QIcon &icon)
{
    bool wasNull = m_icon.isNull();

    m_icon = icon;

    if (wasNull) {
        updateIcon();
    }
    else {
        m_updateTimer->start();
    }
}

void SiteIcon::updateIcon()
{
    ToolButton::setIcon(composeBadgeIcon(m_icon));
}

void SiteIcon::popupClosed()
{
    setDown(false);
    Q_EMIT siteInfoClosed();
}

QIcon SiteIcon::composeBadgeIcon(const QIcon &icon) const
{
    if (m_relaxedProtections.isEmpty() && !m_listUpdating) {
        return icon;
    }

    const QPixmap base = icon.pixmap(QSize(16, 16));
    if (base.isNull()) {
        return icon;
    }

    // The badge is drawn in the icon's own 16-unit space and the
    // pixmap's device pixel ratio is kept, so a high-dpi source
    // (32 px at 2x) gets a proportionally sized dot through the
    // same code path - and wherever the style moves or scales the
    // icon, the badge rides on it. The pulse is painted first, as
    // the glow behind the glyph; the corner badge after, on top -
    // the two speak of different things and never cover each
    // other.
    QPixmap out(base.size());
    out.setDevicePixelRatio(base.devicePixelRatio());
    out.fill(Qt::transparent);

    QPainter p(&out);
    p.setRenderHint(QPainter::Antialiasing, true);

    if (m_listUpdating) {
        paintUpdatePulse(&p, QRectF(0, 0, 16, 16), m_pulsePhase);
    }

    p.drawPixmap(0, 0, base);

    if (!m_relaxedProtections.isEmpty()) {
        paintRelaxedBadge(&p, QRectF(0, 0, 16, 16));
    }

    p.end();

    return QIcon(out);
}

void SiteIcon::paintRelaxedBadge(QPainter *painter, const QRectF &iconArea)
{
    // Amber - the color between the suite's calm cyan and the
    // interstitial's red. A per-site exception is a deliberate,
    // reviewable choice the user made: attention, not alarm.
    const QColor dotColor(0xf5, 0xa5, 0x24);

    // A solid dot with a thin dark rim (so it reads on light
    // backgrounds too) inside a soft wider ring - the quiet glow
    // of the security pages, scaled down to chrome size. All
    // geometry derives from the icon area's width, so the 16 px
    // composite and the popup's larger icon area get the same
    // badge at their own scale.
    const qreal width = iconArea.width();
    const qreal dot = width * 5.5 / 16.0;
    const qreal gap = width * 0.5 / 16.0;
    const qreal glow = width * 1.0 / 16.0;

    QRectF dotRect(iconArea.right() - gap - dot, iconArea.bottom() - gap - dot, dot, dot);

    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->setPen(QPen(QColor(dotColor.red(), dotColor.green(), dotColor.blue(), 110), 1.1));
    painter->setBrush(Qt::NoBrush);
    painter->drawEllipse(dotRect.adjusted(-glow, -glow, glow, glow));

    painter->setPen(QPen(QColor(0x33, 0x1f, 0x00, 190), 0.9));
    painter->setBrush(dotColor);
    painter->drawEllipse(dotRect);
}

void SiteIcon::paintUpdatePulse(QPainter *painter, const QRectF &iconArea, qreal phase)
{
    // The suite's cyan, calmed for chrome: where amber speaks a
    // standing exception and the warning page speaks red, a
    // renewal in flight is the browser doing work for the user
    // right now - the same quiet glow the security pages carry,
    // scaled down to the location bar.
    const QColor pulseColor(0x00, 0xc8, 0xa8);

    // The breath: phase runs 0..1 and the brightness is the
    // triangle wave of it - dim at the edges, bright at the
    // center - so the halo swells and ebbs rather than blinks. All
    // geometry derives from the icon area's width, so the 16 px
    // composite and the popup's larger icon area breathe at their
    // own scale through the same numbers.
    const qreal breathe = 1.0 - qAbs(2.0 * phase - 1.0);

    const qreal width = iconArea.width();
    const qreal halo = width * (0.82 + 0.18 * breathe) / 2.0;
    const QPointF center = iconArea.center();
    const QRectF haloRect(center.x() - halo, center.y() - halo, halo * 2.0, halo * 2.0);

    painter->setRenderHint(QPainter::Antialiasing, true);

    // The halo behind the glyph, breathing with the phase; the rim
    // at its edge a touch stronger, so the breath reads on light
    // backgrounds too.
    painter->setPen(Qt::NoPen);
    painter->setBrush(QColor(pulseColor.red(), pulseColor.green(), pulseColor.blue(), 42 + 112 * breathe));
    painter->drawEllipse(haloRect);

    painter->setPen(QPen(QColor(pulseColor.red(), pulseColor.green(), pulseColor.blue(), 70 + 90 * breathe),
                         qMax(1.0, width * 0.7 / 16.0)));
    painter->setBrush(Qt::NoBrush);
    painter->drawEllipse(haloRect);
}

QString SiteIcon::relaxedProtectionsToolTip(const QStringList &protections, bool clickable)
{
    const QString names = protections.join(QLatin1String(", "));

    if (clickable) {
        return tr("Protections are relaxed for this site: %1. Click the icon to review them.").arg(names);
    }

    return tr("Protections are relaxed for this site: %1.").arg(names);
}

QString SiteIcon::listUpdatingToolTip()
{
    // One string, one context: both surfaces' tooltips name the
    // pulse through it, wherever the glow appears.
    return tr("The malicious-site blocklist is being refreshed now.");
}

void SiteIcon::contextMenuEvent(QContextMenuEvent* e)
{
    // Prevent propagating to LocationBar
    e->accept();
}

void SiteIcon::mousePressEvent(QMouseEvent* e)
{
    if (e->buttons() == Qt::LeftButton) {
        m_dragStartPosition = e->pos();
    }

    // Prevent propagating to LocationBar
    e->accept();

    ToolButton::mousePressEvent(e);
}

void SiteIcon::mouseReleaseEvent(QMouseEvent* e)
{
    // Mouse release event is restoring Down state
    // So we pause updates to prevent flicker

    bool activated = false;

    if (e->button() == Qt::LeftButton && rect().contains(e->pos())) {
        // Popup may not be always shown, eg. on osza: pages
        activated = showPopup();
    }

    if (activated) {
        setUpdatesEnabled(false);
    }

    ToolButton::mouseReleaseEvent(e);

    if (activated) {
        setDown(true);
        setUpdatesEnabled(true);
    }
}

void SiteIcon::mouseMoveEvent(QMouseEvent* e)
{
    if (!m_locationBar || e->buttons() != Qt::LeftButton) {
        ToolButton::mouseMoveEvent(e);
        return;
    }

    int manhattanLength = (e->pos() - m_dragStartPosition).manhattanLength();
    if (manhattanLength <= QApplication::startDragDistance()) {
        ToolButton::mouseMoveEvent(e);
        return;
    }

    const QUrl url = m_locationBar->webView()->url();
    const QString title = m_locationBar->webView()->title();

    if (url.isEmpty() || title.isEmpty()) {
        ToolButton::mouseMoveEvent(e);
        return;
    }

    auto* drag = new QDrag(this);
    auto* mime = new QMimeData;
    mime->setUrls(QList<QUrl>() << url);
    mime->setText(title);
    mime->setImageData(icon().pixmap(16).toImage());

    drag->setMimeData(mime);
    drag->setPixmap(QzTools::createPixmapForSite(icon(), title, url.toString()));
    drag->exec();

    // Restore Down state
    setDown(false);
}

bool SiteIcon::showPopup()
{
    if (!m_view || !m_window) {
        return false;
    }

    QUrl url = m_view->url();

    if (!SiteInfo::canShowSiteInfo(url))
        return false;

    setDown(true);

    // Parented to the window: the popup is a Qt::Popup that grabs
    // input, but the window can still be destroyed while it stands
    // (a page script closing the last tab), and an unparented popup
    // would survive that with a dangling window pointer - while the
    // threat-block manager's signals keep re-rendering its rows.
    // Dying with the window ends the connections with it.
    auto* info = new SiteInfoWidget(m_window, m_window);
    info->showAt(parentWidget());

    connect(info, &QObject::destroyed, this, &SiteIcon::popupClosed);

    return true;
}
