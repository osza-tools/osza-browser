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
#include "popuplocationbar.h"
#include "popupwebview.h"
#include "siteicon.h"
#include "toolbutton.h"
#include "qztools.h"
#include "iconprovider.h"
#include "bookmarksicon.h"
#include "autofillicon.h"
#include "webpage.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "securitymanager.h"
#include "securitysettingsporter.h"
#include "threatblockmanager.h"

#include <QPainter>
#include <QRectF>
#include <QTimer>

class OSZA_EXPORT PopupSiteIcon : public QWidget
{
public:
    explicit PopupSiteIcon(QWidget* parent = nullptr) : QWidget(parent)
        , m_listUpdating(false)
        , m_pulsePhase(0.5)
    {
        // The breath's driver, the same cadence the location bar's
        // composite breathes at: one phase step per tick, repainting
        // this bar's own icon area.
        m_pulseTimer = new QTimer(this);
        m_pulseTimer->setInterval(80);
        connect(m_pulseTimer, &QTimer::timeout, this, &PopupSiteIcon::advancePulse);
    }

    void setIcon(const QIcon &icon) {
        m_icon = QIcon(icon.pixmap(16));
        update();
    }

    // The same protections-relaxed badge the location bar
    // composites into its site icon, painted over this bar's own
    // icon area - one drawing code, two surfaces, no drift. The
    // names are the porter's display names, like in the location
    // bar; the popup has no padlock menu to open, so the tooltip
    // carries no review hint.
    void setRelaxedProtections(const QStringList &protections) {
        if (m_relaxedProtections == protections) {
            return;
        }
        m_relaxedProtections = protections;
        refreshToolTip();
        update();
    }

    // The same update-in-progress pulse the location bar composites
    // into its site icon, breathing behind this bar's own icon -
    // one drawing code, two surfaces, no drift. Set from the
    // manager's lifecycle signals like the location bar sets it;
    // an unchanged value is a no-op.
    void setListUpdating(bool updating) {
        if (m_listUpdating == updating) {
            return;
        }
        m_listUpdating = updating;

        if (m_listUpdating) {
            m_pulsePhase = 0.5;
            m_pulseTimer->start();
        }
        else {
            m_pulseTimer->stop();
        }

        refreshToolTip();
        update();
    }

private:
    QIcon m_icon;
    QStringList m_relaxedProtections;
    bool m_listUpdating;
    QTimer *m_pulseTimer;
    qreal m_pulsePhase;

    void advancePulse() {
        m_pulsePhase += 0.08;

        if (m_pulsePhase > 1.0) {
            m_pulsePhase -= 1.0;
        }

        update();
    }

    // The tooltip of the moment, the same composition the location
    // bar's icon speaks: the standing exception first, then the
    // pulse's note while a refresh runs; this bar has no padlock
    // menu and no default tooltip to restore.
    void refreshToolTip() {
        QStringList parts;

        if (!m_relaxedProtections.isEmpty()) {
            parts.append(SiteIcon::relaxedProtectionsToolTip(m_relaxedProtections, false));
        }

        if (m_listUpdating) {
            parts.append(SiteIcon::listUpdatingToolTip());
        }

        setToolTip(parts.isEmpty() ? QString() : parts.join(QLatin1String(" ")));
    }

    void paintEvent(QPaintEvent*) override {
        QPainter p(this);

        if (m_listUpdating) {
            SiteIcon::paintUpdatePulse(&p, QRectF(rect()), m_pulsePhase);
        }

        m_icon.paint(&p, rect());

        if (!m_relaxedProtections.isEmpty()) {
            SiteIcon::paintRelaxedBadge(&p, QRectF(rect()));
        }
    }
};

PopupLocationBar::PopupLocationBar(QWidget* parent)
    : LineEdit(parent)
    , m_view(nullptr)
{
    m_siteIcon = new PopupSiteIcon(this);
    m_siteIcon->setIcon(IconProvider::emptyWebIcon());
    m_siteIcon->setFixedSize(26, 26);

    m_bookmarkIcon = new BookmarksIcon(this);
    m_autofillIcon = new AutoFillIcon(this);

    auto* rightSpacer = new QWidget(this);
    rightSpacer->setFixedWidth(3);

    addWidget(m_siteIcon, LineEdit::LeftSide);
    addWidget(m_autofillIcon, LineEdit::RightSide);
    addWidget(m_bookmarkIcon, LineEdit::RightSide);
    addWidget(rightSpacer, LineEdit::RightSide);
    setLeftMargin(24);

    setFixedHeight(26);
    setReadOnly(true);

    // Hide icons by default
    m_autofillIcon->hide();

    // The blocklist refresh is browser-wide here too: the icon
    // breathes behind this bar while it runs and falls silent when
    // the evidence lands, the same pulse the main windows' location
    // bars carry - the manager's three lifecycle signals, the same
    // one in-flight query.
    auto *threatBlockManager = mApp->networkManager()->threatBlockManager();
    connect(threatBlockManager, &ThreatBlockManager::updateStarted, this, &PopupLocationBar::updateBlocklistIndicator);
    connect(threatBlockManager, &ThreatBlockManager::listUpdated, this, &PopupLocationBar::updateBlocklistIndicator);
    connect(threatBlockManager, &ThreatBlockManager::updateFailed, this, &PopupLocationBar::updateBlocklistIndicator);
    updateBlocklistIndicator();
}

void PopupLocationBar::setView(PopupWebView* view)
{
    m_view = view;

    m_bookmarkIcon->setWebView(m_view);
    m_autofillIcon->setWebView(m_view);

    // The badge follows the URL even when the favicon does not
    // change (a same-scheme navigation between two sites) and even
    // before the security state settles. It follows the two more
    // movements the main window's location bar gives its badge,
    // which no favicon change announces: a reload of the same
    // address (the padlock menu's and the import's changes land
    // there when nothing else fires) and a settings reload
    // (Preferences, an import or a preset - a tool switched off
    // globally retires the site's exception with it, and the badge
    // must not outlive the state it reports).
    connect(m_view, &QWebEngineView::urlChanged, this, &PopupLocationBar::showSiteIcon);
    connect(m_view, &QWebEngineView::loadFinished, this, &PopupLocationBar::showSiteIcon);
    connect(mApp, &MainApplication::settingsReloaded, this, &PopupLocationBar::showSiteIcon);
}

void PopupLocationBar::startLoading()
{
    m_autofillIcon->hide();

    updateTextMargins();
}

void PopupLocationBar::stopLoading()
{
    m_bookmarkIcon->checkBookmark(m_view->url());

    auto* page = qobject_cast<WebPage*>(m_view->page());

    if (page && !page->autoFillUsernames().isEmpty()) {
        m_autofillIcon->setUsernames(page->autoFillUsernames());
        m_autofillIcon->show();
    }

    updateTextMargins();
}

void PopupLocationBar::showUrl(const QUrl &url)
{
    setText(QzTools::urlEncodeQueryString(url));
    setCursorPosition(0);
}

void PopupLocationBar::showSiteIcon()
{
    QIcon icon = IconProvider::emptyWebIcon();
    if (property("secured").toBool()) {
        icon = QIcon::fromTheme(QSL("document-encrypted"), icon);
    }
    m_siteIcon->setIcon(QIcon(icon.pixmap(16)));

    // The same per-site state the location bar's badge reports,
    // through the same one query and the same one naming.
    QStringList protections;

    if (m_view) {
        const QStringList keys = SecurityManager::relaxedProtections(m_view->url());
        for (const QString &key : keys) {
            protections.append(SecuritySettingsPorter::toolDisplayName(key));
        }
    }

    m_siteIcon->setRelaxedProtections(protections);
}

void PopupLocationBar::setPrivacyState(bool state)
{
    setProperty("secured", QVariant(state));

    // The padlock follows the security state, the badge the URL;
    // refreshing here means the icon is right as soon as the state
    // is, not only the next time the favicon changes.
    showSiteIcon();
}

void PopupLocationBar::updateBlocklistIndicator()
{
    // The one query, the same one the location bar asks: the
    // manager's mutex-guarded in-flight flag, so this bar's pulse
    // and the main windows' can never disagree about whether a
    // refresh is running.
    m_siteIcon->setListUpdating(mApp->networkManager()->threatBlockManager()->isUpdating());
}
