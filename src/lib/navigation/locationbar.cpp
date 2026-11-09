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
#include "locationbar.h"
#include "browserwindow.h"
#include "tabbedwebview.h"
#include "mainapplication.h"
#include "webpage.h"
#include "tabwidget.h"
#include "bookmarksicon.h"
#include "bookmarks.h"
#include "bookmarkitem.h"
#include "bookmarkstoolbar.h"
#include "siteicon.h"
#include "goicon.h"
#include "downicon.h"
#include "qztools.h"
#include "iconprovider.h"
#include "qzsettings.h"
#include "colors.h"
#include "autofillicon.h"
#include "completer/locationcompleter.h"
#include "zoomlabel.h"
#include "networkmanager.h"
#include "securitymanager.h"
#include "securitysettingsporter.h"
#include "threatblockmanager.h"

#include <QTimer>
#include <QMimeData>
#include <QCompleter>
#include <QStringListModel>
#include <QContextMenuEvent>
#include <QStyleOptionFrame>
#include <QVariantAnimation>
#include <QPainterPath>
#include <QGradient>

LocationBar::LocationBar(QWidget *parent)
    : LineEdit(parent)
    , m_window(nullptr)
    , m_webView(nullptr)
    , m_holdingAlt(false)
    , m_oldTextLength(0)
    , m_currentTextLength(0)
    , m_loadProgress(0)
    , m_progressVisible(false)
{
    setObjectName("locationbar");
    setDragEnabled(true);

    // Disable KDE QLineEdit transitions, it breaks with setText() && home()
    setProperty("_kde_no_animations", QVariant(true));

    m_bookmarkIcon = new BookmarksIcon(this);
    m_goIcon = new GoIcon(this);
    m_siteIcon = new SiteIcon(this);
    m_autofillIcon = new AutoFillIcon(this);
    auto* down = new DownIcon(this);
    m_zoomlabel = new ZoomLabel(this);

    addWidget(m_siteIcon, LineEdit::LeftSide);
    addWidget(m_zoomlabel, LineEdit::RightSide);
    addWidget(m_autofillIcon, LineEdit::RightSide);
    addWidget(m_bookmarkIcon, LineEdit::RightSide);
    addWidget(m_goIcon, LineEdit::RightSide);
    addWidget(down, LineEdit::RightSide);

    m_completer = new LocationCompleter(this);
    m_completer->setLocationBar(this);
    connect(m_completer, &LocationCompleter::showCompletion, this, &LocationBar::showCompletion);
    connect(m_completer, &LocationCompleter::showDomainCompletion, this, &LocationBar::showDomainCompletion);
    connect(m_completer, &LocationCompleter::clearCompletion, this, &LocationBar::clearCompletion);
    connect(m_completer, &LocationCompleter::loadRequested, this, &LocationBar::loadRequest);
    connect(m_completer, &LocationCompleter::popupClosed, this, &LocationBar::updateSiteIcon);

    m_domainCompleterModel = new QStringListModel(this);
    auto* domainCompleter = new QCompleter(this);
    domainCompleter->setCompletionMode(QCompleter::InlineCompletion);
    domainCompleter->setModel(m_domainCompleterModel);
    setCompleter(domainCompleter);

    m_progressTimer = new QTimer(this);
    m_progressTimer->setInterval(700);
    m_progressTimer->setSingleShot(true);
    connect(m_progressTimer, &QTimer::timeout, this, &LocationBar::hideProgress);

    // The eased load-progress treatment. The engine reports progress
    // in bursts, so the painted value never follows those reports
    // directly: the glide eases toward each new target from wherever
    // the display stands (OutCubic, ~320 ms - fast enough to keep up
    // with a chatty page, slow enough to read as motion), and once a
    // load finishes and the dwell timer fires, the fade eases the
    // whole treatment out instead of dropping it.
    m_progressGlide = new QVariantAnimation(this);
    m_progressGlide->setStartValue(0);
    m_progressGlide->setEndValue(0);
    m_progressGlide->setDuration(320);
    m_progressGlide->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_progressGlide, &QVariantAnimation::valueChanged, this, &LocationBar::progressGlideAdvanced);

    m_progressFade = new QVariantAnimation(this);
    m_progressFade->setStartValue(1.0);
    m_progressFade->setEndValue(0.0);
    m_progressFade->setDuration(300);
    m_progressFade->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_progressFade, &QVariantAnimation::valueChanged, this, &LocationBar::progressFadeAdvanced);
    connect(m_progressFade, &QVariantAnimation::finished, this, &LocationBar::progressFadeFinished);

    editAction(PasteAndGo)->setText(tr("Paste And &Go"));
    editAction(PasteAndGo)->setIcon(QIcon::fromTheme(QSL("edit-paste")));
    connect(editAction(PasteAndGo), &QAction::triggered, this, &LocationBar::pasteAndGo);

    connect(this, SIGNAL(textEdited(QString)), this, SLOT(textEdited(QString)));
    connect(m_goIcon, &ClickableLabel::clicked, this, &LocationBar::requestLoadUrl);
    connect(down, &ClickableLabel::clicked, m_completer, &LocationCompleter::showMostVisited);
    connect(mApp->searchEnginesManager(), &SearchEnginesManager::activeEngineChanged, this, &LocationBar::updatePlaceHolderText);
    connect(mApp->searchEnginesManager(), &SearchEnginesManager::defaultEngineChanged, this, &LocationBar::updatePlaceHolderText);
    connect(mApp, &MainApplication::settingsReloaded, this, &LocationBar::loadSettings);

    // The padlock menu closing is the one moment the per-site state
    // can change without this bar seeing an urlChanged or a load
    // (an HTTPS-Only exception on an https page does not reload).
    connect(m_siteIcon, &SiteIcon::siteInfoClosed, this, &LocationBar::updateProtectionsBadge);

    // The blocklist refresh is browser-wide activity, and this bar
    // is where it becomes visible: the padlock badge breathes while
    // a refresh runs - wherever it started (the manager's own
    // timer, the padlock menu's renewal button, the warning page's
    // "refresh now" link, or the revoke of a "proceed anyway") -
    // and falls silent the moment the evidence lands or the failure
    // is named. The manager's three lifecycle signals carry it end
    // to end; the one query reads the same mutex-guarded in-flight
    // flag every other surface reports through.
    auto *threatBlockManager = mApp->networkManager()->threatBlockManager();
    connect(threatBlockManager, &ThreatBlockManager::updateStarted, this, &LocationBar::updateBlocklistIndicator);
    connect(threatBlockManager, &ThreatBlockManager::listUpdated, this, &LocationBar::updateBlocklistIndicator);
    connect(threatBlockManager, &ThreatBlockManager::updateFailed, this, &LocationBar::updateBlocklistIndicator);
    updateBlocklistIndicator();

    loadSettings();

    updateSiteIcon();

    // Hide icons by default
    m_goIcon->setVisible(qzSettings->alwaysShowGoIcon);
    m_autofillIcon->hide();

    auto inputMethodFlags = Qt::InputMethodHint::ImhNoAutoUppercase
                          | Qt::InputMethodHint::ImhUrlCharactersOnly;
    if (mApp->isPrivate()) {
        inputMethodFlags |= Qt::InputMethodHint::ImhSensitiveData;
    }
    setInputMethodHints(inputMethodFlags);

    QTimer::singleShot(0, this, &LocationBar::updatePlaceHolderText);
}

BrowserWindow *LocationBar::browserWindow() const
{
    return m_window;
}

void LocationBar::setBrowserWindow(BrowserWindow *window)
{
    m_window = window;
    m_completer->setMainWindow(m_window);
    m_siteIcon->setBrowserWindow(m_window);
}

TabbedWebView* LocationBar::webView() const
{
    return m_webView;
}

void LocationBar::setWebView(TabbedWebView* view)
{
    m_webView = view;

    m_bookmarkIcon->setWebView(m_webView);
    m_siteIcon->setWebView(m_webView);
    m_zoomlabel->setWebView(m_webView);
    m_autofillIcon->setWebView(m_webView);

    connect(m_webView, &QWebEngineView::loadStarted, this, &LocationBar::loadStarted);
    connect(m_webView, &QWebEngineView::loadProgress, this, &LocationBar::loadProgress);
    connect(m_webView, &QWebEngineView::loadFinished, this, &LocationBar::loadFinished);
    connect(m_webView, &QWebEngineView::urlChanged, this, &LocationBar::showUrl);
    connect(m_webView, &QWebEngineView::urlChanged, this, &LocationBar::updateProtectionsBadge);
    connect(m_webView, &WebView::privacyChanged, this, &LocationBar::setPrivacyState);
}

void LocationBar::setText(const QString &text)
{
    m_oldTextLength = text.length();
    m_currentTextLength = m_oldTextLength;

    LineEdit::setText(text);

    refreshTextFormat();
}

void LocationBar::updatePlaceHolderText()
{
    if (qzSettings->searchFromAddressBar) {
        setPlaceholderText(tr("Enter address or search with %1").arg(searchEngine().name));
    } else
        setPlaceholderText(tr("Enter address"));
}

void LocationBar::showCompletion(const QString &completion, bool completeDomain)
{
    LineEdit::setText(completion);

    // Move cursor to the end
    end(false);

    if (completeDomain) {
        completer()->complete();
    }

    updateSiteIcon();
}

void LocationBar::clearCompletion()
{
    m_webView->setFocus();
    showUrl(m_webView->url());
}

void LocationBar::showDomainCompletion(const QString &completion)
{
    m_domainCompleterModel->setStringList(QStringList() << completion);

    // We need to manually force the completion because model is updated asynchronously
    // But only force completion when the user actually added new text
    if (!completion.isEmpty() && m_oldTextLength < m_currentTextLength)
        completer()->complete();
}

QString LocationBar::convertUrlToText(const QUrl &url)
{
    // It was most probably entered by user, so don't urlencode it
    // Also don't urlencode JavaScript code
    if (url.scheme().isEmpty() || url.scheme() == QL1S("javascript")) {
        return QUrl::fromPercentEncoding(url.toEncoded());
    }

    QString stringUrl = QzTools::urlEncodeQueryString(url);

    if (stringUrl == QL1S("osza:speeddial") || stringUrl == QL1S("about:blank")) {
        stringUrl.clear();
    }

    return stringUrl;
}

SearchEnginesManager::Engine LocationBar::searchEngine()
{
    if (!qzSettings->searchFromAddressBar) {
        return {};
    } else if (qzSettings->searchWithDefaultEngine) {
        return mApp->searchEnginesManager()->defaultEngine();
    } else {
        return mApp->searchEnginesManager()->activeEngine();
    }
}

LocationBar::SearchEngineSuggestion LocationBar::suggestSearchEngine(const QString &text) {
    const QString &t = text.trimmed();

    const int firstSpacePos = t.indexOf(QLatin1Char(' '));
    if (qzSettings->searchFromAddressBar && firstSpacePos != -1) {
        const QString shortcut = t.left(firstSpacePos);
        const QString searchString = t.mid(firstSpacePos).trimmed();

        SearchEngine searchEngine =
            mApp->searchEnginesManager()->engineForShortcut(shortcut);
        if (searchEngine.isValid()) {
            return {searchEngine, searchString};
        }
    }

    return {searchEngine(), t};
}

LocationBar::LoadAction LocationBar::loadAction(const QString &text)
{
    LoadAction action;

    const QString &t = text.trimmed();

    if (t.isEmpty()) {
        return action;
    }

    // Check for Search Engine shortcut
    const int firstSpacePos = t.indexOf(QLatin1Char(' '));
    if (qzSettings->searchFromAddressBar && firstSpacePos != -1) {
        const QString shortcut = t.left(firstSpacePos);
        const QString searchedString = t.mid(firstSpacePos).trimmed();

        SearchEngine en = mApp->searchEnginesManager()->engineForShortcut(shortcut);
        if (en.isValid()) {
            action.type = LoadAction::Search;
            action.searchEngine = en;
            action.loadRequest = mApp->searchEnginesManager()->searchResult(en, searchedString);
            return action;
        }
    }

    // Check for Bookmark keyword
    const QList<BookmarkItem*> items = mApp->bookmarks()->searchKeyword(t);
    if (!items.isEmpty()) {
        BookmarkItem* item = items.at(0);
        action.type = LoadAction::Bookmark;
        action.bookmark = item;
        action.loadRequest.setUrl(item->url());
        return action;
    }

    if (!qzSettings->searchFromAddressBar) {
        const QUrl &guessedUrl = QUrl::fromUserInput(t);
        if (guessedUrl.isValid()) {
            action.type = LoadAction::Url;
            action.loadRequest = guessedUrl;
        }
        return action;
    }

    // Check for one word search
    if (t != QL1S("localhost")
            && !QzTools::containsSpace(t)
            && !t.contains(QL1C('.'))
            && !t.contains(QL1C(':'))
            && !t.contains(QL1C('/'))
       ) {
        action.type = LoadAction::Search;
        action.searchEngine = searchEngine();
        action.loadRequest = mApp->searchEnginesManager()->searchResult(searchEngine(), t);
        return action;
    }

    // Otherwise load as url
    const QUrl guessedUrl = QUrl::fromUserInput(t);
    if (guessedUrl.isValid()) {
        // Always allow javascript: to be loaded
        const bool forceLoad = guessedUrl.scheme() == QL1S("javascript");
        // Only allow spaces in query
        if (forceLoad || !QzTools::containsSpace(t) || !QzTools::containsSpace(guessedUrl.toString(QUrl::RemoveQuery))) {
            // Only allow supported schemes
            if (forceLoad || WebPage::supportedSchemes().contains(guessedUrl.scheme())) {
                action.type = LoadAction::Url;
                action.loadRequest = guessedUrl;
                return action;
            }
        }
    }

    // Search when creating url failed
    action.type = LoadAction::Search;
    action.searchEngine = searchEngine();
    action.loadRequest = mApp->searchEnginesManager()->searchResult(searchEngine(), t);
    return action;
}

void LocationBar::refreshTextFormat()
{
    if (!m_webView) {
        return;
    }

    TextFormat textFormat;
    const QString hostName = m_webView->url().isEmpty() ? QUrl(text()).host() : m_webView->url().host();

    if (!hostName.isEmpty()) {
        const int hostPos = text().indexOf(hostName);

        if (hostPos > 0) {
            QTextCharFormat format;
            format.setForeground(Colors::mid(palette().color(QPalette::Base), palette().color(QPalette::Text), 1, 1));

            QTextLayout::FormatRange schemePart;
            schemePart.start = 0;
            schemePart.length = hostPos;
            schemePart.format = format;

            QTextLayout::FormatRange hostPart;
            hostPart.start = hostPos;
            hostPart.length = hostName.size();

            QTextLayout::FormatRange remainingPart;
            remainingPart.start = hostPos + hostName.size();
            remainingPart.length = text().size() - remainingPart.start;
            remainingPart.format = format;

            textFormat.append(schemePart);
            textFormat.append(hostPart);
            textFormat.append(remainingPart);
        }
    }

    setTextFormat(textFormat);
}

void LocationBar::requestLoadUrl()
{
    loadRequest(loadAction(text()).loadRequest);
    updateSiteIcon();
}

void LocationBar::textEdited(const QString &text)
{
    m_oldTextLength = m_currentTextLength;
    m_currentTextLength = text.length();

    if (!text.isEmpty()) {
        m_completer->complete(text);
        m_siteIcon->setIcon(QIcon::fromTheme(QSL("edit-find"), QIcon(QSL(":icons/menu/search-icon.svg"))));
        // The icon is the search icon while typing: the site's
        // badge has no business riding on it. updateSiteIcon()
        // recomputes it when the completer closes.
        m_siteIcon->setRelaxedProtections(QStringList());
    }
    else {
        m_completer->closePopup();
    }

    setGoIconVisible(true);
}

void LocationBar::setGoIconVisible(bool state)
{
    if (state) {
        m_bookmarkIcon->hide();
        m_zoomlabel->hide();
        m_goIcon->show();
    }
    else {
        m_bookmarkIcon->show();
        m_zoomlabel->requestShow();

        if (!qzSettings->alwaysShowGoIcon) {
            m_goIcon->hide();
        }
    }

    updateTextMargins();
}

void LocationBar::showUrl(const QUrl &url)
{
    if (hasFocus() || url.isEmpty()) {
        return;
    }

    const QString stringUrl = convertUrlToText(url);

    if (text() == stringUrl) {
        home(false);
        refreshTextFormat();
        return;
    }

    // Set converted url as text
    setText(stringUrl);

    // Move cursor to the start
    home(false);

    m_bookmarkIcon->checkBookmark(url);
}

void LocationBar::loadRequest(const LoadRequest &request)
{
    if (!m_webView->webTab()->isRestored()) {
        return;
    }

    const QString urlString = convertUrlToText(request.url());

    m_completer->closePopup();
    m_webView->setFocus();

    if (urlString != text()) {
        setText(urlString);
    }

    m_webView->userLoadAction(request);
}

void LocationBar::updateSiteIcon()
{
    if (m_completer->isVisible()) {
        // Searching: the search icon carries no site state.
        m_siteIcon->setRelaxedProtections(QStringList());
        m_siteIcon->setIcon(QIcon::fromTheme(QSL("edit-find"), QIcon(QSL(":icons/menu/search-icon.svg"))));
        return;
    }

    QIcon icon = IconProvider::emptyWebIcon();
    if (property("secured").toBool()) {
        auto* nm =  mApp->networkManager();
        auto host = m_webView->url().host();

        if (nm->ignoredSslHosts().contains(host) || nm->ignoredSslErrors().contains(host)) {
            icon = QIcon::fromTheme(QSL("security-medium"), icon);
        }
        else if (nm->rejectedSslErrors().contains(host)) {
            icon = QIcon::fromTheme(QSL("security-low"), icon);
        }
        else {
            icon = QIcon::fromTheme(QSL("document-encrypted"), icon);
        }
    }
    m_siteIcon->setIcon(QIcon(icon.pixmap(16)));

    updateProtectionsBadge();
}

void LocationBar::updateProtectionsBadge()
{
    // The one query and the one naming: the badge's state comes
    // from SecurityManager::relaxedProtections, its labels from
    // the porter's catalog - the same names the padlock menu's
    // rows and the settings diff carry, so the tooltip and the
    // menu below it can never disagree about what is relaxed.
    // Called from every place the state can move: urlChanged
    // (navigation, even same-scheme and even while focused),
    // updateSiteIcon (privacy change, completer closing, a load
    // issued from the bar), loadFinished (reloads - the padlock
    // menu's and the import's changes land here when nothing else
    // fires), loadSettings (a global switch turned off retires
    // the site's exception with it) and the padlock menu closing.
    QStringList protections;

    if (m_webView) {
        const QStringList keys = SecurityManager::relaxedProtections(m_webView->url());
        for (const QString &key : keys) {
            protections.append(SecuritySettingsPorter::toolDisplayName(key));
        }
    }

    m_siteIcon->setRelaxedProtections(protections);
}

void LocationBar::updateBlocklistIndicator()
{
    // The one query: the manager's own in-flight flag, read through
    // the same mutex-guarded isUpdating() the warning page, the
    // padlock row and the sidebar report through - so the pulse and
    // the states below it can never disagree about whether a
    // refresh is running. The per-site state plays no part here:
    // the pulse rides whatever icon the bar currently shows, the
    // browser's activity over the site's identity.
    m_siteIcon->setListUpdating(mApp->networkManager()->threatBlockManager()->isUpdating());
}

void LocationBar::setPrivacyState(bool state)
{
    m_siteIcon->setProperty("secured", QVariant(state));
    m_siteIcon->style()->unpolish(m_siteIcon);
    m_siteIcon->style()->polish(m_siteIcon);

    setProperty("secured", QVariant(state));
    style()->unpolish(this);
    style()->polish(this);

    updateSiteIcon();
}

void LocationBar::pasteAndGo()
{
    clear();
    paste();
    requestLoadUrl();
}

void LocationBar::contextMenuEvent(QContextMenuEvent* event)
{
    QMenu* menu = createContextMenu();
    menu->setAttribute(Qt::WA_DeleteOnClose);

    // Prevent choosing first option with double rightclick
    QPoint pos = event->globalPos();
    pos.setY(pos.y() + 1);
    menu->popup(pos);
}

void LocationBar::showEvent(QShowEvent* event)
{
    LineEdit::showEvent(event);

    refreshTextFormat();
}

void LocationBar::focusInEvent(QFocusEvent* event)
{
    if (m_webView) {
        const QString stringUrl = convertUrlToText(m_webView->url());

        // Text has been edited, let's show go button
        if (stringUrl != text()) {
            setGoIconVisible(true);
        }
    }

    clearTextFormat();
    LineEdit::focusInEvent(event);

    if (m_window && Settings().value(QSL("Browser-View-Settings/instantBookmarksToolbar")).toBool()) {
        m_window->bookmarksToolbar()->show();
    }
}

void LocationBar::focusOutEvent(QFocusEvent* event)
{
    // Context menu or completer popup were opened
    // Let's block focusOutEvent to trick QLineEdit and paint cursor properly
    if (event->reason() == Qt::PopupFocusReason) {
        return;
    }

    LineEdit::focusOutEvent(event);

    setGoIconVisible(false);

    if (text().trimmed().isEmpty()) {
        clear();
    }

    refreshTextFormat();

    if (m_window && Settings().value(QSL("Browser-View-Settings/instantBookmarksToolbar")).toBool()) {
        m_window->bookmarksToolbar()->hide();
    }
}

void LocationBar::dropEvent(QDropEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        const QUrl dropUrl = event->mimeData()->urls().at(0);
        if (WebView::isUrlValid(dropUrl)) {
            setText(dropUrl.toString());
            loadRequest(dropUrl);

            QFocusEvent event(QFocusEvent::FocusOut);
            LineEdit::focusOutEvent(&event);
            return;
        }
    }
    else if (event->mimeData()->hasText()) {
        const QString dropText = event->mimeData()->text().trimmed();
        const QUrl dropUrl = QUrl(dropText);
        if (WebView::isUrlValid(dropUrl)) {
            setText(dropUrl.toString());
            loadRequest(dropUrl);

            QFocusEvent event(QFocusEvent::FocusOut);
            LineEdit::focusOutEvent(&event);
            return;
        } else {
            setText(dropText);
            setFocus();
            return;
        }
    }

    LineEdit::dropEvent(event);
}

void LocationBar::keyPressEvent(QKeyEvent* event)
{
    switch (event->key()) {
    case Qt::Key_V:
        if (event->modifiers() == (Qt::ControlModifier | Qt::ShiftModifier)) {
            pasteAndGo();
            event->accept();
            return;
        }
        break;

    case Qt::Key_Down:
        m_completer->complete(text());
        break;

    case Qt::Key_Left:
        m_completer->closePopup();
        break;

    case Qt::Key_Escape:
        m_webView->setFocus();
        showUrl(m_webView->url());
        event->accept();
        break;

    case Qt::Key_Alt:
        m_holdingAlt = true;
        break;

    case Qt::Key_Return:
    case Qt::Key_Enter:
        switch (event->modifiers()) {
        case Qt::ControlModifier:
            if (!text().endsWith(QL1S(".com")))
                setText(text().append(QL1S(".com")));
            requestLoadUrl();
            m_holdingAlt = false;
            break;

        case Qt::AltModifier:
            m_completer->closePopup();
            if (m_window) {
                m_window->tabWidget()->addView(loadAction(text()).loadRequest);
            }
            m_holdingAlt = false;
            break;

        default:
            requestLoadUrl();
            m_holdingAlt = false;
        }

        break;

    case Qt::Key_0:
    case Qt::Key_1:
    case Qt::Key_2:
    case Qt::Key_3:
    case Qt::Key_4:
    case Qt::Key_5:
    case Qt::Key_6:
    case Qt::Key_7:
    case Qt::Key_8:
    case Qt::Key_9:
        if (event->modifiers() & Qt::AltModifier || event->modifiers() & Qt::ControlModifier) {
            event->ignore();
            m_holdingAlt = false;
            return;
        }
        break;

    default:
        m_holdingAlt = false;
    }

    LineEdit::keyPressEvent(event);
}

void LocationBar::loadStarted()
{
    m_progressVisible = true;
    m_progressTimer->stop();
    m_progressGlide->stop();
    m_progressFade->stop();
    // A fresh navigation restarts the story from zero: whatever the
    // previous page was doing (gliding, dwelling, fading) is over.
    m_loadProgress = 0;
    m_displayProgress = 0;
    m_progressOpacity = 1.0;
    m_autofillIcon->hide();
    update();
}

void LocationBar::loadProgress(int progress)
{
    if (qzSettings->showLoadingProgress) {
        m_loadProgress = progress;
        retargetProgressGlide(progress);
    }
}

void LocationBar::loadFinished()
{
    if (qzSettings->showLoadingProgress) {
        // Even a page that never reported intermediate progress gets
        // its completed glide, so every load ends the same way: the
        // bar sweeps to 100, dwells there briefly, then fades.
        m_loadProgress = 100;
        retargetProgressGlide(100);
        m_progressTimer->start();
    }

    auto* page = qobject_cast<WebPage*>(m_webView->page());

    if (page && !page->autoFillUsernames().isEmpty()) {
        m_autofillIcon->setUsernames(page->autoFillUsernames());
        m_autofillIcon->show();
    }

    // A reload changes the per-site state without an urlChanged -
    // the badge answers for the page as it finished loading.
    updateProtectionsBadge();
}

void LocationBar::loadSettings()
{
    Settings settings;
    settings.beginGroup(QSL("AddressBar"));
    // The eased accent line is the out-of-the-box experience; the
    // classic Fill/Bottom/Top choices stay available and, once
    // written by Preferences, keep their stored index.
    m_progressStyle = static_cast<ProgressStyle>(settings.value(QSL("ProgressStyle"), ProgressAccentLine).toInt());
    bool customColor = settings.value(QSL("UseCustomProgressColor"), false).toBool();
    m_progressColor = customColor ? settings.value(QSL("CustomProgressColor"), palette().color(QPalette::Highlight)).value<QColor>() : QColor();
    settings.endGroup();

    // A tool switched off globally retires the site's exception
    // with it (Preferences, imports) - the badge must not outlive
    // the state it reports.
    updateProtectionsBadge();
}

void LocationBar::hideProgress()
{
    // The dwell is over: ease the treatment out rather than dropping
    // it. Restarting from full opacity is safe here - the fade is
    // only ever started by this slot or reset by loadStarted().
    if (qzSettings->showLoadingProgress) {
        m_progressFade->stop();
        m_progressFade->start();
    }
}

void LocationBar::progressGlideAdvanced(const QVariant &value)
{
    m_displayProgress = value.toInt();
    update();
}

void LocationBar::progressFadeAdvanced(const QVariant &value)
{
    m_progressOpacity = value.toReal();
    update();
}

void LocationBar::progressFadeFinished()
{
    m_progressVisible = false;
    update();
}

void LocationBar::retargetProgressGlide(int target)
{
    // Only the animation writes m_displayProgress, so the retarget
    // always starts from the value currently on screen - a burst of
    // reports mid-glide redirects the same motion instead of cutting
    // to a new one.
    if (target == m_displayProgress) {
        m_progressGlide->stop();
        return;
    }

    m_progressGlide->stop();
    m_progressGlide->setStartValue(m_displayProgress);
    m_progressGlide->setEndValue(target);
    m_progressGlide->start();
}

QColor LocationBar::progressAccentColor() const
{
    // The custom color wins when set; otherwise the palette's
    // Highlight carries the theme's accent - mint under the cyber
    // theme (its #locationbar rule sets selection-background-color:
    // #00ffd1, which is exactly the Highlight role for this widget),
    // violet under the private variant, and the system accent on
    // every other palette.
    if (m_progressColor.isValid() && m_progressColor.alpha() > 0) {
        return m_progressColor;
    }
    return palette().color(QPalette::Highlight);
}

void LocationBar::paintEvent(QPaintEvent* event)
{
    LineEdit::paintEvent(event);

    // Show loading progress - the eased treatment. Everything painted
    // here follows m_displayProgress (the glide's value, never the
    // engine's raw burst) and fades out through m_progressOpacity.
    if (qzSettings->showLoadingProgress && m_progressVisible) {
        QStyleOptionFrame option;
        initStyleOption(&option);

        QMargins margins = textMargins();

        QRect contentsRect = style()->subElementRect(QStyle::SE_LineEditContents, &option, this);
        contentsRect.adjust(
            margins.left(), margins.top(), -margins.right(), -margins.bottom()
        );

        const int progress = qBound(0, m_displayProgress, 100);
        const bool rtl = layoutDirection() == Qt::RightToLeft;

        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setOpacity(m_progressOpacity);

        switch (m_progressStyle) {
        case ProgressFilled: {
            // Paints over the text, so the calm mid-tone and the
            // softened opacity stay - the look the classic styles
            // always had, now carried by the eased value.
            QColor bg = m_progressColor;
            if (!bg.isValid() || bg.alpha() == 0) {
                bg = Colors::mid(palette().color(QPalette::Base), palette().color(QPalette::Text), 8, 1);
            }

            QRect bar = contentsRect.adjusted(0, 1, 0, -1);
            bar.setWidth(bar.width() * progress / 100);
            if (rtl) {
                bar.moveRight(contentsRect.right());
            }
            const int roundness = bar.height() / 4.0;

            p.setOpacity(0.5 * m_progressOpacity);
            p.setBrush(QBrush(bg));
            p.setPen(QPen(bg.darker(110), 0.8));
            p.drawRoundedRect(bar, roundness, roundness);
            break;
        }
        case ProgressBottom:
        case ProgressTop: {
            // The thin edge lines now ride the theme's accent - they
            // never cover text, so the full accent reads cleanly.
            const QColor accent = progressAccentColor();
            const bool bottom = m_progressStyle == ProgressBottom;
            const QRect track = bottom
                ? QRect(contentsRect.x(), contentsRect.bottom() - 3, contentsRect.width(), 3)
                : QRect(contentsRect.x(), contentsRect.top() + 1, contentsRect.width(), 3);

            QRect bar = track;
            bar.setWidth(track.width() * progress / 100);
            if (rtl) {
                bar.moveRight(track.right());
            }

            p.setPen(Qt::NoPen);
            p.setBrush(QBrush(accent));
            p.drawRoundedRect(bar, 1, 1);
            break;
        }
        case ProgressAccentLine: {
            // The showcase treatment: an accent line riding the
            // bottom edge of the pill, a soft glow rising from it,
            // a brighter tip leading the motion with a small bloom,
            // and a whisper fill over the loaded region - all riding
            // the palette's Highlight, so each theme's accent simply
            // arrives (mint for the cyber theme, violet for the
            // private variant, the system accent elsewhere).
            const QColor accent = progressAccentColor();

            // The inner field, inside the widget's 1 px border; the
            // line is drawn on the widget geometry (not the text
            // rect) so it spans the whole pill.
            const QRect field = rect().adjusted(1, 1, -1, -1);
            // Keep the line's rounded caps clear of the pill's
            // curvature (16 px radius, 30+ px field height).
            const int inset = 10;
            const int trackWidth = field.width() - 2 * inset;
            const int loadedWidth = qRound(trackWidth * progress / 100.0);
            if (loadedWidth <= 0) {
                break;
            }

            const int lineY = field.bottom() - 3;
            QRect line(field.left() + inset, lineY, loadedWidth, 3);
            if (rtl) {
                line = QRect(field.right() - inset - loadedWidth + 1, lineY, loadedWidth, 3);
            }

            // Whisper fill: barely-there tint over the loaded region,
            // clipped to the pill's inner shape.
            const QRect loadedRegion = rtl
                ? QRect(field.right() - loadedWidth, field.top(), loadedWidth, field.height())
                : QRect(field.left(), field.top(), loadedWidth, field.height());
            QPainterPath pillShape;
            pillShape.addRoundedRect(field.adjusted(2, 2, -2, -3), 13, 13);
            p.save();
            p.setClipPath(pillShape);
            p.fillRect(loadedRegion, QColor(accent.red(), accent.green(), accent.blue(), 16));

            // Glow: the accent bleeding upward off the line.
            QLinearGradient glow(0, lineY - 14, 0, lineY);
            glow.setColorAt(0.0, QColor(accent.red(), accent.green(), accent.blue(), 0));
            glow.setColorAt(1.0, QColor(accent.red(), accent.green(), accent.blue(), 56));
            p.fillRect(QRect(line.left(), lineY - 14, line.width(), 14), glow);
            p.restore();

            // The line itself.
            p.setPen(Qt::NoPen);
            p.setBrush(accent);
            p.drawRoundedRect(line, 1.5, 1.5);

            // The leading tip: brighter segment plus a small bloom,
            // so the motion reads as something arriving.
            const int tipWidth = qMin(24, line.width());
            const QRect tip = rtl
                ? QRect(line.left(), lineY, tipWidth, 3)
                : QRect(line.right() - tipWidth + 1, lineY, tipWidth, 3);
            p.setBrush(accent.lighter(160));
            p.drawRoundedRect(tip, 1.5, 1.5);

            const qreal tipX = rtl ? tip.left() : tip.right();
            QRadialGradient bloom(tipX, lineY + 1.5, 16);
            bloom.setColorAt(0.0, QColor(accent.red(), accent.green(), accent.blue(), 90));
            bloom.setColorAt(1.0, QColor(accent.red(), accent.green(), accent.blue(), 0));
            p.setBrush(bloom);
            p.drawEllipse(QPointF(tipX, lineY + 1.5), 16, 16);
            break;
        }
        default:
            break;
        }
    }
}
