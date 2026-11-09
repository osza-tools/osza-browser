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
#ifndef LOCATIONBAR_H
#define LOCATIONBAR_H

#include "qzcommon.h"
#include "lineedit.h"
#include "searchenginesmanager.h"
#include "loadrequest.h"

class QStringListModel;
class QVariantAnimation;

class BrowserWindow;
class LocationCompleter;
class ClickableLabel;
class TabbedWebView;
class BookmarksIcon;
class SiteIcon;
class GoIcon;
class AutoFillIcon;
class BookmarkItem;
class ZoomLabel;

class OSZA_EXPORT LocationBar : public LineEdit
{
    Q_OBJECT

public:
    explicit LocationBar(QWidget *parent = nullptr);

    struct LoadAction {
        enum Type {
            Invalid = 0,
            Search,
            Bookmark,
            Url
        };
        Type type = Invalid;
        SearchEngine searchEngine;
        BookmarkItem *bookmark = nullptr;
        LoadRequest loadRequest;
    };

    // BrowserWindow can be null!
    BrowserWindow *browserWindow() const;
    void setBrowserWindow(BrowserWindow *window);

    TabbedWebView* webView() const;
    void setWebView(TabbedWebView* view);

    struct SearchEngineSuggestion {
        SearchEngine searchEngine;
        QString searchString;
    };

    static QString convertUrlToText(const QUrl &url);
    static SearchEngine searchEngine();
    static SearchEngineSuggestion suggestSearchEngine(const QString &text);
    static LoadAction loadAction(const QString &text);

public Q_SLOTS:
    void setText(const QString &text);
    void showUrl(const QUrl &url);
    void loadRequest(const LoadRequest &request);

private Q_SLOTS:
    void textEdited(const QString &text);
    void requestLoadUrl();
    void pasteAndGo();

    void updateSiteIcon();
    void updateProtectionsBadge();

    // The blocklist update-in-progress indicator on the site icon:
    // driven by the manager's lifecycle signals (updateStarted,
    // listUpdated, updateFailed) rather than the page, because the
    // refresh is browser-wide activity, not this site's state.
    void updateBlocklistIndicator();
    void updatePlaceHolderText();

    void setPrivacyState(bool state);
    void setGoIconVisible(bool state);

    void showCompletion(const QString &completion, bool completeDomain);
    void showDomainCompletion(const QString &completion);
    void clearCompletion();

    void loadStarted();
    void loadProgress(int progress);
    void loadFinished();
    void hideProgress();

    // The eased load-progress treatment: the engine reports progress
    // in bursts (10, 26, 43, ...), so the bar never jumps - a variant
    // animation glides the displayed value toward each new target
    // (progressGlideAdvanced), dwells at 100 for a moment, then eases
    // its opacity out (progressFadeAdvanced/progressFadeFinished)
    // instead of vanishing.
    void progressGlideAdvanced(const QVariant &value);
    void progressFadeAdvanced(const QVariant &value);
    void progressFadeFinished();

    void loadSettings();

private:
    enum ProgressStyle {
        ProgressFilled,
        ProgressBottom,
        ProgressTop,
        // The showcase treatment: an accent line riding the bottom
        // edge of the pill, with a soft glow above it, a brighter
        // leading tip and a whisper fill over the loaded region -
        // the accent follows the palette's Highlight, so the cyber
        // theme's mint and the private variant's violet arrive with
        // no code of their own.
        ProgressAccentLine
    };

    void contextMenuEvent(QContextMenuEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

    void refreshTextFormat();

    // Retargets the glide animation toward a new engine-reported
    // target, starting from wherever the displayed value stands.
    void retargetProgressGlide(int target);
    // The accent the progress treatment paints with: the custom
    // color when one is set, the palette's Highlight otherwise.
    QColor progressAccentColor() const;

    LocationCompleter* m_completer;
    QStringListModel* m_domainCompleterModel;

    BookmarksIcon* m_bookmarkIcon;
    GoIcon* m_goIcon;
    SiteIcon* m_siteIcon;
    AutoFillIcon* m_autofillIcon;
    ZoomLabel* m_zoomlabel;

    BrowserWindow* m_window;
    TabbedWebView* m_webView;

    bool m_holdingAlt;
    int m_oldTextLength;
    int m_currentTextLength;

    int m_loadProgress;
    bool m_progressVisible;
    ProgressStyle m_progressStyle;
    QColor m_progressColor;
    QTimer *m_progressTimer;

    // The eased treatment's live state. m_displayProgress is the
    // value actually painted (driven only by the glide animation);
    // m_loadProgress above stays the last target the engine named.
    // m_progressOpacity is 1 while loading and eases to 0 once the
    // dwell ends. In-class initializers keep every constructor path
    // (including the LineEdit base) starting from zero.
    int m_displayProgress = 0;
    qreal m_progressOpacity = 1.0;
    QVariantAnimation *m_progressGlide = nullptr;
    QVariantAnimation *m_progressFade = nullptr;
};

#endif // LOCATIONBAR_H
