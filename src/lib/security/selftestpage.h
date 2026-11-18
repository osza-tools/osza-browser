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
#ifndef SELFTESTPAGE_H
#define SELFTESTPAGE_H

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QUrl>

#include "qzcommon.h"

class BrowserWindow;

/*
 * The osza:selftest security self-test page.
 *
 * Assembles the internal page served by the OszaSchemeHandler: the
 * live statuses of the bundled security tools, and the per-site noise
 * patterns of two example hosts computed with the same algorithm as
 * the fingerprint guard (FingerprintManager::siteNoisePattern). The
 * page then measures its own canvas, WebGL, audio and hardware
 * readouts in JavaScript - through the same hooks a fingerprinting
 * site would use - and grades the results.
 *
 * The heavy lifting of the readouts happens in the page script; this
 * class only injects the data the page cannot know (settings and the
 * pattern of other hosts).
 *
 * Each section of the page carries its own deep link
 * (osza:selftest?section=<id>): the section headings' "#" anchors
 * copy that address, and a request asking for one lands focused on
 * its section. The URL shape exists once here, in pageUrl() and
 * sectionIdFromUrl(), the same rule the settings-diff page's deep
 * links follow.
 *
 * The page also answers the per-site question: its "Per-site state"
 * section names, for a host the address asks about, how every
 * protection with a per-site choice treats that host right now -
 * the same lists and strengths the padlock menu's rows read, each
 * row marked protected, relaxed or off. The asked site rides in the
 * "site" query item (osza:selftest?site=example.com), piped through
 * verbatim exactly like the "section" item; what counts as a host,
 * and every judgment about it, is decided in one place,
 * collectSiteStates(). A request that asks for a site lands focused
 * on the per-site section (the page's own composition, in its
 * script - the browser stays a pipe for the item itself), and a
 * request that also names a section of its own keeps that focus
 * with the per-site answer still rendered.
 *
 * The section is one click away from the surfaces where the
 * per-site question arises: openSiteState() is the one landing
 * every per-site deep link rides - the padlock menu's link for
 * the site it answers for, the threat interstitial's link for the
 * host it stopped - the same rule SettingsDiffPage::openToolDiff()
 * keeps for the per-tool deep links.
 */
class OSZA_EXPORT SelfTestPage : public QObject
{
    Q_OBJECT

public:
    // The complete HTML document (translated, with the current tool
    // statuses, demo patterns, the per-site answer of the asked site
    // when the request carries one, and the section a request asks
    // to focus, if any). Called for every page request, so the
    // statuses always reflect the settings at request time.
    static QString buildPage(const QString &sectionId = QString(), const QString &site = QString());

    // One JSON object per bundled security tool:
    //   { "id": stable id, "label": translated name,
    //     "on": enabled right now, "detail": translated state text }
    // Public for the autotests.
    static QJsonArray collectToolStatuses();

    // The per-site half of the page: how every protection with a
    // per-site choice treats the site the string asks about, judged
    // through the same managers the padlock menu's rows read. The
    // answer is one object:
    //   { "asked": the trimmed string verbatim,
    //     "host": the host the judgments ran against ("" when the
    //             string did not name one),
    //     "judgeable": whether a host was named,
    //     "rows": one row per protection, in the padlock menu's row
    //             order - { "id", "label", "state" ("on" = the
    //             protection applies to this site, "relaxed" = this
    //             site holds an exception, "off" = the tool itself
    //             is off), "detail" } - with the referrer row
    //             absent on engines too old to run the guard, the
    //             same capability case its padlock row follows.
    // Public for the autotests.
    static QJsonObject collectSiteStates(const QString &site);

    // The address of the page, focused on one section when a
    // non-empty id is given: osza:selftest?section=<id>. The one
    // place the URL shape exists, so the page's own anchors, the
    // scheme handler and any future menu entry cannot drift apart.
    // The ids are the page's section ids ("protections", "site",
    // "fingerprint", "noise", "verify"); which of them exist is
    // the page's own judgment, same as the diff page judges its
    // "tool" item against the porter's key list.
    static QUrl pageUrl(const QString &sectionId = QString(), const QString &site = QString());

    // The section a request asks to focus: the verbatim "section"
    // query item, trimmed; empty when the request carries none (or
    // asks for an empty one - the same unfocused page).
    static QString sectionIdFromUrl(const QUrl &url);

    // The site a request asks about: the verbatim "site" query item,
    // trimmed; empty when the request carries none. Whether the
    // string names a host the page can judge is collectSiteStates'
    // own decision, never the URL's - the same pipe rule the
    // section item follows.
    static QString siteFromUrl(const QUrl &url);

    // A per-site deep link's landing: the self-test page opened on
    // the asked site's answer, in a new selected tab - the one
    // place the padlock menu's link and the threat interstitial's
    // link land, built on the same pageUrl() the page's own ask
    // form composes, so every surface that asks the per-site
    // question can never land in different places. The site string
    // is piped through verbatim (trimmed only); whether it names a
    // host the page can judge stays the page's own answer. An
    // empty ask opens the plain page - the same honest answer the
    // ask form's empty input gets - never an error page. A null
    // window is a no-op, exactly like the diff page's shortcut.
    static void openSiteState(BrowserWindow *window, const QString &site);

private:
    SelfTestPage() = default;

    static QJsonObject toolStatus(const QString &id, const QString &label, bool on, const QString &detail);
    static QJsonObject siteState(const QString &id, const QString &label, const QString &state, const QString &detail);
    static QString normalizeSiteHost(const QString &site);
    static QString statusesJson();
    static QString siteJson(const QString &site);
    static QString demoPatternsJson();
    static QString focusJson(const QString &sectionId);
    static QString i18nJson();
    static QString jsonToScriptLiteral(const QJsonDocument &document);
};

#endif // SELFTESTPAGE_H
