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
#include <QObject>
#include <QString>
#include <QUrl>

#include "qzcommon.h"

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
 */
class OSZA_EXPORT SelfTestPage : public QObject
{
    Q_OBJECT

public:
    // The complete HTML document (translated, with the current tool
    // statuses, demo patterns, and the section a request asks to
    // focus, if any). Called for every page request, so the
    // statuses always reflect the settings at request time.
    static QString buildPage(const QString &sectionId = QString());

    // One JSON object per bundled security tool:
    //   { "id": stable id, "label": translated name,
    //     "on": enabled right now, "detail": translated state text }
    // Public for the autotests.
    static QJsonArray collectToolStatuses();

    // The address of the page, focused on one section when a
    // non-empty id is given: osza:selftest?section=<id>. The one
    // place the URL shape exists, so the page's own anchors, the
    // scheme handler and any future menu entry cannot drift apart.
    // The ids are the page's section ids ("protections",
    // "fingerprint", "noise", "verify"); which of them exist is
    // the page's own judgment, same as the diff page judges its
    // "tool" item against the porter's key list.
    static QUrl pageUrl(const QString &sectionId = QString());

    // The section a request asks to focus: the verbatim "section"
    // query item, trimmed; empty when the request carries none (or
    // asks for an empty one - the same unfocused page).
    static QString sectionIdFromUrl(const QUrl &url);

private:
    SelfTestPage() = default;

    static QJsonObject toolStatus(const QString &id, const QString &label, bool on, const QString &detail);
    static QString statusesJson();
    static QString demoPatternsJson();
    static QString focusJson(const QString &sectionId);
    static QString i18nJson();
    static QString jsonToScriptLiteral(const QJsonDocument &document);
};

#endif // SELFTESTPAGE_H
