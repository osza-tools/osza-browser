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
#ifndef SETTINGSDIFFPAGE_H
#define SETTINGSDIFFPAGE_H

#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QUrl>

#include "qzcommon.h"
#include "securitypresets.h"
#include "securitysettingsporter.h"

class BrowserWindow;

/*
 * The osza:settings-diff security settings diff page.
 *
 * Assembles the internal page served by the OszaSchemeHandler: what
 * one of the built-in recommended baselines would change in this
 * profile, per tool and per field, as the in-browser counterpart of
 * the import preview dialog. The data is exactly the porter's
 * preview - previewDocument(), the same validation an import and a
 * preset apply run - shaped for the page; the one-line summaries of
 * a site-exception change come from exceptionSummaryLines() as they
 * are, so every preview UI says the same thing about the same file.
 *
 * The page is a preview, deliberately nothing more: it renders what
 * a baseline would do, and applying stays a confirmed step in the Qt
 * UI (the security dashboard's "Import / Export" menu or Preferences
 * > Privacy > Security tools), where the confirmation dialog lives.
 * No setting is read past the snapshot the preview takes, and none
 * is written at all.
 *
 * Three shapes, one page, chosen by the URL's "preset" query item
 * (presetIdFromUrl):
 *
 *  - no id    the overview: one card per built-in baseline with the
 *             number of settings it would change here right now,
 *             linking to its diff
 *  - known id the diff for that baseline: a summary banner, the
 *             per-tool field changes (current value against the
 *             value after applying), the sites whose exception is
 *             cleared or added, the sections that would be skipped
 *             with the reason, and the tools already at the
 *             baseline's settings
 *  - other    a dead end that says so and links back - the page is
 *             served for arbitrary queries, so it must answer one
 *
 * A diff can additionally be asked for one tool in particular: the
 * "tool" query item (toolIdFromUrl) carries a stable tool key like
 * "secureDns", and the page opens focused on that tool's section -
 * scrolled to, highlighted, and introduced by a note - or, when the
 * baseline has nothing to say about that tool right now, the note
 * says that instead (skipped, already at the baseline's settings,
 * or not in the baseline at all). A "tool" item that does not name
 * one of the security tools is answered with a warning line and
 * the full diff, never an error page. The item only means something
 * together with a known preset; on the overview and on the unknown
 * preset dead end it is ignored.
 */
class OSZA_EXPORT SettingsDiffPage : public QObject
{
    Q_OBJECT

public:
    // The complete HTML document (translated, with the diff data of
    // the requested preset, focused on the requested tool when one
    // is given). Called for every page request, so the diff always
    // reflects the settings at request time. An empty presetId
    // renders the overview; an id that is not one of the built-ins
    // renders the dead end, never an error page. An empty toolId
    // renders the plain diff; a toolId that names one of the tools
    // focuses the page on it, and anything else is answered with a
    // warning line over the full diff.
    static QString buildPage(const QString &presetId = QString(), const QString &toolId = QString());

    // The data the page renders, shaped for its script:
    //
    //   { "mode": "overview",
    //     "presets": [ { "id", "name", "description",
    //                    "changes": <count, -1 when not computable> } ] }
    //
    //   { "mode": "diff", "preset": { "id", "name", "description" },
    //     "preview": { "ok", "configuredTools", "totalTools",
    //                  "changes": [ { "tool", "toolName", "field",
    //                                 "fieldName", "current", "next",
    //                                 "summary": [lines] } ],
    //                  "skippedTools": [display entries],
    //                  "unchangedTools": [display names],
    //                  "quietTools": [display names] },
    //     "focusTool": { "key", "name", "note" },   // with a "tool" item
    //     "unknownTool": <as requested> }              // naming no tool
    //
    //   { "mode": "unknown", "presetId": <as requested> }
    //
    // focusTool.note is translated here, complete, exactly like the
    // porter's exception summaries: one sentence saying why the
    // reader landed mid-page (a section is focused) or why there is
    // no section to focus (skipped, already matching, or not in the
    // baseline). Public for the autotests; the page embeds it
    // verbatim.
    static QJsonObject diffData(const QString &presetId = QString(), const QString &toolId = QString());

    // The osza:settings-diff URL for a preset: without a query for
    // the overview, with ?preset=<id> for a baseline's diff, and
    // with &tool=<key> to focus that tool's section of it. The one
    // place the URL shape exists, so links and menu entries cannot
    // drift apart.
    static QUrl pageUrl(const QString &presetId = QString(), const QString &toolId = QString());

    // The preset a request asks for: the verbatim "preset" query
    // item, trimmed; empty when the request carries none (or asks
    // for an empty one - the same overview).
    static QString presetIdFromUrl(const QUrl &url);

    // The tool a request asks to focus: the verbatim "tool" query
    // item, trimmed; empty when the request carries none. Whether
    // the string names one of the security tools is decided against
    // SecuritySettingsPorter::toolKeys() by diffData(), which knows
    // what to answer either way.
    static QString toolIdFromUrl(const QUrl &url);

    // The recommended baseline, resolved through the preset catalog:
    // the referent of every "what would the recommended setting
    // for this tool be?" affordance - the security dashboard's tool
    // rows, the padlock menu's per-site entries. A Preset with an
    // empty id when the catalog does not carry it.
    static SecurityPresets::Preset recommendedBaseline();

    // Open the recommended baseline's diff focused on the given
    // tool's section, in a new tab of the window. The one place
    // every such deep link lands: the tool's stable key is judged
    // by the porter's own list (the same judgment the page applies
    // to a "tool" query item) and the baseline by the catalog, and
    // a key that names no tool, or none at all, opens the baselines
    // overview - where every baseline this Osza knows is listed -
    // never an error page. Without a window it is a no-op.
    static void openToolDiff(BrowserWindow *window, const QString &toolKey);

private:
    SettingsDiffPage() = default;

    static QJsonObject previewJson(const SecuritySettingsPorter::Preview &preview,
                                   const QJsonObject &toolsOfDocument);
    static QJsonObject focusToolJson(const SecuritySettingsPorter::Preview &preview,
                                     const QJsonObject &toolsOfDocument,
                                     const QString &toolId);
    static QString i18nJson();
    static QString jsonToScriptLiteral(const QJsonObject &object);
};

#endif // SETTINGSDIFFPAGE_H
