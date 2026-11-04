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
#include "securitysettingsporter.h"

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
 */
class OSZA_EXPORT SettingsDiffPage : public QObject
{
    Q_OBJECT

public:
    // The complete HTML document (translated, with the diff data of
    // the requested preset). Called for every page request, so the
    // diff always reflects the settings at request time. An empty
    // presetId renders the overview; an id that is not one of the
    // built-ins renders the dead end, never an error page.
    static QString buildPage(const QString &presetId = QString());

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
    //                  "quietTools": [display names] } }
    //
    //   { "mode": "unknown", "presetId": <as requested> }
    //
    // Public for the autotests; the page embeds it verbatim.
    static QJsonObject diffData(const QString &presetId = QString());

    // The osza:settings-diff URL for a preset: without a query for
    // the overview, with ?preset=<id> for a baseline's diff. The one
    // place the URL shape exists, so links and menu entries cannot
    // drift apart.
    static QUrl pageUrl(const QString &presetId = QString());

    // The preset a request asks for: the verbatim "preset" query
    // item, trimmed; empty when the request carries none (or asks
    // for an empty one - the same overview).
    static QString presetIdFromUrl(const QUrl &url);

private:
    SettingsDiffPage() = default;

    static QJsonObject previewJson(const SecuritySettingsPorter::Preview &preview,
                                   const QJsonObject &toolsOfDocument);
    static QString i18nJson();
    static QString jsonToScriptLiteral(const QJsonObject &object);
};

#endif // SETTINGSDIFFPAGE_H
