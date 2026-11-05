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
#include "settingsdiffpage.h"
#include "qztools.h"
#include "securitypresets.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QUrlQuery>

namespace {

// The tools a settings document can configure - the count the page
// quotes ("configures 7 of the 7 security tools"). Kept beside its
// only consumer; the porter's buildPlans() is the authority for the
// sections themselves.
const int kTotalTools = 7;

// "secureDns: a secure mode needs at least one server" becomes
// "Secure DNS (DNS-over-HTTPS): a secure mode needs at least one
// server" - the same mapping the import preview dialog applies, so
// the page and the dialog speak the same names for the same skip.
QString displaySkipEntry(const QString &entry)
{
    const int separator = entry.indexOf(QSL(": "));

    if (separator < 0) {
        return entry;
    }

    return QSL("%1: %2").arg(SecuritySettingsPorter::toolDisplayName(entry.left(separator)),
                             entry.mid(separator + 2));
}

} // namespace

QString SettingsDiffPage::buildPage(const QString &presetId, const QString &toolId)
{
    // The translated template is built once; the diff data is
    // substituted on every request, so the page always describes the
    // settings at request time (the same split as the self-test
    // page).
    static QString sPage;

    if (sPage.isEmpty()) {
        sPage.append(QzTools::readAllFileContents(QSL(":html/settingsdiff.html")));

        sPage.replace(QLatin1String("%TITLE%"), tr("Security settings diff"));
        sPage.replace(QLatin1String("%SUBTITLE%"), tr("What a recommended baseline would change in this profile, tool by tool - computed live, exactly like the import preview."));
        sPage.replace(QLatin1String("%JAVASCRIPT-DISABLED%"), tr("The settings diff requires enabled JavaScript."));

        sPage.replace(QLatin1String("%OVERVIEW-HEADING%"), tr("Recommended baselines"));
        sPage.replace(QLatin1String("%OVERVIEW-INTRO%"), tr("Pick a baseline to see what it would change here right now. Nothing is applied by this page."));

        sPage.replace(QLatin1String("%CHANGES-HEADING%"), tr("Changes"));
        sPage.replace(QLatin1String("%DETAIL-HEADING%"), tr("Details"));
        sPage.replace(QLatin1String("%COLUMN-CURRENT%"), tr("Now"));
        sPage.replace(QLatin1String("%COLUMN-AFTER%"), tr("With the baseline"));

        sPage.replace(QLatin1String("%RELOAD-LABEL%"), tr("Reload"));
        sPage.replace(QLatin1String("%ALL-BASELINES-LABEL%"), tr("All baselines"));
        sPage.replace(QLatin1String("%FOOTER-NOTE%"), tr("Computed on this machine, from the live configuration. Applying a baseline is a separate, confirmed step: the security dashboard's \"Import / Export\" menu or Preferences > Privacy > Security tools."));

        sPage.replace(QLatin1String("%I18N-JSON%"), i18nJson());
        sPage = QzTools::applyDirectionToPage(sPage);
    }

    QString page = sPage;
    page.replace(QLatin1String("%DATA-JSON%"), jsonToScriptLiteral(diffData(presetId, toolId)));
    return page;
}

QJsonObject SettingsDiffPage::diffData(const QString &presetId, const QString &toolId)
{
    QJsonObject data;

    const QString trimmed = presetId.trimmed();

    // The overview: one card per built-in baseline, each with the
    // number of settings it would change here right now - the same
    // preview the diff page below renders, reduced to its size.
    if (trimmed.isEmpty()) {
        QJsonArray presets;

        for (const SecurityPresets::Preset &preset : SecurityPresets::presets()) {
            const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(preset.document);

            QJsonObject entry;
            entry.insert(QSL("id"), preset.id);
            entry.insert(QSL("name"), preset.name);
            entry.insert(QSL("description"), preset.description);
            // -1, not a guess: only the preview can say, and it says
            // so per preset (a build without secure-DNS support skips
            // that section, which is a different statement than "it
            // changes nothing").
            entry.insert(QSL("changes"), preview.ok ? preview.changes.size() : -1);
            presets.append(entry);
        }

        data.insert(QSL("mode"), QSL("overview"));
        data.insert(QSL("presets"), presets);
        return data;
    }

    const SecurityPresets::Preset preset = SecurityPresets::presetById(trimmed);

    // The page is served for whatever query it is asked for; an id
    // that is not one of the built-ins gets a dead end with a way
    // back - the baselines themselves, linked - never an error page.
    if (preset.id.isEmpty()) {
        QJsonArray presets;
        for (const SecurityPresets::Preset &builtIn : SecurityPresets::presets()) {
            QJsonObject entry;
            entry.insert(QSL("id"), builtIn.id);
            entry.insert(QSL("name"), builtIn.name);
            entry.insert(QSL("description"), builtIn.description);
            presets.append(entry);
        }

        data.insert(QSL("mode"), QSL("unknown"));
        data.insert(QSL("presetId"), trimmed);
        data.insert(QSL("presets"), presets);
        return data;
    }

    data.insert(QSL("mode"), QSL("diff"));

    QJsonObject presetObject;
    presetObject.insert(QSL("id"), preset.id);
    presetObject.insert(QSL("name"), preset.name);
    presetObject.insert(QSL("description"), preset.description);
    data.insert(QSL("preset"), presetObject);

    // A built-in preset's document is fixed and valid, so the
    // preview always succeeds; the not-ok shape exists anyway
    // because the page must render every answer the porter gives.
    const SecuritySettingsPorter::Preview preview = SecuritySettingsPorter::previewDocument(preset.document);
    data.insert(QSL("preview"), previewJson(preview, preset.document.value(QSL("tools")).toObject()));

    // The tool the request asks to focus, answered only after the
    // preview exists: whether there is a section to focus is
    // something the preview alone can say. A "tool" item naming no
    // security tool is answered beside the full diff, not with one.
    const QJsonObject focusTool = focusToolJson(preview, preset.document.value(QSL("tools")).toObject(), toolId);
    if (!focusTool.isEmpty()) {
        data.insert(QSL("focusTool"), focusTool);
    } else if (!toolId.trimmed().isEmpty()) {
        data.insert(QSL("unknownTool"), toolId.trimmed());
    }

    return data;
}

QJsonObject SettingsDiffPage::previewJson(const SecuritySettingsPorter::Preview &preview,
                                          const QJsonObject &toolsOfDocument)
{
    QJsonObject object;

    if (!preview.ok) {
        object.insert(QSL("ok"), false);
        object.insert(QSL("error"), preview.error);
        return object;
    }

    object.insert(QSL("ok"), true);
    object.insert(QSL("configuredTools"), preview.configuredTools);
    object.insert(QSL("totalTools"), kTotalTools);

    QJsonArray changes;
    for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
        QJsonObject changeObject;
        changeObject.insert(QSL("tool"), change.tool);
        changeObject.insert(QSL("toolName"), SecuritySettingsPorter::toolDisplayName(change.tool));
        changeObject.insert(QSL("field"), change.field);
        changeObject.insert(QSL("fieldName"), SecuritySettingsPorter::fieldDisplayName(change.tool, change.field));
        changeObject.insert(QSL("current"), change.currentValue);
        changeObject.insert(QSL("next"), change.nextValue);

        // The site-exception summaries exactly as the porter words
        // them - the lines the import preview dialog shows under the
        // same field, reused here unchanged.
        changeObject.insert(QSL("summary"),
                            QJsonArray::fromStringList(SecuritySettingsPorter::exceptionSummaryLines(change)));

        changes.append(changeObject);
    }
    object.insert(QSL("changes"), changes);

    QJsonArray skipped;
    for (const QString &entry : preview.skippedTools) {
        skipped.append(displaySkipEntry(entry));
    }
    object.insert(QSL("skippedTools"), skipped);

    QJsonArray unchanged;
    for (const QString &tool : preview.unchangedTools) {
        unchanged.append(SecuritySettingsPorter::toolDisplayName(tool));
    }
    object.insert(QSL("unchangedTools"), unchanged);

    // The sections the document carries that would change nothing
    // here: this profile already runs those tools exactly as the
    // baseline wants. The complement of the changed and skipped
    // tools among the configured ones - honest silence, named
    // instead of left as an absence.
    QJsonArray quietTools;
    const QStringList keys = toolsOfDocument.keys();
    for (const QString &key : keys) {
        bool touched = false;

        for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
            if (change.tool == key) {
                touched = true;
                break;
            }
        }

        if (!touched) {
            for (const QString &entry : preview.skippedTools) {
                if (entry.startsWith(QSL("%1: ").arg(key))) {
                    touched = true;
                    break;
                }
            }
        }

        if (!touched) {
            quietTools.append(SecuritySettingsPorter::toolDisplayName(key));
        }
    }
    object.insert(QSL("quietTools"), quietTools);

    return object;
}

QJsonObject SettingsDiffPage::focusToolJson(const SecuritySettingsPorter::Preview &preview,
                                           const QJsonObject &toolsOfDocument,
                                           const QString &toolId)
{
    // Nothing asked, nothing focused: the plain diff.
    const QString trimmed = toolId.trimmed();

    if (trimmed.isEmpty()) {
        return {};
    }

    // The judgment is the porter's, not a second list here: the keys
    // buildPlans() knows are the keys a "tool" query item can mean.
    if (!SecuritySettingsPorter::toolKeys().contains(trimmed)) {
        return {};
    }

    QJsonObject focus;
    focus.insert(QSL("key"), trimmed);
    focus.insert(QSL("name"), SecuritySettingsPorter::toolDisplayName(trimmed));

    // A tool the baseline would change has a section to focus; the
    // note then says what the reader is looking at. The changes come
    // grouped per tool in the preview's fixed order, so the first
    // match settles it.
    for (const SecuritySettingsPorter::PreviewChange &change : preview.changes) {
        if (change.tool == trimmed) {
            focus.insert(QSL("note"), tr("Showing the changes for %1.").arg(SecuritySettingsPorter::toolDisplayName(trimmed)));
            return focus;
        }
    }

    // The remaining answers all say why there is no section: the
    // skip reasons come from the porter, translated, joined with the
    // tool's display name the same way the skip list phrases them.
    for (const QString &entry : preview.skippedTools) {
        if (entry.startsWith(QSL("%1: ").arg(trimmed))) {
            const QString reason = entry.mid(trimmed.length() + 2);
            focus.insert(QSL("note"), tr("The baseline carries a %1 section that would be skipped: %2.")
                                 .arg(SecuritySettingsPorter::toolDisplayName(trimmed), reason));
            return focus;
        }
    }

    // A section that changes nothing here: this profile already runs
    // the tool exactly as the baseline wants.
    if (toolsOfDocument.contains(trimmed)) {
        focus.insert(QSL("note"), tr("%1 is already at the baseline's settings.").arg(SecuritySettingsPorter::toolDisplayName(trimmed)));
        return focus;
    }

    // No section at all: the baseline does not configure the tool.
    focus.insert(QSL("note"), tr("The baseline does not configure %1; it stays as it is.").arg(SecuritySettingsPorter::toolDisplayName(trimmed)));
    return focus;
}

QUrl SettingsDiffPage::pageUrl(const QString &presetId, const QString &toolId)
{
    QUrl url;
    url.setScheme(QSL("osza"));
    url.setPath(QSL("settings-diff"));

    QUrlQuery query;

    const QString trimmedPreset = presetId.trimmed();
    if (!trimmedPreset.isEmpty()) {
        query.addQueryItem(QSL("preset"), trimmedPreset);
    }

    const QString trimmedTool = toolId.trimmed();
    if (!trimmedTool.isEmpty()) {
        query.addQueryItem(QSL("tool"), trimmedTool);
    }

    if (!query.isEmpty()) {
        url.setQuery(query);
    }

    return url;
}

QString SettingsDiffPage::presetIdFromUrl(const QUrl &url)
{
    // The verbatim "preset" item, trimmed: the overview for no item
    // or an empty one, the dead end for anything the preset catalog
    // does not know.
    return QUrlQuery(url).queryItemValue(QSL("preset")).trimmed();
}

QString SettingsDiffPage::toolIdFromUrl(const QUrl &url)
{
    // The verbatim "tool" item, trimmed: no item means the plain
    // diff; whether an item names one of the tools is answered by
    // diffData(), which has something to say either way.
    return QUrlQuery(url).queryItemValue(QSL("tool")).trimmed();
}

QString SettingsDiffPage::i18nJson()
{
    QJsonObject strings;

    // Overview cards
    strings.insert(QSL("pill_changes_none"), tr("changes nothing here"));
    strings.insert(QSL("pill_changes_one"), tr("would change 1 setting"));
    strings.insert(QSL("pill_changes_many"), tr("would change %1 settings"));
    strings.insert(QSL("preset_open"), tr("Preview the diff"));

    // Diff banner
    strings.insert(QSL("banner_changes"), tr("The baseline \"%1\" would change %2 settings across %3 of the 7 security tools."));
    strings.insert(QSL("banner_changes_single"), tr("The baseline \"%1\" would change 1 setting in %2 of the 7 security tools."));
    strings.insert(QSL("banner_none"), tr("The baseline \"%1\" changes nothing that is set right now - this profile already matches it."));
    strings.insert(QSL("banner_skipped_one"), tr("1 section would be skipped, listed below with the reason."));
    strings.insert(QSL("banner_skipped_many"), tr("%1 sections would be skipped, listed below with the reasons."));
    strings.insert(QSL("banner_preset_source"), tr("A ready-made configuration of the Osza project; applying it replaces the configuration of every security tool."));

    // Sections
    strings.insert(QSL("heading_skipped"), tr("Would be skipped, the rest still applies"));
    strings.insert(QSL("heading_unchanged"), tr("Not in the baseline, left unchanged"));
    strings.insert(QSL("heading_quiet"), tr("Already at the baseline's settings"));

    // Unknown preset
    strings.insert(QSL("unknown_title"), tr("Unknown baseline"));
    strings.insert(QSL("unknown_text"), tr("\"%1\" is not one of the built-in presets. The baselines this Osza knows are linked below."));

    // Unknown tool of a known baseline
    strings.insert(QSL("unknown_tool_text"), tr("\"%1\" is not one of the security tools - the whole diff follows."));

    // Per-tool deep links
    strings.insert(QSL("tool_link_title"), tr("Link to this tool's part of the diff"));

    // Not-importable preview (the defensive shape)
    strings.insert(QSL("broken_text"), tr("The baseline's document did not pass validation: %1"));

    return jsonToScriptLiteral(strings);
}

QString SettingsDiffPage::jsonToScriptLiteral(const QJsonObject &object)
{
    // Compact JSON, embedded as a JavaScript literal. "<" is escaped
    // so no translated string can ever close the <script> element
    // (the same rule as the self-test page).
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact))
        .replace(QChar::fromLatin1('<'), QSL("\\u003c"));
}
