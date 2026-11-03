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
 */
class OSZA_EXPORT SelfTestPage : public QObject
{
    Q_OBJECT

public:
    // The complete HTML document (translated, with the current tool
    // statuses and demo patterns). Called for every page request, so
    // the statuses always reflect the settings at request time.
    static QString buildPage();

    // One JSON object per bundled security tool:
    //   { "id": stable id, "label": translated name,
    //     "on": enabled right now, "detail": translated state text }
    // Public for the autotests.
    static QJsonArray collectToolStatuses();

private:
    SelfTestPage() = default;

    static QJsonObject toolStatus(const QString &id, const QString &label, bool on, const QString &detail);
    static QString statusesJson();
    static QString demoPatternsJson();
    static QString i18nJson();
    static QString jsonToScriptLiteral(const QJsonDocument &document);
};

#endif // SELFTESTPAGE_H
