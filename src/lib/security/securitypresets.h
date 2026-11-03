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
#ifndef SECURITYPRESETS_H
#define SECURITYPRESETS_H

#include <QJsonObject>
#include <QList>
#include <QString>

#include "qzcommon.h"

/*
 * Recommended-baseline presets for the bundled security tools.
 *
 * Security tool #11: a hardened setup should not require clicking
 * through seven toggles. This class provides the configurations the
 * project recommends as ready-made documents in the same
 * "osza-security-settings" format SecuritySettingsPorter imports, so
 * a preset is applied through exactly the same validation and the
 * same live manager APIs as an imported file - there is no second
 * code path that could bypass a rule.
 *
 * The built-in presets, from lightest to strictest:
 *
 *  - "essentials"             The four request-path protections on
 *                             (AdBlock, HTTPS-Only mode, tracking-
 *                             parameter stripping, malicious-site
 *                             protection); secure DNS, fingerprint
 *                             randomization and the GPC signal off.
 *                             For networks and sites where the deeper
 *                             tools cause trouble.
 *
 *  - "recommended-baseline"  All seven protections on with the
 *                             project defaults: secure DNS with
 *                             fallback to the system resolver, the
 *                             default blocklist source, no site
 *                             exceptions. The everyday configuration.
 *
 *  - "maximum-protection"    All seven on, and name resolution
 *                             through secure DNS only - no fallback.
 *                             The strictest setting; if a network
 *                             blocks DoH, pages will not load.
 *
 * Deliberate scope decisions:
 *
 *  - Presets replace the full configuration of every tool (that is
 *    their point), so the UI asks for confirmation first. Exception
 *    lists are reset to empty: a baseline starts from the
 *    recommended state, and a site that truly needs an exception is
 *    re-added by the user who knows why.
 *  - Preset documents carry no checksum and no fingerprint seed:
 *    they are built in memory and applied directly, and like every
 *    document the seed - the per-profile secret - never travels.
 *  - The preset content is pinned by the securityPresetsTest
 *    autotest; changing what "recommended" means is a decision, not
 *    an accident, and shows up in the diff of that test.
 */
class OSZA_EXPORT SecurityPresets
{
public:
    struct Preset
    {
        QString id;          // stable identifier, e.g. "recommended-baseline"
        QString name;        // translated, for menus and combo boxes
        QString description; // translated, for tooltips and dialogs
        QJsonObject document; // in the osza-security-settings format
    };

    // The built-in presets, ordered from lightest to strictest.
    static QList<Preset> presets();

    // The preset with the given id, or a Preset with an empty id when
    // the id is not one of the built-ins.
    static Preset presetById(const QString &id);

private:
    SecurityPresets() = default;
};

#endif // SECURITYPRESETS_H
