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
#ifndef OSZAICONS_H
#define OSZAICONS_H

#include <QString>

namespace OszaIcons
{
    // Makes the bundled Osza icon theme the active theme on every
    // platform - see ICONS.md for the full rationale.
    //
    // Both a light and a dark variant are bundled as resources
    // (":/icons/osza" and ":/icons/osza-dark"); the variant that
    // matches the current palette (or the user's color-scheme
    // preference) is selected. The icon theme that was active
    // before the call is kept as a fallback so names Osza does not
    // ship (for example MIME types) still resolve from the system.
    //
    // The selection happens once at startup; changing the palette
    // or the color-scheme preference takes effect after a restart,
    // exactly like the chrome themes.
    void activateTheme();
}

#endif // OSZAICONS_H
