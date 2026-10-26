/* ============================================================
 * Osza - Qt web browser
 * Copyright (C) 2026 Osza Tools
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
#import <AppKit/AppKit.h>

// Qt 6 no longer exports qt_mac_set_dock_menu(); use the supported NSApp
// API instead. Receives the NSMenu obtained from QMenu::toNSMenu().
void setDockMenuNative(void* menu)
{
    if (menu) {
        [NSApp setDockMenu:(NSMenu*)menu];
    }
}
