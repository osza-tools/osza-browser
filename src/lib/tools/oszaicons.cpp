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
#include "oszaicons.h"
#include "qzcommon.h"
#include "settings.h"

#include <QApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QPalette>
#include <QSettings>
#include <QStyleHints>
#include <QtGuiVersion>

namespace {

bool paletteIsDark()
{
#if QTGUI_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    const auto scheme = QGuiApplication::styleHints()->colorScheme();
    if (scheme == Qt::ColorScheme::Dark) {
        return true;
    }
    if (scheme == Qt::ColorScheme::Light) {
        return false;
    }
#endif
    // Unknown: derive it from the window color the chrome will use
    return QApplication::palette().color(QPalette::Window).lightness() < 128;
}

bool userPrefersDark()
{
    // Settings may not exist yet if this is called before
    // Settings::createSettings() (eg. very early during startup) -
    // fall back to palette detection instead of crashing.
    const QSettings *settings = Settings::globalSettings();
    if (!settings) {
        return paletteIsDark();
    }

    switch (settings->value(QSL("Web-Browser-Settings/prefferColorScheme"),
                            Qz::ColorScheme_Auto).toInt()) {
    case Qz::ColorScheme_Dark:
        return true;
    case Qz::ColorScheme_Light:
        return false;
    default:
        return paletteIsDark();
    }
}

} // namespace

void OszaIcons::activateTheme()
{
    const QString systemTheme = QIcon::themeName();

    QIcon::setThemeName(userPrefersDark() ? QSL("osza-dark") : QSL("osza"));

    // The system theme stays reachable for the few names Osza does
    // not ship (MIME types and friends)
    if (!systemTheme.isEmpty() && systemTheme != QIcon::themeName()) {
        QIcon::setFallbackThemeName(systemTheme);
    }
}
