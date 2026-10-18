/* ============================================================
* Veex - Qt web browser
* Copyright (C) 2014-2018 David Rosca <nowrep@gmail.com>
* Copyright (C) 2020-2025 Juraj Oravec <jurajoravec@mailo.com>
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
#include "qzcommon.h"
#include "../config.h"

namespace Qz
{
const int sessionVersion = 0x0004;

VEEX_EXPORT const char *APPNAME = "Veex";
VEEX_EXPORT const char *VERSION = VEEX_VERSION;
VEEX_EXPORT const char *AUTHOR = "Juraj Oravec";
VEEX_EXPORT const char *COPYRIGHT = "2020-2025";
VEEX_EXPORT const char *WWWADDRESS = "https://github.com/veex-tools/veex-browser";
VEEX_EXPORT const char *BUGSADDRESS = "https://github.com/veex-tools/veex-browser/issues";
VEEX_EXPORT const char *WIKIADDRESS = "https://github.com/veex-tools/veex-browser/wiki";

const QList<AuthorInfo> AUTHORS = {
    {QSL("Juraj Oravec"), QSL("jurajoravec@mailo.com"), 2020, 2025},
    {QSL("David Rosca"), QSL("nowrep@gmail.com"), 2010, 2019},
};

}
