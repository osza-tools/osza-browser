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
* but WITHOUT ANY WARRANTY; without even implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#ifndef THREATBLOCKONLINETEST_H
#define THREATBLOCKONLINETEST_H

#include <QObject>

/*
 * Network test for the malicious-site protection blocklist download.
 *
 * The default source of the threat blocklist is a moving target: the
 * previously used URLhaus feed was retired with a "410 Gone" and the
 * download only failed at runtime. This test fetches the configured
 * source for real and asserts that it still delivers a usable list,
 * so a dead default source fails loudly here instead of silently for
 * every user.
 */
class ThreatBlockOnlineTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void downloadDefaultSourceTest();
};

#endif // THREATBLOCKONLINETEST_H
