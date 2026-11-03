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
#include "autotests.h"
#include "threatblockonlinetest.h"
#include "mainapplication.h"
#include "networkmanager.h"
#include "threatblockmanager.h"

#include <QSignalSpy>
#include <QtTest/QtTest>

void ThreatBlockOnlineTest::downloadDefaultSourceTest()
{
    auto *manager = mApp->networkManager()->threatBlockManager();
    QVERIFY(manager);

    // Start from the documented default source.
    manager->loadSettings();

    const QString source = manager->sourceUrl();
    QVERIFY(source.startsWith(QSL("https://")));

    QSignalSpy updatedSpy(manager, &ThreatBlockManager::listUpdated);
    QSignalSpy failedSpy(manager, &ThreatBlockManager::updateFailed);

    manager->updateNow();

    if (!updatedSpy.wait(60000)) {
        // Give the failure signal a moment to arrive for a useful message.
        QTest::qWait(1000);
        if (failedSpy.count() > 0) {
            QFAIL(qPrintable(QSL("Blocklist download failed: %1").arg(failedSpy.at(0).at(0).toString())));
        }
        QFAIL("Blocklist download did not finish within 60 seconds");
    }

    const int count = updatedSpy.at(0).at(0).toInt();

    // A real curated list is large; a handful of entries means the
    // source stopped being a host list.
    QVERIFY2(count > 10000, qPrintable(QSL("Suspiciously small blocklist: %1 entries from %2").arg(count).arg(source)));

    QVERIFY(manager->isListLoaded());
    QVERIFY(manager->lastUpdate().isValid());
    QCOMPARE(manager->hostCount(), count);
}

OSZATEST_MAIN(ThreatBlockOnlineTest)
