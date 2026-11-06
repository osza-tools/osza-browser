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
#ifndef SECURITYTOOLSTEST_H
#define SECURITYTOOLSTEST_H

#include <QObject>

class SecurityToolsTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void securityManagerCountersTest();
    void securityManagerPersistenceTest();
    void relaxedProtectionsQueryTest();
    void httpsOnlyExclusionTest();
    void httpsOnlyHostMatchingTest();
    void dnsOverHttpsConfigurationTest();
    void dnsOverHttpsProvidersTest();
    void securityDashboardWidgetTest();
    void securityDashboardToolDiffLinksTest();
    void padlockMenuToolDiffLinksTest();
    void locationBarProtectionsBadgeTest();

    void threatBlockListParsingTest();
    void threatBlockHostMatchingTest();
    void threatBlockSessionAllowTest();
    void threatBlockPageUrlTest();
    void threatBlockInterstitialTest();
    void threatBlockManagerStateTest();
    void threatBlockIntegrationTest();

    void fingerprintScriptSourceTest();
    void fingerprintExclusionTest();
    void fingerprintExceptionsDialogTest();
    void fingerprintScriptLifecycleTest();
    void fingerprintIntegrationTest();

    void gpcScriptSourceTest();
    void gpcExclusionTest();
    void gpcExceptionsDialogTest();
    void gpcScriptLifecycleTest();
    void gpcDomSignalIntegrationTest();
    void gpcHeaderIntegrationTest();

    void selfTestNoisePatternTest();
    void selfTestNoiseEquivalenceTest();
    void selfTestPageBuildTest();
    void selfTestSectionUrlTest();
    void selfTestPageIntegrationTest();

    void settingsPorterDocumentTest();
    void settingsPorterRoundTripTest();
    void settingsPorterValidationTest();
    void settingsPorterChecksumTest();
    void settingsPorterPreviewTest();
    void settingsPorterPresetExportTest();
    void securityImportPreviewDialogTest();
    void securityPresetsTest();
    void settingsDiffPageBuildTest();
    void settingsDiffPageIntegrationTest();
};

#endif // SECURITYTOOLSTEST_H
