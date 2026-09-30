/*
 * Forbidden, required and accepted-risk switches, under each profile.
 */
package com.pingidentity.ps.oidf.platform.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.LocalDate;
import org.junit.jupiter.api.Test;

class ProfileGuardTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 28);
    private static final ProfileGuard PRODUCTION = ProfileGuard.of(DeploymentProfile.PRODUCTION, AcceptedRisks.none());
    private static final ProfileGuard DEVELOPMENT = ProfileGuard.of(DeploymentProfile.DEVELOPMENT, AcceptedRisks.none());

    @Test
    void aForbiddenSwitchIsRefusedOnlyWhenOnInProduction() {
        ProfileGuard.Refusal refusal = PRODUCTION.forbidInProduction("OIDF_FEDERATION_IGNORE_SSL_ERRORS", true, "it trusts any certificate");
        assertEquals("OIDF_FEDERATION_IGNORE_SSL_ERRORS", refusal.setting());
        assertEquals("OIDF_FEDERATION_IGNORE_SSL_ERRORS is forbidden under the production profile: it trusts any certificate."
                + " Turn it off, or set OIDF_DEPLOYMENT_PROFILE=development on a rig", refusal.message());
        assertNull(PRODUCTION.forbidInProduction("OIDF_FEDERATION_IGNORE_SSL_ERRORS", false, "it trusts any certificate"));
        assertNull(DEVELOPMENT.forbidInProduction("OIDF_FEDERATION_IGNORE_SSL_ERRORS", true, "it trusts any certificate"));
    }

    @Test
    void aRequiredSwitchIsRefusedOnlyWhenOffInProduction() {
        ProfileGuard.Refusal refusal = PRODUCTION.requireInProduction("REQUIRE_COMPLIANT_DEVICE", false, "any device would enrol");
        assertEquals("REQUIRE_COMPLIANT_DEVICE is required under the production profile: any device would enrol. Set it, or set"
                + " OIDF_DEPLOYMENT_PROFILE=development on a rig", refusal.message());
        assertEquals("REQUIRE_COMPLIANT_DEVICE", refusal.setting());
        assertNull(PRODUCTION.requireInProduction("REQUIRE_COMPLIANT_DEVICE", true, "any device would enrol"));
        assertNull(DEVELOPMENT.requireInProduction("REQUIRE_COMPLIANT_DEVICE", false, "any device would enrol"));
    }

    @Test
    void aRiskySwitchNeedsItsRiskAcceptedInProduction() {
        String setting = "OIDF_AUTO_REGISTRATION_REQUIRE_PKCE";
        ProfileGuard.Refusal refusal = PRODUCTION.requireRisk(setting, true, AcceptedRisk.PKCE_OFF, "clients may skip PKCE");
        assertEquals(setting + " is on under the production profile and OIDF_ACCEPTED_RISKS does not accept 'pkce-off': clients may"
                + " skip PKCE. Turn it off, or add pkce-off (or pkce-off@YYYY-MM-DD, to make it expire) to OIDF_ACCEPTED_RISKS",
                refusal.message());
        ProfileGuard accepting = ProfileGuard.of(DeploymentProfile.PRODUCTION, AcceptedRisks.parse("pkce-off", TODAY));
        assertNull(accepting.requireRisk(setting, true, AcceptedRisk.PKCE_OFF, "clients may skip PKCE"));
        assertNull(PRODUCTION.requireRisk(setting, false, AcceptedRisk.PKCE_OFF, "clients may skip PKCE"));
        assertNull(DEVELOPMENT.requireRisk(setting, true, AcceptedRisk.PKCE_OFF, "clients may skip PKCE"));
    }

    @Test
    void anExpiredOrOtherRiskDoesNotCountAndADatedRiskAsksForADate() {
        ProfileGuard expired = ProfileGuard.of(DeploymentProfile.PRODUCTION,
                AcceptedRisks.parse("expiry-log-mode@2026-01-01,pkce-off", TODAY));
        ProfileGuard.Refusal refusal = expired.requireRisk("OIDF_REGISTRATION_EXPIRY_ENFORCEMENT", true, AcceptedRisk.EXPIRY_LOG_MODE,
                "expired registrations are served");
        assertEquals("OIDF_REGISTRATION_EXPIRY_ENFORCEMENT is on under the production profile and OIDF_ACCEPTED_RISKS does not accept"
                + " 'expiry-log-mode': expired registrations are served. Turn it off, or add expiry-log-mode@YYYY-MM-DD to"
                + " OIDF_ACCEPTED_RISKS", refusal.message());
        assertEquals("OIDF_ACCEPTED_RISKS accepted 'expiry-log-mode' until 2026-01-01, and that has passed", expired.risks().refusals().get(0));
        assertSame(DeploymentProfile.PRODUCTION, expired.profile());
        assertThrows(NullPointerException.class, () -> PRODUCTION.requireRisk("X", true, null, "r"));
    }

    @Test
    void theProcessGuardIsTheEnvironmentsAndARefusalNeedsBothParts() {
        ProfileGuard current = ProfileGuard.current();
        assertSame(DeploymentProfile.current(), current.profile());
        assertThrows(NullPointerException.class, () -> ProfileGuard.of(null, AcceptedRisks.none()));
        assertThrows(NullPointerException.class, () -> ProfileGuard.of(DeploymentProfile.PRODUCTION, null));
        assertThrows(NullPointerException.class, () -> new ProfileGuard.Refusal(null, "m"));
        assertThrows(NullPointerException.class, () -> new ProfileGuard.Refusal("s", null));
    }
}
