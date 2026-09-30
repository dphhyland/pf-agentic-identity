/*
 * OIDF_ACCEPTED_RISKS: known ids, optional expiry, every other entry refused by name.
 */
package com.pingidentity.ps.oidf.platform.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AcceptedRisksTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 28);

    @Test
    void theRegistryHasStableLowerCaseIdsOnePerRisk() {
        Set<String> ids = new HashSet<>();
        for (AcceptedRisk risk : AcceptedRisk.values()) {
            assertTrue(risk.id().matches("[a-z]+(-[a-z]+)*"), risk.id());
            assertTrue(ids.add(risk.id()), "unique: " + risk.id());
            assertSame(risk, AcceptedRisk.byId(risk.id()));
            assertFalse(risk.description().isBlank(), risk.id());
        }
        // PR-2's eight accepted risks and decision 4's in-memory state when standalone, in this order.
        assertEquals(List.of("no-metadata-policy", "attester-binding-off", "registration-fail-open", "expiry-log-mode",
                "pdp-fail-open", "pkce-off", "resolve-any", "audit-off", "in-memory-state"), List.copyOf(idsInOrder()));
        assertTrue(AcceptedRisk.EXPIRY_LOG_MODE.dated(), "the plan says expiry in log mode is dated");
        assertFalse(AcceptedRisk.PKCE_OFF.dated());
        assertNull(AcceptedRisk.byId("PKCE-OFF"), "ids are exact");
        assertNull(AcceptedRisk.byId("nothing"));
    }

    private static List<String> idsInOrder() {
        return java.util.Arrays.stream(AcceptedRisk.values()).map(AcceptedRisk::id).toList();
    }

    @Test
    void unsetOrBlankAcceptsNothing() {
        for (String value : new String[] {null, "", "  "}) {
            AcceptedRisks risks = AcceptedRisks.parse(value, TODAY);
            assertSame(AcceptedRisks.none(), risks);
            assertEquals(Map.of(), risks.accepted());
            assertEquals(List.of(), risks.refusals());
            assertFalse(risks.accepts(AcceptedRisk.PKCE_OFF));
        }
    }

    @Test
    void idsAloneAndWithAnExpiryAreAcceptedThroughTheirLastDay() {
        AcceptedRisks risks = AcceptedRisks.parse(" pkce-off , expiry-log-mode@2026-09-28,audit-off@2027-01-01 ", TODAY);
        assertEquals(List.of(), risks.refusals());
        assertTrue(risks.accepts(AcceptedRisk.PKCE_OFF));
        assertTrue(risks.accepts(AcceptedRisk.EXPIRY_LOG_MODE), "today is the last day and still holds");
        assertTrue(risks.accepts(AcceptedRisk.AUDIT_OFF));
        assertFalse(risks.accepts(AcceptedRisk.RESOLVE_ANY));
        assertEquals(Optional.empty(), risks.accepted().get(AcceptedRisk.PKCE_OFF));
        assertEquals(Optional.of(LocalDate.of(2026, 9, 28)), risks.accepted().get(AcceptedRisk.EXPIRY_LOG_MODE));
        assertEquals(3, risks.accepted().size());
    }

    @Test
    void anUnknownIdIsRefusedNamingItAndTheKnownIds() {
        AcceptedRisks risks = AcceptedRisks.parse("pkce-off,PKCE-OFF,no-pkce@2027-01-01", TODAY);
        assertTrue(risks.accepts(AcceptedRisk.PKCE_OFF));
        assertEquals(2, risks.refusals().size());
        assertTrue(risks.refusals().get(0).startsWith("OIDF_ACCEPTED_RISKS names 'PKCE-OFF', which is not a risk"), risks.refusals().get(0));
        assertTrue(risks.refusals().get(1).contains("'no-pkce'"), risks.refusals().get(1));
        assertTrue(risks.refusals().get(1).endsWith("the ids are " + AcceptedRisks.ids()), risks.refusals().get(1));
        assertTrue(AcceptedRisks.ids().startsWith("no-metadata-policy, attester-binding-off, "), AcceptedRisks.ids());
    }

    @Test
    void anExpiredAcceptanceIsRefusedNamingItsDate() {
        AcceptedRisks risks = AcceptedRisks.parse("resolve-any@2026-09-27", TODAY);
        assertFalse(risks.accepts(AcceptedRisk.RESOLVE_ANY));
        assertEquals(List.of("OIDF_ACCEPTED_RISKS accepted 'resolve-any' until 2026-09-27, and that has passed"), risks.refusals());
    }

    @Test
    void aDateThatIsNotYyyyMmDdOrDoesNotExistIsRefused() {
        for (String date : new String[] {"2026-9-30", "30-09-2026", "2026-02-30", "2026-13-01", "", "tomorrow", "+2026-09-30",
                "2026-09-30@2026-10-01", "２０２６-09-30"}) {
            AcceptedRisks risks = AcceptedRisks.parse("pkce-off@" + date, TODAY);
            assertFalse(risks.accepts(AcceptedRisk.PKCE_OFF), date);
            assertEquals(List.of("OIDF_ACCEPTED_RISKS entry 'pkce-off@" + date + "' does not end in a date that exists, written YYYY-MM-DD"),
                    risks.refusals(), date);
        }
        assertEquals(LocalDate.of(2028, 2, 29), AcceptedRisks.date("2028-02-29"));
        assertNull(AcceptedRisks.date("2027-02-29"));
    }

    @Test
    void aDatedRiskWithoutAnExpiryIsRefused() {
        AcceptedRisks risks = AcceptedRisks.parse("expiry-log-mode", TODAY);
        assertFalse(risks.accepts(AcceptedRisk.EXPIRY_LOG_MODE));
        assertEquals(List.of("OIDF_ACCEPTED_RISKS accepts 'expiry-log-mode' without an expiry; this risk is accepted only with one,"
                + " as expiry-log-mode@YYYY-MM-DD"), risks.refusals());
    }

    @Test
    void anIdNamedTwiceIsRefusedOnceAndNotAccepted() {
        AcceptedRisks risks = AcceptedRisks.parse("pkce-off@2027-01-01,audit-off,pkce-off,pkce-off@2028-01-01", TODAY);
        assertFalse(risks.accepts(AcceptedRisk.PKCE_OFF), "which expiry was meant is a guess");
        assertTrue(risks.accepts(AcceptedRisk.AUDIT_OFF));
        assertEquals(List.of("OIDF_ACCEPTED_RISKS names 'pkce-off' more than once; name it once"), risks.refusals());
        AcceptedRisks refusedFirst = AcceptedRisks.parse("pkce-off@2020-01-01,pkce-off", TODAY);
        assertFalse(refusedFirst.accepts(AcceptedRisk.PKCE_OFF), "a second entry does not rescue a refused first");
        assertEquals(2, refusedFirst.refusals().size());
    }

    @Test
    void anEmptyEntryIsRefusedAndTheRestStillCount() {
        AcceptedRisks risks = AcceptedRisks.parse("pkce-off,,audit-off,", TODAY);
        assertTrue(risks.accepts(AcceptedRisk.PKCE_OFF));
        assertTrue(risks.accepts(AcceptedRisk.AUDIT_OFF));
        assertEquals(List.of("OIDF_ACCEPTED_RISKS has an empty entry; separate ids with single commas",
                "OIDF_ACCEPTED_RISKS has an empty entry; separate ids with single commas"), risks.refusals());
    }

    @Test
    void theListIsReadFromItsVariableAndTheProcessEnvironment() {
        AcceptedRisks risks = AcceptedRisks.of(Map.of("OIDF_ACCEPTED_RISKS", "audit-off")::get, TODAY);
        assertTrue(risks.accepts(AcceptedRisk.AUDIT_OFF));
        // The build accepts no risks.
        assertEquals(System.getenv(AcceptedRisks.SETTING) == null, AcceptedRisks.current().accepted().isEmpty());
    }
}
