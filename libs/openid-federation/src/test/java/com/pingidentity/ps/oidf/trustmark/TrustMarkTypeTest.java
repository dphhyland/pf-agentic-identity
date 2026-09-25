package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The Trust Mark types an operator configures this entity to issue. */
class TrustMarkTypeTest {
    private static final String CERTIFIED = "https://pf.example.com/marks/certified";

    private static String delegation(String typ, String type) {
        return Statements.spec(typ).claim("iss", "https://owner.example.com").claim("sub", "https://pf.example.com")
                .claim("trust_mark_type", type).sign(Keys.ec("owner-1"), Clock.systemUTC());
    }

    @Test
    void aTypeNeedsOnlyItsIdentifier() {
        TrustMarkType type = TrustMarkType.parseAll("{\"" + CERTIFIED + "\": {}}").get(CERTIFIED);

        assertEquals(CERTIFIED, type.id());
        assertEquals(TrustMarkType.DEFAULT_LIFETIME_SECONDS, type.lifetimeSeconds());
        assertEquals(TrustMarkType.Subjects.HOSTED, type.subjects(), "hosted entities only unless the operator says otherwise");
        assertNull(type.delegation());
        assertNull(type.ref());
        assertNull(type.logoUri());
    }

    @Test
    void everySettingIsRead() {
        String delegation = delegation(TrustMarkValidator.DELEGATION_TYP, CERTIFIED);
        TrustMarkType type = TrustMarkType.parseAll("{\"" + CERTIFIED + "\": {\"lifetime_seconds\": 600, \"subjects\": \"ANY\", \"delegation\": \""
                + delegation + "\", \"ref\": \"https://pf.example.com/about\", \"logo_uri\": \"https://pf.example.com/logo.svg\"}}").get(CERTIFIED);

        assertEquals(600L, type.lifetimeSeconds());
        assertEquals(4_000_000_000L, TrustMarkType.parseAll("{\"" + CERTIFIED + "\": {\"lifetime_seconds\": 4000000000}}").get(CERTIFIED)
                .lifetimeSeconds(), "past what an int holds");
        assertEquals(TrustMarkType.Subjects.ANY, type.subjects());
        assertEquals(delegation, type.delegation());
        assertEquals("https://pf.example.com/about", type.ref());
        assertEquals("https://pf.example.com/logo.svg", type.logoUri());
    }

    @Test
    void typesKeepTheOrderTheyWereConfiguredIn() {
        assertEquals(List.of("https://b.example", "https://a.example", "https://c.example"),
                List.copyOf(TrustMarkType.parseAll("{\"https://b.example\": {}, \"https://a.example\": {}, \"https://c.example\": {}}").keySet()));
    }

    @Test
    void blankIsNone() {
        assertTrue(TrustMarkType.parseAll(null).isEmpty());
        assertTrue(TrustMarkType.parseAll(" ").isEmpty());
    }

    /** A type the operator got wrong stops the deployment, rather than issuing marks nobody can use. */
    @Test
    void anythingElseIsRefused() {
        String otherTypesDelegation = delegation(TrustMarkValidator.DELEGATION_TYP, "https://other.example/type");
        String notADelegation = delegation(TrustMarkValidator.TRUST_MARK_TYP, CERTIFIED);
        for (String bad : List.of("[]", "not json", "{\"" + CERTIFIED + "\": 1}",
                "{\"" + CERTIFIED + "\": {\"lifetime_seconds\": \"a day\"}}",
                "{\"" + CERTIFIED + "\": {\"lifetime_seconds\": 1.5}}",
                "{\"" + CERTIFIED + "\": {\"lifetime_seconds\": 0}}",
                "{\"" + CERTIFIED + "\": {\"subjects\": \"everyone\"}}",
                "{\"" + CERTIFIED + "\": {\"subjects\": 1}}",
                "{\"" + CERTIFIED + "\": {\"subjects\": \" \"}}",
                "{\"" + CERTIFIED + "\": {\"delegation\": \"" + otherTypesDelegation + "\"}}",
                "{\"" + CERTIFIED + "\": {\"delegation\": \"" + notADelegation + "\"}}",
                "{\"" + CERTIFIED + "\": {\"delegation\": \"not a jwt\"}}",
                "{\"" + CERTIFIED + "\": {\"ref\": \"http://pf.example.com/about\"}}",
                "{\"" + CERTIFIED + "\": {\"ref\": \"https:///no-host\"}}",
                "{\"" + CERTIFIED + "\": {\"logo_uri\": \"https://bad host/logo.svg\"}}",
                "{\" \": {}}")) {
            assertThrows(IllegalArgumentException.class, () -> TrustMarkType.parseAll(bad), bad);
        }
    }

    @Test
    void aTypeIsWhatItSaysItIs() {
        assertThrows(NullPointerException.class, () -> new TrustMarkType(CERTIFIED, 1, null, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> new TrustMarkType(null, 1, TrustMarkType.Subjects.ANY, null, null, null));
        assertEquals(Map.of(), TrustMarkType.parseAll("{}"));
    }
}
