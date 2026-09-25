package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/**
 * The Trust Mark claims an operator has this entity publish, held to the shape a receiving entity's statement checks
 * demand (§3.1.2, §3.2) - publishing one they refuse would cost this entity its own chain.
 */
class TrustMarkClaimsTest {
    private static final String CERTIFIED = "https://ta.example.com/marks/certified";

    private static String mark(String typ, String type) {
        return Statements.spec(typ).claim("iss", "https://tmi.example.com").claim("sub", "https://pf.example.com")
                .claim("trust_mark_type", type).sign(Keys.ec("tmi-1"), Clock.systemUTC());
    }

    private static String entry(String type, String jwt) {
        return "{\"trust_mark_type\": \"" + type + "\", \"trust_mark\": \"" + jwt + "\"}";
    }

    @Test
    void marksThisEntityCarriesAreTrustMarksOfTheTypeTheyAreListedUnder() {
        String mark = mark(TrustMarkValidator.TRUST_MARK_TYP, CERTIFIED);

        assertEquals(List.of(Map.of("trust_mark_type", CERTIFIED, "trust_mark", mark)), TrustMarkClaims.parseMarks("[" + entry(CERTIFIED, mark) + "]"));
        assertTrue(TrustMarkClaims.parseMarks(" ").isEmpty());
        assertTrue(TrustMarkClaims.parseMarks(null).isEmpty());
        for (String bad : List.of("{}", "not json", "[1]", "[{\"trust_mark_type\": \"" + CERTIFIED + "\"}]", "[{\"trust_mark\": \"" + mark + "\"}]",
                "[" + entry("https://other.example/type", mark) + "]",
                "[" + entry(CERTIFIED, mark("JWT", CERTIFIED)) + "]",
                "[" + entry(CERTIFIED, "not a jwt") + "]")) {
            assertThrows(IllegalArgumentException.class, () -> TrustMarkClaims.parseMarks(bad), bad);
        }
    }

    @Test
    void issuersAreEntityIdentifiersByType() {
        assertEquals(Map.of(CERTIFIED, List.of("https://tmi.example.com"), "https://ta.example.com/marks/open", List.of()),
                TrustMarkClaims.parseIssuers("{\"" + CERTIFIED + "\": [\"https://tmi.example.com\"], \"https://ta.example.com/marks/open\": []}"));
        assertTrue(TrustMarkClaims.parseIssuers(null).isEmpty());
        for (String bad : List.of("[]", "{\"" + CERTIFIED + "\": \"https://tmi.example.com\"}", "{\"" + CERTIFIED + "\": [\"http://tmi.example.com\"]}",
                "{\"" + CERTIFIED + "\": [1]}")) {
            assertThrows(IllegalArgumentException.class, () -> TrustMarkClaims.parseIssuers(bad), bad);
        }
    }

    @Test
    void anOwnerIsAnEntityWithItsPublicFederationKeys() {
        String jwks = JsonUtil.toJson(Keys.publicJwks(Keys.ec("owner-1")));
        Map<String, Object> owners = TrustMarkClaims.parseOwners("{\"" + CERTIFIED + "\": {\"sub\": \"https://owner.example.com\", \"jwks\": " + jwks + "}}");

        assertEquals("https://owner.example.com", ((Map<?, ?>) owners.get(CERTIFIED)).get("sub"));
        assertTrue(TrustMarkClaims.parseOwners("").isEmpty());
        String privateJwks = JsonUtil.toJson(Map.of("keys", List.of(Keys.privateJwk(Keys.ec("owner-1")))));
        for (String bad : List.of("not json", "{\"" + CERTIFIED + "\": []}", "{\"" + CERTIFIED + "\": {\"jwks\": " + jwks + "}}",
                "{\"" + CERTIFIED + "\": {\"sub\": \"not a url\", \"jwks\": " + jwks + "}}",
                "{\"" + CERTIFIED + "\": {\"sub\": \"https://owner.example.com\"}}",
                "{\"" + CERTIFIED + "\": {\"sub\": \"https://owner.example.com\", \"jwks\": " + privateJwks + "}}")) {
            assertThrows(IllegalArgumentException.class, () -> TrustMarkClaims.parseOwners(bad), bad);
        }
    }
}
