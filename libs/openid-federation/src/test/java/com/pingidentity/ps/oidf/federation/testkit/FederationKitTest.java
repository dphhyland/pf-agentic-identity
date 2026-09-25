package com.pingidentity.ps.oidf.federation.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The kit itself: a federation it builds must validate with the production validator, and each way it
 * breaks a statement must break only that statement. Everything else in the suite trusts these two facts.
 */
class FederationKitTest {
    private static final String TA = "https://ta.example.com";
    private static final String INT = "https://int.example.com";
    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";

    private static Federation.Builder threeLevels() {
        return Federation.builder()
                .anchor(TA)
                .intermediate(INT, TA)
                .leaf(RP, INT)
                .metadata(RP, "openid_relying_party", Map.of("client_name", "rp"));
    }

    @Test
    void aBuiltFederationValidatesWithTheProductionValidator() throws Exception {
        Federation f = threeLevels().build();

        TrustChainValidationResult result = f.validator(TA).validate(f.chain(RP, TA), RP, OP);

        assertEquals(TA, result.trustAnchorIssuer());
        assertEquals("rp", result.metadataFor("openid_relying_party").get("client_name"));
    }

    @Test
    void theValidatorCanDiscoverEverythingFromTheLeafAlone() throws Exception {
        Federation f = threeLevels().build();

        TrustChainValidationResult result = f.validator(TA).validate(List.of(), RP, OP);

        assertEquals(RP, result.leafSubject());
        assertTrue(f.http().hits(RP + "/.well-known/openid-federation") >= 1);
    }

    @Test
    void chainsFollowTheFirstPathAndCanCarryTheAnchor() throws Exception {
        Federation f = threeLevels().build();

        assertEquals(List.of(RP, INT, TA), f.path(RP, TA));
        assertEquals(3, f.chain(RP, TA).size());
        List<String> full = f.chainWithAnchor(RP, TA);
        assertEquals(4, full.size());
        assertEquals(TA, JwtCodec.parseUnverifiedClaims(full.get(3)).getSubject());
        assertThrows(IllegalArgumentException.class, () -> f.path(TA, RP));
    }

    @Test
    void entitiesWithSubordinatesPublishFetchAndListEndpoints() throws Exception {
        Federation f = threeLevels().build();

        JwtClaims ta = JwtCodec.parseUnverifiedClaims(f.entityConfiguration(TA));
        @SuppressWarnings("unchecked")
        Map<String, Object> fed = (Map<String, Object>) ((Map<String, Object>) ta.getClaimValue("metadata")).get("federation_entity");
        assertEquals(f.fetchEndpoint(TA), fed.get("federation_fetch_endpoint"));
        assertEquals(f.listEndpoint(TA), fed.get("federation_list_endpoint"));
        assertTrue(!JwtCodec.parseUnverifiedClaims(f.entityConfiguration(RP)).getClaimsMap().containsKey("authority_hints")
                || f.superiors(RP).equals(List.of(INT)));
        assertEquals(Federation.Role.INTERMEDIATE, f.role(INT));
    }

    @Test
    void breakingOneStatementBreaksTheChain() {
        Federation broken = threeLevels().subordinate(INT, RP, s -> s.typ(null)).build();

        assertThrows(Exception.class, () -> broken.validator(TA).validate(broken.chain(RP, TA), RP, OP));
    }

    @Test
    void policiesAndConstraintsLandInTheSubordinateStatement() throws Exception {
        Federation f = threeLevels()
                .metadataPolicy(TA, INT, "openid_relying_party", Map.of("client_name", Map.of("value", "fixed")))
                .constraints(TA, INT, Map.of("max_path_length", 1))
                .build();

        JwtClaims statement = JwtCodec.parseUnverifiedClaims(f.subordinateStatement(TA, INT));
        assertTrue(statement.hasClaim("metadata_policy"));
        assertTrue(statement.hasClaim("constraints"));
        assertEquals("fixed", f.validator(TA).validate(f.chain(RP, TA), RP, OP)
                .metadataFor("openid_relying_party").get("client_name"));
    }

    @Test
    void theServingMapAnswersFetchesWithOrWithoutIss() throws Exception {
        Federation f = threeLevels().build();
        ServingMap http = f.http();

        String withIss = http.get(f.fetchEndpoint(INT) + "?sub=" + java.net.URLEncoder.encode(RP, "UTF-8") + "&iss=x", "a");
        String withoutIss = http.get(f.fetchEndpoint(INT) + "?sub=" + java.net.URLEncoder.encode(RP, "UTF-8"), "a");
        assertEquals(withIss, withoutIss);
        assertThrows(IllegalArgumentException.class, () -> http.get(f.fetchEndpoint(INT) + "?sub=nobody", "a"));

        http.sequence("https://x.example/a", "one", "two");
        assertEquals("one", http.get("https://x.example/a", "a"));
        assertEquals("two", http.get("https://x.example/a", "a"));
        assertEquals("two", http.get("https://x.example/a", "a"));
        http.failing("https://x.example/b", new IllegalStateException("down"));
        assertThrows(IllegalStateException.class, () -> http.get("https://x.example/b", "a"));
        assertEquals(1, http.hits("https://x.example/b"));
        assertTrue(http.hitsStartingWith("https://x.example/") >= 4);
    }

    @Test
    void aMutableClockMovesStatementTimes() throws Exception {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_700_000_000L));
        Federation f = Federation.builder(clock).anchor(TA).leaf(RP, TA).build();
        long iat = JwtCodec.parseUnverifiedClaims(f.entityConfiguration(RP)).getIssuedAt().getValue();
        assertEquals(1_700_000_000L - 60, iat);
        clock.advance(Duration.ofHours(1));
        assertEquals(1_700_003_600L, clock.epochSecond());
    }
}
