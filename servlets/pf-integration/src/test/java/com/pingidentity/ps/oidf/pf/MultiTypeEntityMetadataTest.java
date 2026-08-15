package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.ClientEntityAuthorizer;

/**
 * Regression coverage for the Phase 0.1 fix: an entity holding more than one metadata type at once
 * (an agent is typically both {@code openid_relying_party} <em>and</em> {@code oauth_client}) must
 * have every type surfaced by {@link TrustChainValidator}, not just {@code openid_relying_party}.
 *
 * <p>Before the fix, {@code TrustChainValidationResult.leafMetadata()} returned only the
 * {@code openid_relying_party} block, so {@link ClientEntityAuthorizer#authorize}, which reads
 * {@code oauth_client}, was always handed an empty map and refused every agent with "resolved entity
 * has no oauth_client metadata" — regardless of what the entity actually published.
 */
class MultiTypeEntityMetadataTest {
    private static final String AGENT = "https://agent.example.com";
    private static final String ANCHOR = "https://anchor.example.com";

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(TestJwts.publicParams(key)));
    }

    private static String entityStatement(PublicJsonWebKey signingKey, String iss, String sub,
                                          Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        return TestJwts.sign(signingKey, "ES256", "entity-statement+jwt", c);
    }

    @Test
    void leafHoldingMultipleTypesSurfacesAll() throws Exception {
        PublicJsonWebKey agentKey = TestJwts.ec("agent-1");
        PublicJsonWebKey anchorKey = TestJwts.ec("anchor-1");

        Map<String, Object> openidRelyingParty = Map.of("client_name", "Payment Agent");
        Map<String, Object> oauthClient = Map.of(
                "client_registration_types", List.of("automatic"),
                "scope", "read_accounts create_opportunity");
        Map<String, Object> oauthResource = Map.of("resource", AGENT);

        String agentConfig = entityStatement(agentKey, AGENT, AGENT, Map.of(
                "jwks", jwks(agentKey),
                "authority_hints", List.of(ANCHOR),
                "metadata", Map.of(
                        "openid_relying_party", openidRelyingParty,
                        "oauth_client", oauthClient,
                        "oauth_resource", oauthResource)));
        String anchorConfig = entityStatement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        String subordinate = entityStatement(anchorKey, ANCHOR, AGENT, Map.of("jwks", jwks(agentKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(AGENT + "/.well-known/openid-federation", agentConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(AGENT, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        TrustChainValidationResult result = validator.validate(List.of(), AGENT, AGENT);

        // All three types the leaf published are visible, not just openid_relying_party.
        assertEquals(3, result.resolvedMetadata().size());
        assertEquals(openidRelyingParty, result.metadataFor("openid_relying_party"));
        assertEquals(oauthClient, result.metadataFor("oauth_client"));
        assertEquals(oauthResource, result.metadataFor("oauth_resource"));
        assertTrue(result.metadataFor("does_not_exist").isEmpty(), "unknown type resolves to empty, not null");

        // The deprecated accessor keeps its documented (narrower) behaviour, unchanged.
        assertEquals(openidRelyingParty, result.leafMetadata());

        // This is the actual bug: an agent resolved this way can now authenticate as an oauth_client.
        // ClientEntityAuthorizer.authorize wants the FULL multi-type metadata map (it looks up
        // "oauth_client" inside it itself) — resolvedMetadata(), not metadataFor("oauth_client").
        ClientEntityAuthorizer.Decision decision = ClientEntityAuthorizer.authorize(
                true, result.resolvedMetadata(), List.of("read_accounts"));
        assertTrue(decision.authenticated, decision.reason);
    }

    @Test
    void leafHoldingOnlyRelyingPartyTypeLeavesOauthClientEmpty() throws Exception {
        // The pre-fix shape: an entity that genuinely is *only* a relying party. oauth_client must
        // resolve to empty (not throw), and ClientEntityAuthorizer must still refuse it correctly —
        // the fix surfaces every type an entity holds, it doesn't fabricate types it doesn't hold.
        PublicJsonWebKey rpKey = TestJwts.ec("rp-1");
        PublicJsonWebKey anchorKey = TestJwts.ec("anchor-1");
        String rp = "https://rp.example.com";

        String rpConfig = entityStatement(rpKey, rp, rp, Map.of(
                "jwks", jwks(rpKey),
                "authority_hints", List.of(ANCHOR),
                "metadata", Map.of("openid_relying_party", Map.of("client_name", "Plain RP"))));
        String anchorConfig = entityStatement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        String subordinate = entityStatement(anchorKey, ANCHOR, rp, Map.of("jwks", jwks(rpKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(rp + "/.well-known/openid-federation", rpConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(rp, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        TrustChainValidationResult result = validator.validate(List.of(), rp, rp);

        assertTrue(result.metadataFor("oauth_client").isEmpty());
        ClientEntityAuthorizer.Decision decision = ClientEntityAuthorizer.authorize(
                true, result.resolvedMetadata(), List.of());
        assertFalse(decision.authenticated);
        assertTrue(decision.reason.contains("no oauth_client metadata"));
    }
}
