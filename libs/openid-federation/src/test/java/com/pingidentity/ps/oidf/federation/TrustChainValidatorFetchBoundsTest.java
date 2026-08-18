package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.HttpGetClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * The walk is over caller-supplied data: a chain's leaf names authority_hints, each of which can name
 * more, and every hint is tried. These assert the ceilings that keep one unauthenticated request from
 * turning into an unbounded outbound fan-out on a synchronous request thread.
 */
class TrustChainValidatorFetchBoundsTest {

    private static final String ANCHOR = "https://anchor.example";
    private static final String LEAF = "https://leaf.example";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey k = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        k.setKeyId(kid);
        return k;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static String statement(PublicJsonWebKey signer, String iss, String sub, Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTimeMinutesInTheFuture(30.0f);
        claims.forEach(c::setClaim);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signer.getPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        return jws.getCompactSerialization();
    }

    @Test
    void aFanOutOfHintsCannotSpendUnboundedFetches() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        // A leaf naming many authorities, none of which is the configured anchor. Every one is a URL
        // this validator would otherwise dereference looking for a route.
        List<String> hints = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            hints.add("https://hint-" + i + ".example");
        }
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", hints));

        AtomicInteger fetches = new AtomicInteger();
        HttpGetClient http = (url, accept) -> {
            fetches.incrementAndGet();
            if (url.startsWith(LEAF)) {
                return leafConfig;
            }
            // Every hint answers with a statement that names yet more authorities.
            throw new IllegalArgumentException("unreachable: " + url);
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);

        assertThrows(IllegalArgumentException.class, () -> validator.validate(List.of(), LEAF, LEAF));
        assertTrue(fetches.get() <= TrustChainValidator.DEFAULT_MAX_FETCHES_PER_VALIDATION + 2,
                "fan-out must be bounded by the fetch budget, made " + fetches.get() + " fetches");
    }

    @Test
    void aNonHttpsLeafIdentifierIsRefusedBeforeAnyFetch() {
        AtomicInteger fetches = new AtomicInteger();
        HttpGetClient http = (url, accept) -> {
            fetches.incrementAndGet();
            return "";
        };
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);

        for (String bad : new String[] { "file:///etc/passwd", "gopher://x/1", "not-a-url" }) {
            assertThrows(IllegalArgumentException.class, () -> validator.validate(List.of(), bad, bad), bad);
        }
        assertTrue(fetches.get() == 0, "a non-https entity identifier must be refused before any fetch");
    }
}
