/*
 * CimdClientResolver parses a Client ID Metadata Document into attester clients.
 */
package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;

class CimdClientResolverTest {

    // The attester's signing key is deployment config (a throwaway demo key here), NOT in the public CIMD.
    private static final String SIGNING_JWK = "{\"kty\":\"EC\",\"kid\":\"mock-attester-1\",\"crv\":\"P-256\","
            + "\"x\":\"c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag\","
            + "\"y\":\"ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI\","
            + "\"d\":\"9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84\"}";

    private static String cimdDoc() throws Exception {
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("td-1")));
        String bundle = new JsonWebKeySet(pub).toJson();
        return "{\"spiffe_mappings\":[{"
                + "\"spiffe_id\":\"spiffe://railway.demo/workload/payment-agent\","
                + "\"client_id\":\"demo-attest-railway\","
                + "\"issuer\":\"https://attester.example.com\","
                + "\"trust_domain\":\"railway.demo\","
                + "\"bundle\":" + bundle + ","
                + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}],"
                + "\"ttl\":300"
                + "}]}";
    }

    private static CimdClientResolver resolverFor(String doc) {
        return new CimdClientResolver("https://cimd.example/doc", (url, accept) -> doc, 300, SIGNING_JWK);
    }

    @Test
    void parsesMappingIntoAnAttesterClient() throws Exception {
        CimdClientResolver resolver = resolverFor(cimdDoc());

        List<AttesterClient> clients = resolver.attestationClients();
        assertEquals(1, clients.size());
        AttesterClient c = clients.get(0);
        assertEquals("demo-attest-railway", c.clientId());
        assertEquals("https://attester.example.com", c.config().issuer());
        assertEquals("railway.demo", c.config().expectedTrustDomain());
        assertTrue(c.config().bindingFor("spiffe://railway.demo/workload/payment-agent").isPresent());
        assertEquals("https://attester.example.com", resolver.resolve("demo-attest-railway").issuer());
    }

    @Test
    void cachesWithinTtlThenRefetches() throws Exception {
        String doc = cimdDoc();
        AtomicInteger fetches = new AtomicInteger();
        HttpGetClient http = (url, accept) -> {
            fetches.incrementAndGet();
            return doc;
        };
        CimdClientResolver cached = new CimdClientResolver("https://cimd.example/doc", http, 300);
        cached.attestationClients();
        cached.attestationClients();
        assertEquals(1, fetches.get(), "second call within TTL served from cache");
    }

    @Test
    void servesStaleCopyWhenRefetchFails() throws Exception {
        String doc = cimdDoc();
        AtomicInteger fetches = new AtomicInteger();
        HttpGetClient http = (url, accept) -> {
            if (fetches.incrementAndGet() == 1) {
                return doc;
            }
            throw new IllegalStateException("upstream down");
        };
        CimdClientResolver cache = new CimdClientResolver("https://cimd.example/doc", http, 0);
        assertEquals(1, cache.attestationClients().size());
        assertEquals(1, cache.attestationClients().size(), "stale copy served on error");
    }

    @Test
    void fetchFailureWithNoCacheIsServerError() {
        CimdClientResolver cache = new CimdClientResolver("https://cimd.example/doc",
                (url, accept) -> { throw new IllegalStateException("down"); }, 300);
        IssuanceException e = assertThrows(IssuanceException.class, cache::attestationClients);
        assertEquals("server_error", e.error());
    }

    @Test
    void unknownClientIdIsRejected() throws Exception {
        String doc = cimdDoc();
        CimdClientResolver resolver = new CimdClientResolver("https://cimd.example/doc",
                (url, accept) -> doc, 300);
        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve("nope"));
        assertEquals("invalid_client", e.error());
    }
}
