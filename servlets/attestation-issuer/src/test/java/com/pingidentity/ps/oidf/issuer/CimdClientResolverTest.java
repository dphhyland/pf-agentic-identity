/*
 * CimdClientResolver parses a Client ID Metadata Document into attester clients.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

class CimdClientResolverTest {

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

    private static CimdClientResolver resolverFor(String doc) throws Exception {
        // Generated per run. The attester's signing key is deployment config, not part of the public
        // CIMD - and a real private key committed to a test file is a real private key, wherever the
        // file ends up. This one used to be mock-attester-1, whose public half a demo image trusted.
        String signingJwk = TestJwts.ec("test-attester").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        return new CimdClientResolver("https://cimd.example/doc", (url, accept) -> doc, 300, signingJwk);
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
