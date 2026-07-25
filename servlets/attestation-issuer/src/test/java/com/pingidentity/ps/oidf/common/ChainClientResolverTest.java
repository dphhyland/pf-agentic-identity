/*
 * ChainClientResolver aggregates clients across resolver plugins.
 */
package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;

class ChainClientResolverTest {

    private static AttestationIssuanceConfig config(String spiffeId) throws Exception {
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("k")));
        return AttestationIssuanceConfig.fromProperties(Map.of(
                AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com",
                AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson(),
                AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"" + spiffeId + "\"}]"));
    }

    private static IssuanceClientResolver plugin(String id, AttesterClient... clients) {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                for (AttesterClient c : clients) {
                    if (c.clientId().equals(clientId)) {
                        return c.config();
                    }
                }
                throw IssuanceException.invalidClient("unknown: " + clientId);
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of(clients);
            }

            @Override
            public String pluginId() {
                return id;
            }
        };
    }

    @Test
    void unionsClientsAcrossPluginsAndListsActiveIds() throws Exception {
        AttesterClient a = new AttesterClient("client-a", config("spiffe://td/a"));
        AttesterClient b = new AttesterClient("client-b", config("spiffe://td/b"));
        ChainClientResolver chain = new ChainClientResolver(List.of(
                plugin("cimd", a), plugin("pf-client-metadata", b)));

        assertEquals(2, chain.attestationClients().size());
        assertEquals(List.of("cimd", "pf-client-metadata"), chain.activePluginIds());
        assertEquals("https://attester.example.com", chain.resolve("client-b").issuer());
    }

    @Test
    void sameClientInTwoPluginsIsDedupedFirstWins() throws Exception {
        // The same client declared by CIMD and by the PF store: the earlier plugin's mapping wins, so
        // evidence-first resolution sees ONE candidate rather than an ambiguous pair.
        AttesterClient fromCimd = new AttesterClient("client-a", config("spiffe://td/from-cimd"));
        AttesterClient fromPf = new AttesterClient("client-a", config("spiffe://td/from-pf"));
        ChainClientResolver chain = new ChainClientResolver(List.of(
                plugin("cimd", fromCimd), plugin("pf-client-metadata", fromPf)));

        List<AttesterClient> clients = chain.attestationClients();
        assertEquals(1, clients.size());
        assertTrue(clients.get(0).config().bindingFor("spiffe://td/from-cimd").isPresent(),
                "the first plugin's binding is the one kept");
    }

    @Test
    void aFailingPluginDoesNotSinkTheOthers() throws Exception {
        AttesterClient a = new AttesterClient("client-a", config("spiffe://td/a"));
        IssuanceClientResolver broken = new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.serverError("down");
            }

            @Override
            public List<AttesterClient> attestationClients() throws IssuanceException {
                throw IssuanceException.serverError("document unreachable");
            }

            @Override
            public String pluginId() {
                return "openid-federation";
            }
        };
        ChainClientResolver chain = new ChainClientResolver(List.of(broken, plugin("cimd", a)));
        List<AttesterClient> clients = chain.attestationClients();
        assertEquals(1, clients.size());
        assertEquals("client-a", clients.get(0).clientId());
    }

    @Test
    void allPluginsFailingSurfacesTheError() {
        IssuanceClientResolver broken = new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.serverError("down");
            }

            @Override
            public List<AttesterClient> attestationClients() throws IssuanceException {
                throw IssuanceException.serverError("document unreachable");
            }
        };
        ChainClientResolver chain = new ChainClientResolver(List.of(broken));
        IssuanceException e = assertThrows(IssuanceException.class, chain::attestationClients);
        assertEquals("server_error", e.error());
    }

    @Test
    void supportedPluginCatalogueListsAllThree() {
        List<String> ids = ClientResolverPlugins.supported().stream()
                .map(m -> (String) m.get("id")).toList();
        assertTrue(ids.contains("pf-client-metadata"));
        assertTrue(ids.contains("cimd"));
        assertTrue(ids.contains("openid-federation"));
    }
}
