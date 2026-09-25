package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.EndpointAuthPolicy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Which federation endpoints take client authentication (§8.8), as a deployment says, and what a client may sign with. */
class FederationRuntimeConfigEndpointAuthTest {
    private static FederationRuntimeConfig from(Map<String, String> env) {
        return FederationRuntimeConfig.from(env::get, name -> null);
    }

    @Test
    @Requirement("OIDFED §8.8(1)")
    void unsetNoEndpointTakesClientAuthentication() {
        EndpointAuthPolicy policy = from(Map.of()).endpointAuth();

        assertFalse(policy.anyEnabled());
        assertEquals(List.of(), policy.signingAlgorithms(), "nothing to sign for");
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §5.1.1(3.16)"})
    void eachEndpointTakesWhatTheDeploymentSaysSignedWithRs256ByDefault() {
        EndpointAuthPolicy policy = from(Map.of(FederationRuntimeConfig.ENDPOINT_AUTH_ENV,
                "{\"federation_fetch_endpoint\": \"required\", \"federation_resolve_endpoint\": \"optional\"}")).endpointAuth();

        assertEquals(EndpointAuthPolicy.Mode.REQUIRED, policy.mode("federation_fetch_endpoint"));
        assertEquals(EndpointAuthPolicy.Mode.OPTIONAL, policy.mode("federation_resolve_endpoint"));
        assertEquals(List.of("RS256", "PS256", "ES256"), policy.signingAlgorithms(), "§5.1.1: servers SHOULD support RS256");

        EndpointAuthPolicy es = FederationRuntimeConfig.from(name -> null, name -> switch (name) {
            case "oidf.federation.endpoint.auth" -> "{\"federation_list_endpoint\": \"required\"}";
            case "oidf.federation.endpoint.auth.signing.algs" -> "ES256, EdDSA";
            default -> null;
        }).endpointAuth();
        assertEquals(List.of("ES256", "EdDSA"), es.signingAlgorithms());
        assertTrue(es.anyEnabled(), "system properties as well as the environment");
    }

    @Test
    void aSettingThatIsNotOneStopsTheDeploymentNamingIt() {
        IllegalStateException badJson = assertThrows(IllegalStateException.class, () -> from(Map.of(FederationRuntimeConfig.ENDPOINT_AUTH_ENV,
                "{\"federation_fetch_endpoint\": \"always\"}")));
        assertTrue(badJson.getMessage().startsWith(FederationRuntimeConfig.ENDPOINT_AUTH_ENV + ":"), badJson.getMessage());

        IllegalStateException badAlg = assertThrows(IllegalStateException.class, () -> from(Map.of(
                FederationRuntimeConfig.ENDPOINT_AUTH_ENV, "{\"federation_fetch_endpoint\": \"required\"}",
                FederationRuntimeConfig.ENDPOINT_AUTH_SIGNING_ALGS_ENV, "RS256 HS256")));
        assertTrue(badAlg.getMessage().startsWith(FederationRuntimeConfig.ENDPOINT_AUTH_SIGNING_ALGS_ENV + ":"), badAlg.getMessage());

        assertThrows(IllegalStateException.class, () -> from(Map.of(FederationRuntimeConfig.ENDPOINT_AUTH_SIGNING_ALGS_ENV, " , ")),
                "a list of nothing is a slip");
    }
}
