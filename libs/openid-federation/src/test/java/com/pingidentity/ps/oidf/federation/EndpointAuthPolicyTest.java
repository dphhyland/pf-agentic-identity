package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Which federation endpoints take client authentication, as a federation chooses (OpenID Federation 1.0 §8.8, §8.8.1). */
class EndpointAuthPolicyTest {
    private static final List<String> ALGS = List.of("ES256", "RS256");

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8.1(6)"})
    void byDefaultNoEndpointTakesClientAuthentication() {
        EndpointAuthPolicy none = EndpointAuthPolicy.none();
        for (String endpoint : EndpointAuthPolicy.ENDPOINTS) {
            assertEquals(EndpointAuthPolicy.Mode.NONE, none.mode(endpoint));
            assertNull(none.authMethods(endpoint), "absent means [\"none\"]");
        }
        assertFalse(none.anyEnabled());
        assertSame(none, EndpointAuthPolicy.parse(null, ALGS));
        assertSame(none, EndpointAuthPolicy.parse(" ", List.of()));
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8.1(2)", "OIDFED §8.8.1(3)"})
    void eachEndpointIsOptionalRequiredOrNotAllowedAndSaysWhichMethodsItTakes() {
        EndpointAuthPolicy policy = EndpointAuthPolicy.parse("{\"federation_trust_mark_endpoint\": \"required\","
                + " \"federation_resolve_endpoint\": \"Optional\", \"federation_list_endpoint\": \"none\"}", ALGS);

        assertEquals(EndpointAuthPolicy.Mode.REQUIRED, policy.mode("federation_trust_mark_endpoint"));
        assertEquals(List.of("private_key_jwt"), policy.authMethods("federation_trust_mark_endpoint"));
        assertEquals(EndpointAuthPolicy.Mode.OPTIONAL, policy.mode("federation_resolve_endpoint"));
        assertEquals(List.of("none", "private_key_jwt"), policy.authMethods("federation_resolve_endpoint"));
        assertEquals(EndpointAuthPolicy.Mode.NONE, policy.mode("federation_list_endpoint"));
        assertNull(policy.authMethods("federation_fetch_endpoint"), "an endpoint not named takes none");
        assertTrue(policy.anyEnabled());
        assertEquals(ALGS, policy.signingAlgorithms());

        assertFalse(EndpointAuthPolicy.parse("{\"federation_list_endpoint\": \"none\"}", List.of()).anyEnabled(),
                "no algorithm is needed where nothing authenticates");
    }

    @Test
    void anythingElseStopsTheDeploymentStarting() {
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse("{\"federation_registration_endpoint\": \"required\"}", ALGS),
                "explicit registration authenticates with the request itself, not under §8.8");
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse("{\"federation_fetch_endpoint\": \"sometimes\"}", ALGS));
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse("{\"federation_fetch_endpoint\": true}", ALGS));
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse("required", ALGS));
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse("[\"federation_fetch_endpoint\"]", ALGS));
    }

    @Test
    @Requirement("OIDFED §5.1.1(3.16)")
    void aClientSignsWithAnAsymmetricAlgorithmAndThereIsAtLeastOne() {
        String required = "{\"federation_fetch_endpoint\": \"required\"}";
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse(required, List.of("none")));
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse(required, List.of("HS256")));
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse(required, List.of("RS265")), "a typo is not an algorithm");
        assertThrows(IllegalArgumentException.class, () -> EndpointAuthPolicy.parse(required, List.of()));
        assertThrows(NullPointerException.class, () -> EndpointAuthPolicy.parse(required, null));
        assertEquals(List.of("EdDSA", "PS256"), EndpointAuthPolicy.parse(required, List.of("EdDSA", "PS256")).signingAlgorithms());
    }
}
