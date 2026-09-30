/*
 * The global required claims: the system property, else the environment variable (plan item R-I3).
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class RequiredClaimsDefaultTest {

    private static final String PROPERTY = "oidf.attestation.required.claims";
    private static final String ENV = "OIDF_ATTESTATION_REQUIRED_CLAIMS";

    private static Function<String, String> of(String name, String value) {
        return value == null ? n -> null : n -> Map.of(name, value).get(n);
    }

    @Test
    void theSystemPropertyComesFirst() {
        assertEquals(Set.of("workload"),
                ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, "workload"), of(ENV, "agent")));
    }

    @Test
    void theEnvironmentVariableIsReadWhenThePropertyIsUnsetOrBlank() {
        assertEquals(Set.of("workload"), ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, null), of(ENV, "workload")));
        assertEquals(Set.of("workload"), ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, "  "), of(ENV, "workload")));
    }

    @Test
    void theListIsCommaSeparatedTrimmedAndInOrder() {
        assertEquals(List.of("workload", "agent"), List.copyOf(
                ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, null), of(ENV, " workload , ,agent,workload "))));
    }

    @Test
    void nothingNamedIsNoRequiredClaims() {
        assertNull(ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, null), of(ENV, null)),
                "the code's default is unchanged: no required claims (Phase 3 plan, decision 12)");
        assertNull(ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, ""), of(ENV, " ")));
        assertNull(ClientAttestationUtils.requiredClaimsDefault(of(PROPERTY, null), of(ENV, " , ,")));
    }
}
