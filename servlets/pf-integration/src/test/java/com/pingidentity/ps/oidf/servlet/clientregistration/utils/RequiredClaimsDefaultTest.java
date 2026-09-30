/*
 * The global required claims: the system property, else the environment variable (plan item R-I3), strictly (ST-5).
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;

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

    /** The global required claims with this system-property lookup and this environment lookup. */
    private static Set<String> requiredClaimsDefault(Function<String, String> props, Function<String, String> env) {
        return ClientAttestationUtils.requiredClaimsDefault(Sources.of(env, props, null));
    }

    @Test
    void theSystemPropertyComesFirst() {
        assertEquals(Set.of("workload"),
                requiredClaimsDefault(of(PROPERTY, "workload"), of(ENV, "agent")));
    }

    @Test
    void theEnvironmentVariableIsReadWhenThePropertyIsUnsetOrBlank() {
        assertEquals(Set.of("workload"), requiredClaimsDefault(of(PROPERTY, null), of(ENV, "workload")));
        assertEquals(Set.of("workload"), requiredClaimsDefault(of(PROPERTY, "  "), of(ENV, "workload")));
    }

    @Test
    void theListIsCommaSeparatedTrimmedAndInOrder() {
        assertEquals(List.of("workload", "agent"), List.copyOf(
                requiredClaimsDefault(of(PROPERTY, null), of(ENV, " workload , ,agent,workload "))));
    }

    @Test
    void nothingNamedIsNoRequiredClaims() {
        assertNull(requiredClaimsDefault(of(PROPERTY, null), of(ENV, null)),
                "the code's default is unchanged: no required claims (Phase 3 plan, decision 12)");
        assertNull(requiredClaimsDefault(of(PROPERTY, ""), of(ENV, " ")));
        // A list of nothing is refused from 0.6.0 (plan item ST-5), naming the setting, where it was read as none.
        assertEquals(PROPERTY, assertThrows(SettingRefused.class, () -> requiredClaimsDefault(of(PROPERTY, null), of(ENV, " , ,")))
                .setting());
    }
}
