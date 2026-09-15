package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RarContainmentTest {

    @Test
    @Requirement("RFC9396 §6.1")
    void requestWithinEntitlementIsSubset() {
        Map<String, Object> accepted = Map.of("type", "sales_agent",
                "actions", List.of("read_accounts", "create_opportunity"), "sales_regions", List.of("EMEA"));
        Map<String, Object> requested = Map.of("type", "sales_agent",
                "actions", List.of("create_opportunity"), "sales_regions", List.of("EMEA"));
        assertTrue(RarContainment.isSubset(requested, accepted));
    }

    @Test
    @Requirement("RFC9396 §6.1")
    void regionOutsideEntitlementIsNotSubset() {
        Map<String, Object> accepted = Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"));
        Map<String, Object> requested = Map.of("type", "sales_agent", "sales_regions", List.of("AMER"));
        assertFalse(RarContainment.isSubset(requested, accepted));
    }

    @Test
    @Requirement("RFC9396 §6.1")
    void actionOutsideEntitlementIsNotSubset() {
        Map<String, Object> accepted = Map.of("type", "sales_agent", "actions", List.of("read_accounts"));
        Map<String, Object> requested = Map.of("type", "sales_agent", "actions", List.of("delete_account"));
        assertFalse(RarContainment.isSubset(requested, accepted));
    }

    @Test
    void fieldsTheEntitlementOmitsAreUnconstrained() {
        Map<String, Object> accepted = Map.of("type", "sales_agent");
        Map<String, Object> requested = Map.of("type", "sales_agent", "actions", List.of("anything"));
        assertTrue(RarContainment.isSubset(requested, accepted));
    }

    @Test
    @Requirement("RFC9396 §6.1")
    void differentTypeIsNotSubset() {
        assertFalse(RarContainment.isSubset(Map.of("type", "payment_initiation"), Map.of("type", "sales_agent")));
    }

    /**
     * A refresh request that omits a field the accepted detail constrains. Containment here is a
     * boolean the refresh path acts on by issuing the REQUESTED detail, so "contained" would replace an
     * EMEA-only grant with one that names no region at all. The token endpoint answers the same
     * question by inheriting the constraint into the grant ({@code RarEntitlement}); a boolean cannot
     * narrow, so the only answer that never widens is no.
     */
    @Test
    @Requirement("CAS §7")
    void aRequestThatOmitsAFieldTheAcceptedDetailConstrainsIsNotContained() {
        Map<String, Object> accepted = Map.of("type", "sales_agent",
                "actions", List.of("read_accounts"), "sales_regions", List.of("EMEA"));
        Map<String, Object> requested = Map.of("type", "sales_agent", "actions", List.of("read_accounts"));
        assertFalse(RarContainment.isSubset(requested, accepted));
    }
}
