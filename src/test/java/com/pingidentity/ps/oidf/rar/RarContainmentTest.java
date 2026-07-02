package com.pingidentity.ps.oidf.rar;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RarContainmentTest {

    @Test
    void requestWithinEntitlementIsSubset() {
        Map<String, Object> accepted = Map.of("type", "sales_agent",
                "actions", List.of("read_accounts", "create_opportunity"), "sales_regions", List.of("EMEA"));
        Map<String, Object> requested = Map.of("type", "sales_agent",
                "actions", List.of("create_opportunity"), "sales_regions", List.of("EMEA"));
        assertTrue(RarContainment.isSubset(requested, accepted));
    }

    @Test
    void regionOutsideEntitlementIsNotSubset() {
        Map<String, Object> accepted = Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"));
        Map<String, Object> requested = Map.of("type", "sales_agent", "sales_regions", List.of("AMER"));
        assertFalse(RarContainment.isSubset(requested, accepted));
    }

    @Test
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
    void differentTypeIsNotSubset() {
        assertFalse(RarContainment.isSubset(Map.of("type", "payment_initiation"), Map.of("type", "sales_agent")));
    }
}
