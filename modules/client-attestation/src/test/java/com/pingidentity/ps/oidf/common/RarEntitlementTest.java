package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RarEntitlementTest {

    // Sales agent entitled to EMEA only (RFC 9396 authorization_details asserted by the attester).
    private static final List<Map<String, Object>> ENTITLEMENT = List.of(Map.of(
            "type", "sales_agent",
            "actions", List.of("read_accounts", "create_opportunity", "submit_quote"),
            "locations", List.of("https://crm.contoso.com/api"),
            "sales_regions", List.of("EMEA"),
            "privileges", List.of("quota:standard")));

    private static List<Map<String, Object>> req(String region, String action) {
        return List.of(Map.of("type", "sales_agent", "actions", List.of(action), "sales_regions", List.of(region)));
    }

    @Test
    void grantsRequestWithinEntitlement() throws Exception {
        assertEquals(1, RarEntitlement.authorize(req("EMEA", "create_opportunity"), ENTITLEMENT).size());
    }

    @Test
    void deniesRegionOutsideEntitlement() {
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> RarEntitlement.authorize(req("AMER", "create_opportunity"), ENTITLEMENT));
        assertEquals(ClientAttestationException.ACCESS_DENIED, e.error());
    }

    @Test
    void deniesActionOutsideEntitlement() {
        assertThrows(ClientAttestationException.class,
                () -> RarEntitlement.authorize(req("EMEA", "delete_account"), ENTITLEMENT));
    }

    @Test
    void deniesWhenNoEntitlementButRequested() {
        assertThrows(ClientAttestationException.class,
                () -> RarEntitlement.authorize(req("EMEA", "read_accounts"), List.of()));
    }

    @Test
    void grantsNothingWhenNoneRequested() throws Exception {
        assertTrue(RarEntitlement.authorize(List.of(), ENTITLEMENT).isEmpty());
    }

    @Test
    void missingTypeIsInvalid() {
        List<Map<String, Object>> bad = List.of(Map.of("actions", List.of("read_accounts")));
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> RarEntitlement.authorize(bad, ENTITLEMENT));
        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
    }

    @Test
    void parseArrayReadsJson() throws Exception {
        List<Map<String, Object>> parsed = RarEntitlement.parseArray(
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]");
        assertEquals("sales_agent", parsed.get(0).get("type"));
    }

    @Test
    void parseArrayEmptyForBlank() throws Exception {
        assertTrue(RarEntitlement.parseArray(null).isEmpty());
        assertTrue(RarEntitlement.parseArray("  ").isEmpty());
    }
}
