package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import com.pingidentity.ps.oidf.conformance.Requirement;
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
    @Requirement("CAS §7")
    void grantsRequestWithinEntitlement() throws Exception {
        assertEquals(1, RarEntitlement.authorize(req("EMEA", "create_opportunity"), ENTITLEMENT).size());
    }

    /**
     * A request that omits a field the entitlement constrains. {@code containsAll} of nothing is true,
     * so this was granted verbatim — a {@code sales_agent} detail with no {@code sales_regions} at all,
     * which every consumer downstream reads as "any region". Narrowing by omission produced a wider
     * grant than the EMEA-only ceiling. CAS §7: the issued details MUST be a subset of the ceiling;
     * the request's silence on a field means the ceiling's value for it, not the absence of one.
     */
    @Test
    @Requirement("CAS §7")
    void aRequestThatOmitsAConstrainedFieldInheritsTheCeilingsValueForIt() throws Exception {
        List<Map<String, Object>> requested = List.of(Map.of("type", "sales_agent", "actions", List.of("read_accounts")));

        List<Map<String, Object>> granted = RarEntitlement.authorize(requested, ENTITLEMENT);

        assertEquals(1, granted.size());
        Map<String, Object> detail = granted.get(0);
        assertEquals(List.of("read_accounts"), detail.get("actions"), "what was asked for stays as asked");
        assertEquals(List.of("EMEA"), detail.get("sales_regions"), "the omitted constraint is inherited, not dropped");
        assertEquals(List.of("https://crm.contoso.com/api"), detail.get("locations"));
        assertEquals(List.of("quota:standard"), detail.get("privileges"));
    }

    /** The other direction is unchanged: a field the entitlement does not constrain passes through as requested. */
    @Test
    @Requirement("CAS §7")
    void aFieldTheEntitlementDoesNotConstrainPassesThroughUnchanged() throws Exception {
        List<Map<String, Object>> ceiling = List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA")));
        List<Map<String, Object>> requested = List.of(Map.of("type", "sales_agent",
                "sales_regions", List.of("EMEA"), "actions", List.of("anything")));

        Map<String, Object> detail = RarEntitlement.authorize(requested, ceiling).get(0);

        assertEquals(List.of("anything"), detail.get("actions"));
        assertEquals(List.of("EMEA"), detail.get("sales_regions"));
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
