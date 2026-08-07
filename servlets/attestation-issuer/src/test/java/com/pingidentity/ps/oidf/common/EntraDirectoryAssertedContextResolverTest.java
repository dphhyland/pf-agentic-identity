/*
 * EntraDirectoryAssertedContextResolver resolves an asserted Entra Agent ID oid against a static directory.
 */
package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EntraDirectoryAssertedContextResolverTest {

    private static final String DIRECTORY_JSON = "{"
            + "\"d7c5a2b1-0000-4000-8000-copilot0demo\":{"
            + "\"display_name\":\"Northwind Copilot (demo)\","
            + "\"groups\":[\"copilot-bridge-users\",\"copilot-payments-allowed\"],"
            + "\"ceiling\":[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]"
            + "}}";

    @Test
    void idIsEntraDirectory() {
        assertEquals("entra-directory", EntraDirectoryAssertedContextResolver.ID);
    }

    @Test
    void resolvesARegisteredOidToItsClaimsAndCeiling() throws Exception {
        EntraDirectoryAssertedContextResolver resolver =
                EntraDirectoryAssertedContextResolver.fromJson(DIRECTORY_JSON);
        AssertedContext context = resolver.resolve(
                InstanceIdentity.ofSpiffe(new SpiffeSvid("spiffe://demo/gateway", "demo", "/gateway",
                        List.of("https://attester.example.com"), 0, 0, "raw")),
                "d7c5a2b1-0000-4000-8000-copilot0demo", null);
        assertEquals("entra-copilot-agent-oid", context.claims().get("type"));
        assertEquals("d7c5a2b1-0000-4000-8000-copilot0demo", context.claims().get("oid"));
        assertEquals("Northwind Copilot (demo)", context.claims().get("display_name"));
        assertEquals(List.of("copilot-bridge-users", "copilot-payments-allowed"), context.claims().get("groups"));
        assertEquals(1, context.ceiling().size());
        assertEquals("payment_initiation", context.ceiling().get(0).get("type"));
    }

    @Test
    void unknownOidIsAccessDenied() throws Exception {
        EntraDirectoryAssertedContextResolver resolver =
                EntraDirectoryAssertedContextResolver.fromJson(DIRECTORY_JSON);
        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve(
                InstanceIdentity.ofSpiffe(new SpiffeSvid("spiffe://demo/gateway", "demo", "/gateway",
                        List.of("https://attester.example.com"), 0, 0, "raw")),
                "ffffffff-not-registered", null));
        assertEquals("access_denied", e.error());
    }

    @Test
    void blankDiscriminatorIsInvalidRequest() throws Exception {
        EntraDirectoryAssertedContextResolver resolver =
                EntraDirectoryAssertedContextResolver.fromJson(DIRECTORY_JSON);
        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve(
                InstanceIdentity.ofSpiffe(new SpiffeSvid("spiffe://demo/gateway", "demo", "/gateway",
                        List.of("https://attester.example.com"), 0, 0, "raw")),
                "  ", null));
        assertEquals("invalid_request", e.error());
    }

    @Test
    void fromJsonReturnsNullForAbsentOrUnparseable() {
        assertNull(EntraDirectoryAssertedContextResolver.fromJson(null));
        assertNull(EntraDirectoryAssertedContextResolver.fromJson(""));
        assertNull(EntraDirectoryAssertedContextResolver.fromJson("not json"));
        assertNull(EntraDirectoryAssertedContextResolver.fromJson("{}"));
    }

    @Test
    void entryWithNoGroupsOrCeilingDefaultsToEmpty() throws Exception {
        EntraDirectoryAssertedContextResolver resolver =
                EntraDirectoryAssertedContextResolver.fromJson("{\"oid-1\":{}}");
        AssertedContext context = resolver.resolve(
                InstanceIdentity.ofSpiffe(new SpiffeSvid("spiffe://demo/gateway", "demo", "/gateway",
                        List.of("https://attester.example.com"), 0, 0, "raw")),
                "oid-1", null);
        assertEquals(List.of(), context.claims().get("groups"));
        assertTrue(context.ceiling().isEmpty());
    }
}
