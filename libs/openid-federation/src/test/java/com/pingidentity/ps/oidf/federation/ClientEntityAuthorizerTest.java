package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The four AS-side client-authentication gates — the same decision the demo shows against live Lighthouse. */
class ClientEntityAuthorizerTest {

    private static Map<String, Object> meta(List<String> regTypes, String scope) {
        return Map.of("federation_entity", Map.of("organization_name", "RP"),
            "oauth_client", Map.of("client_registration_types", regTypes, "scope", scope));
    }

    @Test
    void authenticatesMemberWithinPolicyAndScope() {
        // rp-sales requesting a subset of its registered scopes
        ClientEntityAuthorizer.Decision d = ClientEntityAuthorizer.authorize(
            true, meta(List.of("automatic"), "read_accounts create_opportunity submit_quote"),
            List.of("read_accounts", "create_opportunity"));
        assertTrue(d.authenticated);
        assertTrue(d.member && d.statusActive && d.withinPolicy && d.scopeOk);
        assertEquals(Set.of("read_accounts", "create_opportunity"), d.grantedScopes);
    }

    @Test
    void rejectsScopeBeyondRegistered() {
        ClientEntityAuthorizer.Decision d = ClientEntityAuthorizer.authorize(
            true, meta(List.of("automatic"), "read_accounts"),
            List.of("read_accounts", "delete_account"));
        assertFalse(d.authenticated);
        assertTrue(d.member && d.withinPolicy);
        assertFalse(d.scopeOk);
        assertTrue(d.reason.contains("delete_account"));
    }

    @Test
    void rejectsWhenPolicyForbidsAutomaticRegistration() {
        // rp-legacy: resolves fine, but explicit-only registration
        ClientEntityAuthorizer.Decision d = ClientEntityAuthorizer.authorize(
            true, meta(List.of("explicit"), "read_accounts"), List.of("read_accounts"));
        assertFalse(d.authenticated);
        assertTrue(d.member);
        assertFalse(d.withinPolicy);
    }

    @Test
    void rejectsUnresolvedEntity() {
        // rp-suspended / unknown: does not chain to the anchor
        ClientEntityAuthorizer.Decision d = ClientEntityAuthorizer.authorize(false, null, List.of("read_accounts"));
        assertFalse(d.authenticated);
        assertFalse(d.member);
        assertFalse(d.statusActive);
    }

    @Test
    void rejectsResolvedEntityWithoutOauthClientMetadata() {
        ClientEntityAuthorizer.Decision d = ClientEntityAuthorizer.authorize(
            true, Map.of("federation_entity", Map.of()), List.of("read_accounts"));
        assertFalse(d.authenticated);
        assertTrue(d.member);
        assertFalse(d.withinPolicy);
    }
}
