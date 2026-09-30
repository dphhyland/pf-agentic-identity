/*
 * The admin bearer rule: the same token as the operator API, fail-closed, compared in constant time.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class HealthAccessTest {

    @Test
    void theTokenIsTheSystemPropertyThenTheEnvironmentAsTheOperatorApiReadsIt() {
        assertEquals("p", HealthAccess.resolveToken(Map.of(HealthAccess.TOKEN_PROPERTY, "p")::get, Map.of(HealthAccess.TOKEN_ENV, "e")::get));
        assertEquals("e", HealthAccess.resolveToken(Map.of(HealthAccess.TOKEN_PROPERTY, " ")::get, Map.of(HealthAccess.TOKEN_ENV, "e")::get));
        assertEquals("e", HealthAccess.resolveToken(name -> null, Map.of(HealthAccess.TOKEN_ENV, "e")::get));
        assertNull(HealthAccess.resolveToken(name -> null, Map.of(HealthAccess.TOKEN_ENV, "  ")::get));
        assertNull(HealthAccess.resolveToken(name -> null, name -> null));
        assertEquals("oidf.authority.admin_token", HealthAccess.TOKEN_PROPERTY);
        assertEquals("OIDF_AUTHORITY_ADMIN_TOKEN", HealthAccess.TOKEN_ENV);
    }

    @Test
    void onlyTheConfiguredTokenAsABearerIsAuthorised() {
        assertTrue(HealthAccess.isAuthorized("t", "Bearer t"));
        assertTrue(HealthAccess.isAuthorized("t", "bearer  t "), "the scheme in any case, the token trimmed");
        assertFalse(HealthAccess.isAuthorized("t", "Bearer u"));
        assertFalse(HealthAccess.isAuthorized("t", "Bearer tt"));
        assertFalse(HealthAccess.isAuthorized("t", "Basic t"));
        assertFalse(HealthAccess.isAuthorized("t", "Bearer"));
        assertFalse(HealthAccess.isAuthorized("t", null));
        assertFalse(HealthAccess.isAuthorized(null, "Bearer t"), "no token configured authorises nobody");
        assertFalse(HealthAccess.isAuthorized(" ", "Bearer  "));
    }
}
