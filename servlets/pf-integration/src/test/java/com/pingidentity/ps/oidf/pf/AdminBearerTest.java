package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.ServletConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The operator endpoints' bearer check: closed unless a token is configured, and then open only to exactly
 * that token.
 */
class AdminBearerTest {
    private static final String PROP = "oidf.test.admin.token";

    @AfterEach
    void clear() {
        System.clearProperty(PROP);
    }

    @Test
    void anUnconfiguredTokenAuthorisesNothing() {
        assertFalse(AdminBearer.isAuthorized(null, "Bearer anything"));
        assertFalse(AdminBearer.isAuthorized(" ", "Bearer  "));
    }

    @Test
    void onlyTheConfiguredTokenAsABearerIsAccepted() {
        assertTrue(AdminBearer.isAuthorized("s3cret", "Bearer s3cret"));
        assertTrue(AdminBearer.isAuthorized("s3cret", "bearer s3cret "), "the scheme is case-insensitive");
        assertFalse(AdminBearer.isAuthorized("s3cret", "Bearer s3cret-not"));
        assertFalse(AdminBearer.isAuthorized("s3cret", "Basic s3cret"));
        assertFalse(AdminBearer.isAuthorized("s3cret", null));
        assertFalse(AdminBearer.isAuthorized("s3cret", "Bearer"));
    }

    @Test
    void theTokenIsReadInitParamFirstThenPropertyThenEnvironment() {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("adminToken")).thenReturn("from-init");
        assertEquals("from-init", AdminBearer.resolveToken(config, "adminToken", PROP, "OIDF_TEST_ADMIN_TOKEN_UNSET"));

        System.setProperty(PROP, "from-prop");
        assertEquals("from-prop", AdminBearer.resolveToken(mock(ServletConfig.class), "adminToken", PROP, "OIDF_TEST_ADMIN_TOKEN_UNSET"));
        assertEquals("from-prop", AdminBearer.resolveToken(null, "adminToken", PROP, "OIDF_TEST_ADMIN_TOKEN_UNSET"));

        System.clearProperty(PROP);
        assertNull(AdminBearer.resolveToken(null, "adminToken", PROP, "OIDF_TEST_ADMIN_TOKEN_UNSET"));
    }
}
