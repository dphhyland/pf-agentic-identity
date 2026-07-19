/*
 * Fail-soft servlet bootstrap: unconfigured SSF returns false (never throws); configured returns true.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.ServletConfig;
import org.junit.jupiter.api.Test;

class SsfBootstrapTest {

    @Test
    void unconfiguredReturnsFalseAndDoesNotThrow() {
        System.clearProperty("oidf.ssf.issuer"); // ensure no ambient config
        ServletConfig cfg = mock(ServletConfig.class); // all init-params null
        assertFalse(SsfHttp.bootstrap(cfg), "no issuer -> SSF stays disabled, bootstrap returns false");
    }

    @Test
    void configuredReturnsTrue() {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("issuer")).thenReturn("https://op.example.com");
        assertTrue(SsfHttp.bootstrap(cfg), "issuer present -> transmitter configured");
    }
}
