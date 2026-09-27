/*
 * Fail-soft servlet bootstrap: unconfigured SSF returns false (never throws); configured returns true.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.SsfSupport;
import jakarta.servlet.ServletConfig;
import org.junit.jupiter.api.Test;

class SsfBootstrapTest {

    @Test
    void unconfiguredReturnsFalseAndDoesNotThrow() {
        System.clearProperty("oidf.ssf.issuer"); // ensure no ambient config
        ServletConfig cfg = mock(ServletConfig.class); // all init-params null
        assertFalse(SsfHttp.bootstrap(cfg), "no issuer -> SSF stays disabled, bootstrap returns false");
    }

    /**
     * The push loop is the bootstrap's to start, so it runs from the first servlet to initialise - at boot,
     * {@code SsfConfigurationServlet} (loadOnStartup = 1) - and not, as until 0.4.0, from the stream
     * management servlet's lazy init, which no request may reach for hours (B5).
     */
    @Test
    void configuredReturnsTrueAndThePushLoopIsRunning() {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("issuer")).thenReturn("https://op.example.com");
        assertTrue(SsfHttp.bootstrap(cfg), "issuer present -> transmitter configured");
        assertTrue(SsfSupport.pushDeliveryService().isRunning(), "started by the bootstrap, not by a management request");
    }
}
