/*
 * The SSF servlets with no part of their own start nothing: their init answers whether the transmitter is up.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import com.pingidentity.ps.oidf.ssf.SsfSupportTestAccess;
import jakarta.servlet.ServletConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfBootstrapTest {

    @BeforeEach
    @AfterEach
    void fresh() {
        SsfSupportTestAccess.reset();
    }

    /**
     * Before 0.6.0 every SSF servlet's init started the transmitter from its own init-params; now only the
     * {@code SSF} part does, once, so an init-param on the poll servlet configures nothing.
     */
    @Test
    void aServletWithNoPartStartsNothing() {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("issuer")).thenReturn("https://op.example.com");

        assertFalse(SsfHttp.bootstrap(cfg), "the transmitter starts from its part, not from here");
        assertFalse(SsfSupport.isConfigured());
    }

    @Test
    void itAnswersWhetherTheTransmitterIsUp() {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").build());

        assertTrue(SsfHttp.bootstrap(null));
    }
}
