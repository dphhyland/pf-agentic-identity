package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

/** https, or http under development, and nothing else: the rule the admin console and configure both apply. */
class PdpUrlPolicyTest {

    @Test
    void httpsIsAlwaysAcceptable() {
        assertNull(PdpUrlPolicy.problem("https://pdp.internal/decide", "production"));
        assertNull(PdpUrlPolicy.problem("HTTPS://pdp.internal:8443/decide", "development"));
        assertEquals("https://pdp.internal/decide", PdpUrlPolicy.check(" https://pdp.internal/decide ", "production"));
    }

    @Test
    void httpNeedsDevelopment() {
        assertNull(PdpUrlPolicy.problem("http://host.docker.internal:45500/decide", "development"));
        String refused = PdpUrlPolicy.problem("http://pdp.internal/decide", "production");
        assertTrue(refused.contains("OIDF_DEPLOYMENT_PROFILE=development"), refused);
        assertTrue(refused.contains("production"), refused);
        assertThrows(IllegalStateException.class, () -> PdpUrlPolicy.check("http://pdp.internal/decide", "production"));
        assertThrows(IllegalStateException.class, () -> PdpUrlPolicy.check("http://pdp.internal/decide", null));
    }

    @Test
    void anythingElseIsRefused() {
        assertTrue(PdpUrlPolicy.problem(null, "development").contains("required"));
        assertTrue(PdpUrlPolicy.problem(" ", "development").contains("required"));
        assertTrue(PdpUrlPolicy.problem("ftp://pdp/decide", "development").contains("ftp"));
        assertTrue(PdpUrlPolicy.problem("pdp.internal/decide", "development").contains("no host"));
        assertTrue(PdpUrlPolicy.problem("https:///decide", "development").contains("no host"));
        assertTrue(PdpUrlPolicy.problem("http://[bad", "development").contains("not a URL"));
        assertTrue(PdpUrlPolicy.problem("https://", "production").contains("not a URL"), "an empty authority is a parse error");
    }

    @Test
    void theValidatorSaysTheSameToTheAdminConsole() throws Exception {
        PdpUrlPolicy.Validator production = new PdpUrlPolicy.Validator("production");
        production.validate(new Field("PDP URL", "https://pdp.internal/decide"));
        ValidationException e = assertThrows(ValidationException.class,
                () -> production.validate(new Field("PDP URL", "http://pdp.internal/decide")));
        assertTrue(e.getMessage().contains("https"), e.getMessage());
        assertThrows(ValidationException.class, () -> production.validate(null));
        new PdpUrlPolicy.Validator("development").validate(new Field("PDP URL", "http://pdp.internal/decide"));
    }
}
