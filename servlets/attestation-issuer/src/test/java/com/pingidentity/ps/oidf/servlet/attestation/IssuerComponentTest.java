/*
 * The client attester registers its part at init: ready when its models load, and failed on its configuration, with
 * init still refusing to start, when they do not.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class IssuerComponentTest {

    @AfterEach
    void reset() throws Exception {
        modelsFrom(null);
    }

    private static void modelsFrom(Map<String, String> env) throws Exception {
        java.lang.reflect.Method reset = AttestationRarModels.class.getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, env);
    }

    private static PartStatus part() {
        return Startup.parts().parts().stream().filter(p -> p.part().equals("AttestationIssuanceServlet")).findFirst().orElseThrow();
    }

    @Test
    void anAttesterWhoseModelsLoadIsReady() throws Exception {
        modelsFrom(Map.of());
        new AttestationIssuanceServlet().init(mock(ServletConfig.class));
        assertEquals(ComponentState.READY, part().state());
        assertEquals(Startup.ATTESTATION_ISSUER, part().component());
    }

    @Test
    void anAttesterWhoseModelsDoNotLoadStillRefusesToStartAndIsAFailedConfiguration() throws Exception {
        modelsFrom(Map.of(RarModels.ENV_MODELS, "{\"types\":"));
        ServletException e = assertThrows(ServletException.class, () -> new AttestationIssuanceServlet().init(mock(ServletConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, part().state());
        assertTrue(part().reason().startsWith("attestation issuance: the RAR containment models could not be loaded"), part().reason());
        assertTrue(e.getMessage().startsWith("attestation issuance:"), e.getMessage());
        assertEquals(ComponentState.FAILED_CONFIG, Components.status(Startup.ATTESTATION_ISSUER).orElseThrow().state());
    }
}
