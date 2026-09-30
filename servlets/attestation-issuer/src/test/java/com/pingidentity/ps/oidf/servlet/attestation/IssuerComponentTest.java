/*
 * The client attester registers its part at init: ready when its models load, and failed on its configuration when
 * they do not - init returns, and the gate answers its path with 503.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

@org.junit.jupiter.api.extension.ExtendWith(InMemoryStateAccepted.class)
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
    void anAttesterWhoseModelsDoNotLoadIsAFailedConfigurationAndItsPathAnswers503() throws Exception {
        modelsFrom(Map.of(RarModels.ENV_MODELS, "{\"types\":"));
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        assertDoesNotThrow(() -> servlet.init(mock(ServletConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, part().state());
        assertTrue(part().reason().startsWith("attestation issuance: the RAR containment models could not be loaded"), part().reason());
        assertEquals(ComponentState.FAILED_CONFIG, Components.status(Startup.ATTESTATION_ISSUER).orElseThrow().state());

        // The gate answers first: 503 temporarily_unavailable, and the request never reaches doPost.
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                body.write(b);
            }
        });
        servlet.service(request, response);
        verify(response).setStatus(503);
        assertTrue(body.toString(StandardCharsets.UTF_8).contains("\"error\":\"temporarily_unavailable\""), body.toString(StandardCharsets.UTF_8));
        verify(request, never()).getInputStream();
        verify(response, never()).setHeader("Pragma", "no-cache");
    }
}
