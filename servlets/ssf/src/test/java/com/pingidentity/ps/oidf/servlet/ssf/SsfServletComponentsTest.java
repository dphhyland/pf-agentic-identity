/*
 * The SSF servlets register their parts at deploy and answer through their gates.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import com.pingidentity.ps.oidf.ssf.SsfSupportTestAccess;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfServletComponentsTest {

    @BeforeEach
    void fresh() {
        System.clearProperty("oidf.ssf.issuer");
        SsfSupportTestAccess.reset();
        SsfHttp.resetForTests();
        ProfileRefusals.resetForTests();
        // The in-memory store these tests run on is refused under production without the risk; development warns.
        ProfileRefusals.publish(new ProfileAudit.Result(DeploymentProfile.DEVELOPMENT, List.of(), List.of()));
    }

    @AfterEach
    void cleanUp() {
        SsfSupportTestAccess.reset();
        SsfHttp.resetForTests();
        ProfileRefusals.resetForTests();
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((k, v) -> when(config.getInitParameter(k)).thenReturn(v));
        return config;
    }

    private static HttpServletResponse response() throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        return resp;
    }

    @Test
    void bothServletsLoadAtStartUpTheReceiverAfterTheTransmitter() {
        assertEquals(1, SsfConfigurationServlet.class.getAnnotation(WebServlet.class).loadOnStartup());
        assertEquals(2, SsfReceiverServlet.class.getAnnotation(WebServlet.class).loadOnStartup(), "finding F-0193's last servlet");
    }

    @Test
    void withNoIssuerTheTransmitterIsDisabledAndItsServletsAnswer404() throws Exception {
        new SsfConfigurationServlet().init(config(Map.of()));
        assertEquals(ComponentState.DISABLED, part("SsfConfigurationServlet").state());
        assertEquals(Startup.SSF, part("SsfConfigurationServlet").component());

        HttpServletResponse resp = response();
        new SsfPollServlet().doPost(mock(HttpServletRequest.class), resp);
        verify(resp).setStatus(404);
    }

    @Test
    void aConfiguredTransmitterIsReadyAndServes() throws Exception {
        SsfConfigurationServlet servlet = new SsfConfigurationServlet();
        servlet.init(config(Map.of("issuer", "https://op.example.com")));
        assertEquals(ComponentState.READY, part("SsfConfigurationServlet").state());
        assertTrue(SsfSupport.pushDeliveryService().isRunning(), "the push loop starts with the transmitter, at deploy");

        HttpServletResponse resp = response();
        servlet.doGet(mock(HttpServletRequest.class), resp);
        verify(resp).setStatus(200);
    }

    /** Every transmitter servlet answers 503 while SSF is failed: the part's gate, as the first statement. */
    @Test
    void aTransmitterThatFailedOnItsConfigurationAnswers503OnEveryServlet() throws Exception {
        SsfConfigurationServlet servlet = new SsfConfigurationServlet();
        servlet.init(config(Map.of("issuer", "https://op.example.com", "signingAlgorithm", "ES512")));
        assertEquals(ComponentState.FAILED_CONFIG, part("SsfConfigurationServlet").state());
        assertTrue(part("SsfConfigurationServlet").reason().contains("OIDF_SSF_SIGNING_ALGORITHM"), part("SsfConfigurationServlet").reason());

        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        HttpServletResponse[] responses = new HttpServletResponse[7];
        for (int i = 0; i < responses.length; i++) {
            responses[i] = response();
        }
        servlet.doGet(req, responses[0]);
        servlet.doOptions(req, responses[1]);
        new SsfPollServlet().doPost(req, responses[2]);
        new SsfEventEmitServlet().doPost(req, responses[3]);
        new SsfStreamManagementServlet().doPost(req, responses[4]);
        new SsfScimSubjectServlet().doPost(req, responses[5]);
        new SsfReceiverServlet().doPost(req, responses[6]);
        for (int i = 0; i < 6; i++) {
            verify(responses[i]).setStatus(503);
        }
        verify(responses[6]).setStatus(404); // the receiver servlet has no part yet: it answers as the receiver it is
    }

    @Test
    void withNoIssuerTheReceiverIsDisabled() throws Exception {
        new SsfConfigurationServlet().init(config(Map.of()));
        SsfReceiverServlet servlet = new SsfReceiverServlet();
        servlet.init(config(Map.of()));
        assertEquals(ComponentState.DISABLED, part("SsfReceiverServlet").state());
        assertEquals(Startup.SSF_RECEIVER, part("SsfReceiverServlet").component());

        HttpServletResponse resp = response();
        servlet.doPost(mock(HttpServletRequest.class), resp);
        verify(resp).setStatus(404);
    }

    @Test
    void aReceiverMissingItsAudienceAndTokenIsAFailedConfigurationAndAnswers503() throws Exception {
        new SsfConfigurationServlet().init(config(Map.of("issuer", "https://op.example.com",
                "receiverExpectedIssuer", "https://transmitter.example.com")));
        SsfReceiverServlet servlet = new SsfReceiverServlet();
        servlet.init(config(Map.of()));
        assertEquals(ComponentState.FAILED_CONFIG, part("SsfReceiverServlet").state());

        HttpServletResponse resp = response();
        servlet.doGet(mock(HttpServletRequest.class), resp);
        verify(resp).setStatus(503);
    }

    @Test
    void aConfiguredReceiverIsReady() throws Exception {
        new SsfConfigurationServlet().init(config(Map.of("issuer", "https://op.example.com",
                "receiverExpectedIssuer", "https://transmitter.example.com", "receiverAudience", "https://op.example.com",
                "receiverEndpointAuthToken", "t0ken", "receiverActionsEnabled", "false")));
        new SsfReceiverServlet().init(config(Map.of()));
        assertEquals(ComponentState.READY, part("SsfReceiverServlet").state());
    }
}
