/*
 * /ssf/events:emit answers a provisioner and nobody else - least of all a receiver.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.servlet.ssf.SsfEventEmitServlet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * {@link SsfEmitServiceTest} covers the rule. This covers that the endpoint is wired to it, the way
 * {@link ScimProvisionerGateTest} does for SCIM: driven through the servlet with a fake introspection, so
 * the scope check under test is the one a request meets. A receiver that could raise an event would have
 * the transmitter sign a SET about any subject, onto every receiver's stream.
 */
class EmitProvisionerGateTest {

    private static final String BODY = "{\"event_type\":\"" + SsfEventTypes.CAEP_SESSION_REVOKED
            + "\",\"subject\":{\"format\":\"email\",\"email\":\"alice@example.com\"}}";
    private static final Map<String, AuthContext> TOKENS = Map.of(
            "receiver", AuthContext.active("receiver-a", Set.of("ssf.manage")),
            "provisioner", AuthContext.active("operator", Set.of("ssf.provision")));

    @BeforeEach
    @AfterEach
    void reset() {
        SsfSupport.resetForTests();
    }

    private static void configure(String provisionerScope) {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope(provisionerScope).defaultSubjects("ALL").build());
        SsfSupport.installReceiverAuthenticator(token -> TOKENS.getOrDefault(token, AuthContext.inactive()));
        // A stream that does not deliver the raised type: the gate is what is under test, and a SET minted
        // here would need PingFederate's signing key. A 200 with a fan-out of nothing is the gate passing.
        SsfSupport.store().createStream(Stream.builder().id("s1").audience("receiver-a").ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.POLL).eventsRequested(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED))
                .eventsDelivered(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED)).status(StreamStatus.ENABLED).build());
    }

    private static int post(String token) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(req.getInputStream()).thenReturn(new BytesInputStream(BODY));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new ByteArrayOutputStream()));

        new SsfEventEmitServlet().service(req, resp);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        verify(resp).setStatus(status.capture());
        return status.getValue();
    }

    @Test
    @Requirement("CAEPIOP §2.4.4")
    void aReceiverTokenIsRefusedAndAProvisionerTokenIsNot() throws Exception {
        configure("ssf.provision");

        assertEquals(403, post("receiver"));
        assertEquals(0, SsfSupport.store().peek("s1", 10).size(), "refused before anything was signed");
        assertEquals(401, post("nobody"));

        assertEquals(200, post("provisioner")); // control: same request, the other scope
    }

    @Test
    void withNoProvisionerScopeConfiguredTheEndpointRefusesEveryone() throws Exception {
        configure(null);

        assertEquals(403, post("provisioner"));
        assertEquals(403, post("receiver"));
    }

    private static final class BytesInputStream extends ServletInputStream {
        private final ByteArrayInputStream bytes;

        BytesInputStream(String body) {
            this.bytes = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public int read() {
            return this.bytes.read();
        }

        @Override
        public boolean isFinished() {
            return this.bytes.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
        }
    }
}
