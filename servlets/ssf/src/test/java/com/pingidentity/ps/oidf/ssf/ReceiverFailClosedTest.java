/*
 * An enabled receiver runs with an audience and an endpoint token, or does not run.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.servlet.ssf.SsfReceiverServlet;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.List;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * A SET acted on here revokes a user's grants. The transmitter's signature says it minted the SET, not
 * that it minted it for this receiver ({@code aud}) or that it is the one delivering it (the endpoint
 * token) - and a transmitter's other receivers can come to hold SETs it signed. Both used to be optional,
 * and unset meant unchecked.
 */
class ReceiverFailClosedTest {

    private static final String ISS = "https://tx.example.com";

    @BeforeEach
    @AfterEach
    void reset() {
        SsfSupport.resetForTests();
    }

    private static SsfConfiguration.Builder receiver() {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").receiverExpectedIssuer(ISS);
    }

    @Test
    void aReceiverMissingEitherSettingDoesNotStart() {
        SsfConfiguration neither = receiver().build();
        SsfConfiguration noToken = receiver().receiverAudience("https://me.example.com").build();
        SsfConfiguration noAudience = receiver().receiverEndpointAuthToken("s3cret").build();
        SsfConfiguration blank = receiver().receiverAudience(" ").receiverEndpointAuthToken("").build();

        assertEquals(List.of("receiverAudience", "receiverEndpointAuthToken"), neither.receiverMissingRequirements());
        assertEquals(List.of("receiverEndpointAuthToken"), noToken.receiverMissingRequirements());
        assertEquals(List.of("receiverAudience"), noAudience.receiverMissingRequirements());
        assertEquals(List.of("receiverAudience", "receiverEndpointAuthToken"), blank.receiverMissingRequirements());
        for (SsfConfiguration c : List.of(neither, noToken, noAudience, blank)) {
            assertFalse(SsfSupport.receiverMayRun(c));
        }

        SsfSupport.configure(noAudience);
        assertNull(SsfSupport.receiverService(), "not started, so nothing is accepted or polled");
        assertNotNull(SsfSupport.streamService(), "and the transmitter is unaffected");
    }

    @Test
    void aReceiverWithBothStartsAndOneThatIsOffAsksForNothing() {
        SsfConfiguration both = receiver().receiverAudience("https://me.example.com").receiverEndpointAuthToken("s3cret").build();
        SsfConfiguration off = new SsfConfiguration.Builder().issuer("https://op.example.com").build();

        assertTrue(SsfSupport.receiverMayRun(both));
        assertTrue(off.receiverMissingRequirements().isEmpty(), "a receiver that is off is not misconfigured");
        assertFalse(SsfSupport.receiverMayRun(off));

        SsfSupport.configure(both);
        assertNotNull(SsfSupport.receiverService());
    }

    @Test
    void thePushEndpointRefusesADeliveryWithoutTheToken() throws Exception {
        SsfSupport.configure(receiver().receiverAudience("https://me.example.com").receiverEndpointAuthToken("s3cret").build());

        assertEquals(401, post(null));
        assertEquals(401, post("Bearer wrong"));
        assertEquals(401, post("Basic s3cret"));
        // control: with the token the request gets past the bearer check, to be refused for its content type
        assertEquals(400, post("Bearer s3cret"));
    }

    private static int post(String authorization) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getHeader("Authorization")).thenReturn(authorization);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new ByteArrayOutputStream()));

        new SsfReceiverServlet().service(req, resp);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        org.mockito.Mockito.verify(resp).setStatus(status.capture());
        return status.getValue();
    }
}
