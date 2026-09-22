/*
 * /ssf/scim/v2/Users answers a provisioner and nobody else - least of all a receiver.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.servlet.ssf.SsfScimSubjectServlet;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * {@link ScimSubjectServiceTest} covers the rule. This covers that the endpoint is wired to it: the servlet
 * once took the receiver's token, and a receiver that can deprovision has the transmitter sign an
 * account-disabled about any subject, onto a stream it then polls. Driven through the servlet with a fake
 * introspection, so the scope check under test is the one a request meets.
 */
class ScimProvisionerGateTest {

    private static final SubjectId ALICE = SubjectId.email("alice@example.com");
    private static final Map<String, AuthContext> TOKENS = Map.of(
            "receiver", AuthContext.active("receiver-a", Set.of("ssf.manage")),
            "provisioner", AuthContext.active("scim-provisioner", Set.of("ssf.provision")));

    @BeforeEach
    @AfterEach
    void reset() {
        SsfSupport.resetForTests();
    }

    private static void configure(String provisionerScope) {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope(provisionerScope).build());
        SsfSupport.installReceiverAuthenticator(token -> TOKENS.getOrDefault(token, AuthContext.inactive()));
        // a stream of the receiver's own, holding the subject: where a deprovision it raised would land
        SsfSupport.store().createStream(Stream.builder().id("s1").audience("receiver-a").ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.POLL).eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .eventsDelivered(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED).build());
        SsfSupport.store().addSubject("s1", ALICE);
    }

    private static int delete(String token) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("DELETE");
        when(req.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(req.getPathInfo()).thenReturn("/" + ALICE.canonicalKey());
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new ByteArrayOutputStream()));

        new SsfScimSubjectServlet().service(req, resp);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        org.mockito.Mockito.verify(resp).setStatus(status.capture());
        return status.getValue();
    }

    @Test
    void aReceiverTokenIsRefusedAndAProvisionerTokenIsNot() throws Exception {
        configure("ssf.provision");

        assertEquals(403, delete("receiver"));
        assertTrue(SsfSupport.store().hasSubject("s1", ALICE), "refused before anything was done");

        assertEquals(204, delete("provisioner")); // control: same request, the other scope
        assertEquals(false, SsfSupport.store().hasSubject("s1", ALICE));
    }

    @Test
    void withNoProvisionerScopeConfiguredTheEndpointRefusesEveryone() throws Exception {
        configure(null);

        assertEquals(403, delete("provisioner"));
        assertEquals(403, delete("receiver"));
        assertTrue(SsfSupport.store().hasSubject("s1", ALICE));
    }
}
