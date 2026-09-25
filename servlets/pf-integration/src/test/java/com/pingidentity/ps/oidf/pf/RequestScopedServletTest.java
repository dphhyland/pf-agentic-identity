package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.testkit.AuditCapture;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A servlet's every request is scoped where {@code doGet} and {@code doPost} are dispatched from: what a handler audits
 * carries the caller's address, and the scope is gone when the request is, however the handler ends.
 */
class RequestScopedServletTest {
    private final AuditCapture audit = AuditCapture.install();

    @AfterEach
    void release() {
        this.audit.close();
    }

    /** Audits a refusal on GET; fails on POST as a handler whose client has gone away would. */
    private static final class Probe extends RequestScopedServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
            FederationEvents.event(FederationEvents.REQUEST_REFUSED).failure("invalid_request").audit().emit();
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            throw new IOException("the client went away");
        }
    }

    private static HttpServletRequest request(String method, String address) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getRemoteAddr()).thenReturn(address);
        return request;
    }

    @Test
    void whatAHandlerAuditsCarriesTheCallersAddressAndTheScopeEndsWithTheRequest() throws Exception {
        new Probe().service(request("GET", "203.0.113.5"), mock(HttpServletResponse.class));

        assertEquals("203.0.113.5", this.audit.only(FederationEvents.REQUEST_REFUSED).remoteAddress());
        assertNull(PfRequestScope.current());
    }

    @Test
    void aHandlerThatThrowsStillLeavesNoScopeOnThePooledThread() {
        assertThrows(IOException.class, () -> new Probe().service(request("POST", "203.0.113.5"), mock(HttpServletResponse.class)));

        assertNull(PfRequestScope.current());
    }

    @Test
    void aScopeAlreadyOpenIsBackAfterTheServletsRequest() throws Exception {
        PfRequestScope.Context none = PfRequestScope.enter(request("GET", "198.51.100.4"));
        PfRequestScope.Context open = PfRequestScope.current();

        new Probe().service(request("GET", "203.0.113.5"), mock(HttpServletResponse.class));

        assertEquals("203.0.113.5", this.audit.only(FederationEvents.REQUEST_REFUSED).remoteAddress());
        assertSame(open, PfRequestScope.current());
        PfRequestScope.exit(none);
    }
}
