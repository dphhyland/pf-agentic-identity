/*
 * A federation refusal: generic for a caller that has not authenticated, detailed for an operator, logged either way.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert;
import com.pingidentity.ps.oidf.servlet.oauth.RefusalLog;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class FederationErrorsTest {
    private static final String MARKER = "hfede-marker-" + UUID.randomUUID();

    private record Written(HttpServletResponse response, StringWriter body) {
        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(this.body.toString());
        }
    }

    private static Written response() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));
        return new Written(response, body);
    }

    /**
     * H-FED-4 (F-0046): a classified refusal, a bad request and a fault of ours each carry peer text in their message; the
     * caller reads only the code's fixed description and a reference, and the line with the same reference holds the text.
     */
    @Test
    @Requirement("OIDFED §8.9(1)")
    void aHostileMarkerNeverReachesAnUnauthenticatedCaller() throws Exception {
        for (Exception e : new Exception[] {
                new FederationException(FederationError.INVALID_TRUST_CHAIN, "no route from https://rp.example/" + MARKER),
                new FederationException(FederationError.TEMPORARILY_UNAVAILABLE, "https://" + MARKER + " did not answer"),
                new IllegalArgumentException("sub " + MARKER + " is not an entity identifier"),
                new IllegalStateException("the store said " + MARKER)}) {
            try (RefusalLog log = RefusalLog.open()) {
                Written written = response();
                FederationErrors.write(written.response(), e);

                String body = written.body().toString();
                assertFalse(body.contains(MARKER), body);
                Map<String, Object> json = PublicErrorsAssert.assertGeneric((String) written.json().get("error"), body);
                String description = (String) json.get("error_description");
                String reference = description.substring(description.indexOf("(reference ") + 11, description.length() - 1);
                assertTrue(log.last().contains("ref=" + reference) && log.last().contains(MARKER), log.last());
            }
        }
    }

    @Test
    void anOperatorIsToldTheDetailButNeverAServerFaultsMessage() throws Exception {
        Written refused = response();
        FederationErrors.writeToOperator(refused.response(), 409, "stale_update", "entity " + MARKER + " changed first", null);
        verify(refused.response()).setStatus(409);
        assertEquals("entity " + MARKER + " changed first", refused.json().get("error_description"));

        Written fault = response();
        FederationErrors.writeToOperator(fault.response(), 500, "server_error", "jdbc:postgresql://secret-host/" + MARKER, null);
        assertEquals(FederationErrors.SERVER_ERROR_DESCRIPTION, fault.json().get("error_description"));

        Written unavailable = response();
        FederationErrors.writeToOperator(unavailable.response(), 503, "temporarily_unavailable", "try later", null);
        assertEquals("try later", unavailable.json().get("error_description"));
    }
}
