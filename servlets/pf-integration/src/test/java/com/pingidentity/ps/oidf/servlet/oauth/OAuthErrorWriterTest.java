package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class OAuthErrorWriterTest {

    @AfterEach
    void clean() {
        ThreadContext.clearMap();
    }

    private static String write(int status, String error, String detail) throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));
        OAuthErrorWriter.write(response, status, error, detail);
        verify(response).setStatus(status);
        verify(response).setContentType("application/json");
        verify(response).setHeader("Cache-Control", "no-store");
        verify(response).setHeader("Pragma", "no-cache");
        return body.toString();
    }

    @Test
    @Requirement("RFC6749 §5.2")
    void anErrorIsJsonThatIsNeverCachedAndCarriesOnlyTheCodesFixedDescriptionAndAReference() throws Exception {
        try (RefusalLog log = RefusalLog.open()) {
            String body = write(401, "invalid_client", "renew it by registering again (OpenID Federation 1.0 §12.3), \"now\"");

            Map<String, Object> json = PublicErrorsAssert.assertGeneric("invalid_client", body);
            String description = (String) json.get("error_description");
            assertEquals(OAuthErrorDescriptionFilter.withinSet(description), description, "inside %x20-21 / %x23-5B / %x5D-7E");
            assertFalse(body.contains("renew"), "the detail is never the caller's");
            String reference = description.substring(description.indexOf("(reference ") + 11, description.length() - 1);
            assertTrue(log.last().contains("ref=" + reference) && log.last().contains("renew it by registering again"),
                    "the log line holding the detail carries the same reference: " + log.last());
        }
    }

    @Test
    void theReferenceIsPingFederatesTrackingIdWhenTheThreadHasOne() throws Exception {
        ThreadContext.put("trackingid", "tid:abc_DEF-1");
        Map<String, Object> json = PublicErrorsAssert.assertGeneric("invalid_request", write(400, "invalid_request", "x"));
        assertEquals(PublicErrors.generic("invalid_request") + " (reference tid:abc_DEF-1)", json.get("error_description"));
    }

    @Test
    void aServerErrorIsLoggedAsAWarningAndACodeTheListDoesNotNameGetsTheDefault() throws Exception {
        try (RefusalLog log = RefusalLog.open()) {
            PublicErrorsAssert.assertGeneric("server_error", write(500, "server_error", "boom"));
            assertTrue(log.last().contains("status=500"));
        }
        assertEquals(PublicErrors.DEFAULT, PublicErrors.generic("no_such_code"));
        assertEquals(PublicErrors.DEFAULT, PublicErrors.generic(null));
        assertTrue(PublicErrors.correlationId().startsWith(PublicErrors.GENERATED_PREFIX + "-"));
    }
}
