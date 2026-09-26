package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PingFederate's own discovery documents, as the federation Entity Configuration's {@code openid_provider} and AS metadata
 * start from them: read per issuer, kept five minutes, and never the reason the Entity Configuration can't be served.
 */
class PfProviderMetadataTest {
    private static final String PF = "https://pf.example.com";
    private static final String OP = "{\"issuer\": \"" + PF + "\", \"jwks_uri\": \"" + PF + "/pf/JWKS\", \"subject_types_supported\": [\"public\"]}";

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final List<String> read = new ArrayList<>();

    private PfProviderMetadata reading(Map<String, String> documents) {
        return new PfProviderMetadata((type, request) -> {
            this.read.add(type);
            String document = documents.get(type);
            if (document == null) {
                throw new IllegalStateException("no handler for " + type);
            }
            return document;
        }, this.clock);
    }

    @Test
    @Requirement({"OIDFED §5.1.3(2)", "OIDFED §5.1.4(2)"})
    void theDocumentsAreReadPerIssuerAndKeptFiveMinutes() {
        PfProviderMetadata metadata = this.reading(Map.of("openid_provider", OP, "oauth_authorization_server", "{\"issuer\": \"" + PF + "\"}"));
        HttpServletRequest request = mock(HttpServletRequest.class);

        metadata.refresh(PF, request);
        metadata.refresh(PF, request);

        assertEquals(PF + "/pf/JWKS", metadata.of("openid_provider", PF).get("jwks_uri"));
        assertEquals(Map.of("issuer", PF), metadata.of("oauth_authorization_server", PF));
        assertEquals(List.of("openid_provider", "oauth_authorization_server"), this.read, "read once, then kept");
        assertEquals(Map.of(), metadata.of("openid_provider", "https://other.example.com"), "another issuer's has not been read");

        this.clock.advance(Duration.ofSeconds(PfProviderMetadata.REFRESH_SECONDS));
        metadata.refresh(PF, request);
        assertEquals(4, this.read.size(), "five minutes on, read again");
    }

    @Test
    void aDocumentThatCannotBeReadLeavesTheLastOneOrNothing() {
        java.util.concurrent.atomic.AtomicReference<String> op = new java.util.concurrent.atomic.AtomicReference<>(OP);
        PfProviderMetadata metadata = new PfProviderMetadata((type, request) -> {
            if ("oauth_authorization_server".equals(type)) {
                throw new NoClassDefFoundError("org/sourceid/openid/connect/handlers/ProviderConfigurationInfoHandler");
            }
            String document = op.get();
            if (document == null) {
                throw new java.io.IOException("the template is missing");
            }
            return document;
        }, this.clock);

        metadata.refresh(PF, null);
        assertEquals(Map.of(), metadata.of("oauth_authorization_server", PF), "a PingFederate without the handler: nothing, not a failure");

        op.set(null);
        this.clock.advance(Duration.ofSeconds(PfProviderMetadata.REFRESH_SECONDS));
        metadata.refresh(PF, null);
        assertEquals(List.of("public"), metadata.of("openid_provider", PF).get("subject_types_supported"), "the last good document stands");
    }

    @Test
    void aHandlerWritesIntoAResponseThatGoesNowhereForARequestWithNoParameters() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sub")).thenReturn("https://agent.example.com");
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Host")).thenReturn("pf.example.com");

        String body = PfProviderMetadata.capture((req, resp) -> {
            assertEquals("GET", req.getMethod());
            assertNull(req.getParameter("sub"), "a federation request's parameters mean nothing to discovery");
            assertEquals(Map.of(), req.getParameterMap());
            assertFalse(req.getParameterNames().hasMoreElements());
            assertNull(req.getParameterValues("sub"));
            assertNull(req.getQueryString());
            assertEquals("pf.example.com", req.getHeader("Host"), "everything else is the request's own");
            resp.setContentType("application/json");
            resp.setHeader("Cache-Control", "no-store");
            resp.setStatus(200);
            assertFalse(resp.isCommitted());
            assertFalse(resp.containsHeader("Cache-Control"), "nothing is kept but the body");
            assertEquals(0, resp.getBufferSize());
            assertEquals(200, resp.getStatus());
            assertEquals("UTF-8", resp.getCharacterEncoding());
            assertNull(resp.getHeader("Cache-Control"));
            assertEquals("discovery capture", resp.toString());
            assertTrue(resp.equals(resp));
            assertEquals(System.identityHashCode(resp), resp.hashCode());
            resp.getWriter().write("{\"issuer\":");
            resp.getOutputStream().write(" \"https://pf.example.com\"}".getBytes(StandardCharsets.UTF_8));
            assertTrue(resp.getOutputStream().isReady());
            resp.getOutputStream().setWriteListener(null);
        }, request);

        assertEquals("{\"issuer\": \"https://pf.example.com\"}", body);
    }

    @Test
    void anUnknownMethodAnswersAsAnEmptyResponseWould() {
        assertEquals(false, PfProviderMetadata.emptyAnswer(boolean.class));
        assertEquals(0, PfProviderMetadata.emptyAnswer(int.class));
        assertEquals(0L, PfProviderMetadata.emptyAnswer(long.class));
        assertNull(PfProviderMetadata.emptyAnswer(String.class));
        assertNull(PfProviderMetadata.emptyAnswer(void.class));
        assertTrue(HttpServletResponse.class.isInterface());
    }
}
