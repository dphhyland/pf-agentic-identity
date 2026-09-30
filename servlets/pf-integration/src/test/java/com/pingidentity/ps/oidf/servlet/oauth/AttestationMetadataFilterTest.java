/*
 * PingFederate's discovery documents leave with the attestation members added; anything the filter cannot extend leaves as
 * PingFederate wrote it.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.AttestationMetadataConfig;
import com.pingidentity.ps.oidf.federation.AttestationMetadataConfigs;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.zip.GZIPOutputStream;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AttestationMetadataFilterTest {
    private static final String ISSUER = "https://pf.example.com";
    private static final String OIDC = "/.well-known/openid-configuration";
    private static final String OAS = "/.well-known/oauth-authorization-server";

    /** PingFederate 13.1.3's shape (the rig, 2026-10-01): pretty-printed, its own methods and DPoP list, ping_* members. */
    static final String PF_DOCUMENT = "{\n  \"issuer\": \"" + ISSUER + "\",\n"
            + "  \"token_endpoint\": \"" + ISSUER + "/as/token.oauth2\",\n"
            + "  \"ping_end_session_endpoint\": \"" + ISSUER + "/idp/startSLO.ping\",\n"
            + "  \"token_endpoint_auth_methods_supported\": [\n    \"client_secret_basic\",\n    \"private_key_jwt\",\n"
            + "    \"tls_client_auth\",\n    \"none\"\n  ],\n"
            + "  \"backchannel_logout_supported\": true,\n"
            + "  \"dpop_signing_alg_values_supported\": [\"RS256\", \"RS384\", \"ES256\", \"PS256\"],\n"
            + "  \"client_id_metadata_document_supported\": false\n}";

    @AfterEach
    void forget() {
        AttestationMetadataConfigs.resetCurrent();
    }

    /** The response PingFederate's servlet writes into: status, headers and body recorded, as a container would hold them. */
    static final class Recorded extends HttpServletResponseWrapper {
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        final Map<String, List<String>> headers = new LinkedHashMap<>();
        int status = 200;
        String contentType;
        long contentLength = -1;
        boolean committed;
        int flushes;
        private final ServletOutputStream stream = new ServletOutputStream() {
            @Override
            public void write(int b) {
                Recorded.this.body.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }
        };

        Recorded() {
            super(mock(HttpServletResponse.class));
        }

        @Override
        public void setStatus(int sc) {
            this.status = sc;
        }

        @Override
        public int getStatus() {
            return this.status;
        }

        @Override
        public void setContentType(String type) {
            this.contentType = type;
        }

        @Override
        public String getContentType() {
            return this.contentType;
        }

        @Override
        public void setContentLength(int len) {
            this.contentLength = len;
        }

        @Override
        public void setContentLengthLong(long len) {
            this.contentLength = len;
        }

        @Override
        public void setHeader(String name, String value) {
            this.headers.put(name, new ArrayList<>(List.of(value)));
        }

        @Override
        public void addHeader(String name, String value) {
            this.headers.computeIfAbsent(name, n -> new ArrayList<>()).add(value);
        }

        @Override
        public void setIntHeader(String name, int value) {
            this.setHeader(name, Integer.toString(value));
        }

        @Override
        public void addIntHeader(String name, int value) {
            this.addHeader(name, Integer.toString(value));
        }

        @Override
        public ServletOutputStream getOutputStream() {
            return this.stream;
        }

        @Override
        public boolean isCommitted() {
            return this.committed;
        }

        @Override
        public void flushBuffer() {
            this.flushes++;
        }

        String text() {
            return this.body.toString(StandardCharsets.UTF_8);
        }
    }

    private static HttpServletRequest request(String method, String uri, String contextPath) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getRequestURI()).thenReturn(contextPath + uri);
        when(request.getContextPath()).thenReturn(contextPath);
        return request;
    }

    /** PingFederate's controller: 200, application/json, a length, then the document through the writer or the stream. */
    private static FilterChain pingFederate(int status, String contentType, byte[] body, boolean viaWriter, List<String> methodsSeen) {
        return (req, resp) -> {
            methodsSeen.add(((HttpServletRequest) req).getMethod());
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(status);
            out.setContentType(contentType);
            out.setContentLength(body.length);
            out.setHeader("Cache-Control", "no-cache, no-store");
            if (viaWriter) {
                out.getWriter().write(new String(body, StandardCharsets.UTF_8));
                out.getWriter().flush();
                out.flushBuffer();
            } else {
                out.getOutputStream().write(body);
            }
        };
    }

    private static Recorded run(Supplier<AttestationMetadataConfig> members, HttpServletRequest request, FilterChain chain) throws Exception {
        Recorded out = new Recorded();
        new AttestationMetadataFilter(members).doFilter(request, out, chain);
        return out;
    }

    private static Map<String, Object> json(Recorded out) throws Exception {
        return JsonUtil.parseJson(out.text());
    }

    /**
     * ABCA-10 §6.1 (read 2026-10-01): "If the Authorization Server supports metadata as defined in [RFC8414] ..., it MUST
     * signal support for the challenge endpoint by including the metadata entry challenge_endpoint"; §8's methods and
     * algorithm members with it. PingFederate's own members stay first, in its order, with its values.
     */
    @Test
    @Requirement({"ABCA-10 §6.1", "ABCA-10 §8"})
    void aPingFederateDocumentLeavesWithTheMembersAdded() throws Exception {
        for (String uri : List.of(OIDC, OAS)) {
            for (boolean viaWriter : new boolean[] {true, false}) {
                String document = uri.substring(uri.lastIndexOf('/') + 1);
                long before = AttestationMetadataFilter.counted(document, "extended");
                List<String> seen = new ArrayList<>();
                Recorded out = run(AttestationMetadataConfigs::defaults, request("GET", uri, ""),
                        pingFederate(200, "application/json", PF_DOCUMENT.getBytes(StandardCharsets.UTF_8), viaWriter, seen));
                Map<String, Object> doc = json(out);
                Map<String, Object> pf = JsonUtil.parseJson(PF_DOCUMENT);

                assertEquals(List.of("issuer", "token_endpoint", "ping_end_session_endpoint", "token_endpoint_auth_methods_supported",
                        "backchannel_logout_supported", "dpop_signing_alg_values_supported", "client_id_metadata_document_supported",
                        "client_attestation_signing_alg_values_supported", "client_attestation_pop_signing_alg_values_supported",
                        "client_attestation_pop_methods_supported", "challenge_endpoint"), List.copyOf(doc.keySet()));
                for (String own : pf.keySet()) {
                    if (!"token_endpoint_auth_methods_supported".equals(own)) {
                        assertEquals(pf.get(own), doc.get(own), own);
                    }
                }
                assertEquals(List.of("client_secret_basic", "private_key_jwt", "tls_client_auth", "none", "attest_jwt_client_auth",
                        "attest_jwt_client_auth_dpop"), doc.get("token_endpoint_auth_methods_supported"));
                assertEquals(ISSUER + "/federation/attestation-challenge", doc.get("challenge_endpoint"),
                        "the authorization server's challenge endpoint, never the attester's /federation/attestation/challenge");
                assertEquals(out.body.size(), out.contentLength, "the length is the extended document's");
                assertEquals(List.of("no-cache, no-store"), out.headers.get("Cache-Control"), "PingFederate's headers pass");
                assertEquals(null, out.headers.get("Content-Length"));
                assertEquals(List.of("GET"), seen);
                assertEquals(before + 1, AttestationMetadataFilter.counted(document, "extended"));
            }
        }
    }

    @Test
    void theChallengeEndpointIsUnderTheContextPath() throws Exception {
        String slashIssuer = PF_DOCUMENT.replace("\"issuer\": \"" + ISSUER + "\"", "\"issuer\": \"" + ISSUER + "/\"");
        for (String[] c : new String[][] {{"/ctx", ISSUER + "/ctx"}, {"/", ISSUER}}) {
            Recorded out = run(AttestationMetadataConfigs::defaults, request("GET", OIDC, c[0]),
                    pingFederate(200, "application/json;charset=UTF-8", slashIssuer.getBytes(StandardCharsets.UTF_8), false, new ArrayList<>()));
            assertEquals(c[1] + "/federation/attestation-challenge", json(out).get("challenge_endpoint"));
        }
        assertEquals(AttestationMetadataConfig.CHALLENGE_PATH,
                com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet.PATH,
                "the path the servlet is mapped to");
    }

    /** S9b's rule: with ATTESTATION_AUTH switched off the request is PingFederate's alone - the same objects, nothing held. */
    @Test
    void switchedOffTheRequestPassesUntouched() throws Exception {
        for (Supplier<AttestationMetadataConfig> none : List.<Supplier<AttestationMetadataConfig>>of(AttestationMetadataConfigs::switchedOff,
                AttestationMetadataConfigs::noAttestationMethod)) {
            HttpServletRequest request = request("GET", OAS, "");
            HttpServletResponse response = mock(HttpServletResponse.class);
            List<Object[]> passed = new ArrayList<>();
            long before = AttestationMetadataFilter.counted("oauth-authorization-server", "not_advertised");
            new AttestationMetadataFilter(none).doFilter(request, response, (req, resp) -> passed.add(new Object[] {req, resp}));
            assertSame(request, passed.get(0)[0]);
            assertSame(response, passed.get(0)[1]);
            assertEquals(before + 1, AttestationMetadataFilter.counted("oauth-authorization-server", "not_advertised"));
        }
    }

    @Test
    void aConfigurationThatCannotBeReadSendsTheDocumentAsItCame() throws Exception {
        HttpServletRequest request = request("GET", OIDC, "");
        HttpServletResponse response = mock(HttpServletResponse.class);
        List<ServletResponse> passed = new ArrayList<>();
        new AttestationMetadataFilter(() -> {
            throw new IllegalArgumentException("a refused setting");
        }).doFilter(request, response, (req, resp) -> passed.add(resp));
        assertSame(response, passed.get(0));
        assertTrue(AttestationMetadataFilter.counted("openid-configuration", "no_configuration") > 0);
    }

    /** A document it cannot parse goes out byte for byte, counted - JSON that is not an object, names no issuer, and so on. */
    @Test
    void aDocumentItCannotParseLeavesAsItCame() throws Exception {
        for (String body : List.of("not json at all", "[1, 2]", "{\"token_endpoint\": \"x\"}", "{\"issuer\": \" \"}", "{\"issuer\": 7}",
                "{\"issuer\": \"" + ISSUER + "\", \"token_endpoint_auth_methods_supported\": \"private_key_jwt\"}", "null")) {
            long before = AttestationMetadataFilter.counted("openid-configuration", "unparseable");
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            Recorded out = run(AttestationMetadataConfigs::defaults, request("GET", OIDC, ""),
                    pingFederate(200, "application/json", bytes, true, new ArrayList<>()));
            assertArrayEquals(bytes, out.body.toByteArray(), body);
            assertEquals(bytes.length, out.contentLength);
            assertEquals(before + 1, AttestationMetadataFilter.counted("openid-configuration", "unparseable"), body);
        }
    }

    /** PingFederate 13.1.3 compresses neither document (U-0029; the rig, 2026-10-01); a compressed one passes unread. */
    @Test
    void aCompressedDocumentLeavesAsItCame() throws Exception {
        ByteArrayOutputStream zipped = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(zipped)) {
            gz.write(PF_DOCUMENT.getBytes(StandardCharsets.UTF_8));
        }
        byte[] bytes = zipped.toByteArray();
        for (String encoding : List.of("gzip", "br")) {
            long before = AttestationMetadataFilter.counted("oauth-authorization-server", "encoded");
            Recorded out = run(AttestationMetadataConfigs::defaults, request("GET", OAS, ""), (req, resp) -> {
                HttpServletResponse r = (HttpServletResponse) resp;
                r.setContentType("application/json");
                r.addHeader("Content-Encoding", encoding);
                r.addHeader("Content-Length", Integer.toString(bytes.length));
                r.getOutputStream().write(bytes);
            });
            assertArrayEquals(bytes, out.body.toByteArray());
            assertEquals(List.of(encoding), out.headers.get("Content-Encoding"));
            assertEquals(bytes.length, out.contentLength);
            assertEquals(before + 1, AttestationMetadataFilter.counted("oauth-authorization-server", "encoded"));
        }
        Recorded identity = run(AttestationMetadataConfigs::defaults, request("GET", OAS, ""), (req, resp) -> {
            HttpServletResponse r = (HttpServletResponse) resp;
            r.setContentType("application/json");
            r.setHeader("Content-Encoding", " identity ");
            r.getOutputStream().write(PF_DOCUMENT.getBytes(StandardCharsets.UTF_8));
        });
        assertTrue(json(identity).containsKey("challenge_endpoint"), "identity is no encoding");
        Recorded blank = run(AttestationMetadataConfigs::defaults, request("GET", OAS, ""), (req, resp) -> {
            HttpServletResponse r = (HttpServletResponse) resp;
            r.setContentType("application/json");
            r.setHeader("Content-Encoding", " ");
            r.getOutputStream().write(PF_DOCUMENT.getBytes(StandardCharsets.UTF_8));
        });
        assertTrue(json(blank).containsKey("challenge_endpoint"), "a blank encoding is none");
    }

    @Test
    void anErrorOrAnotherTypeLeavesAsItCame() throws Exception {
        byte[] page = "<html>404</html>".getBytes(StandardCharsets.UTF_8);
        Recorded notFound = run(AttestationMetadataConfigs::defaults, request("GET", OIDC + "x", ""),
                pingFederate(404, "text/html", page, true, new ArrayList<>()));
        assertArrayEquals(page, notFound.body.toByteArray());
        assertEquals(404, notFound.status);
        assertTrue(AttestationMetadataFilter.counted("openid-configuration", "status") > 0);

        byte[] doc = PF_DOCUMENT.getBytes(StandardCharsets.UTF_8);
        for (String type : new String[] {"text/plain", null}) {
            Recorded other = run(AttestationMetadataConfigs::defaults, request("GET", OIDC, ""),
                    pingFederate(200, type, doc, false, new ArrayList<>()));
            assertArrayEquals(doc, other.body.toByteArray());
        }
        assertTrue(AttestationMetadataFilter.counted("openid-configuration", "not_json") > 0);
    }

    /** A body past the limit is not a discovery document: what was held goes out, then the rest, with PingFederate's length. */
    @Test
    void aBodyPastTheLimitStreamsOutAsItCame() throws Exception {
        byte[] big = new byte[AttestationMetadataFilter.LIMIT + 10];
        java.util.Arrays.fill(big, (byte) 'a');
        long before = AttestationMetadataFilter.counted("oauth-authorization-server", "too_large");
        Recorded out = run(AttestationMetadataConfigs::defaults, request("GET", OAS, ""), (req, resp) -> {
            HttpServletResponse r = (HttpServletResponse) resp;
            r.setContentType("application/json");
            r.setContentLength(big.length);
            r.getOutputStream().write(big);
            r.setContentLength(big.length);
            r.setHeader("Content-Length", Integer.toString(big.length));
            r.flushBuffer();
        });
        assertArrayEquals(big, out.body.toByteArray());
        assertEquals(big.length, out.contentLength);
        assertTrue(out.flushes >= 1);
        assertEquals(before + 1, AttestationMetadataFilter.counted("oauth-authorization-server", "too_large"));

        Recorded unknownLength = run(AttestationMetadataConfigs::defaults, request("GET", OAS, ""), (req, resp) -> {
            resp.setContentType("application/json");
            ((HttpServletResponse) resp).setHeader("Content-Length", "unknown");
            resp.getOutputStream().write(big);
        });
        assertArrayEquals(big, unknownLength.body.toByteArray());
        assertEquals(-1, unknownLength.contentLength, "no length PingFederate did not give");
    }

    @Test
    void aResponseCommittedPastTheFilterIsLeftAlone() throws Exception {
        long before = AttestationMetadataFilter.counted("openid-configuration", "committed");
        Recorded out = new Recorded();
        new AttestationMetadataFilter(AttestationMetadataConfigs::defaults).doFilter(request("GET", OIDC, ""), out, (req, resp) -> {
            resp.getOutputStream().write('x');
            out.committed = true;
        });
        assertEquals(0, out.body.size());
        assertEquals(before + 1, AttestationMetadataFilter.counted("openid-configuration", "committed"));
    }

    /** A HEAD is rendered as the GET it describes: the extended document's length, and no body. */
    @Test
    void aHeadAnswersWithTheExtendedLengthAndNoBody() throws Exception {
        List<String> seen = new ArrayList<>();
        Recorded get = run(AttestationMetadataConfigs::defaults, request("GET", OIDC, ""),
                pingFederate(200, "application/json", PF_DOCUMENT.getBytes(StandardCharsets.UTF_8), true, seen));
        Recorded head = run(AttestationMetadataConfigs::defaults, request("HEAD", OIDC, ""),
                pingFederate(200, "application/json", PF_DOCUMENT.getBytes(StandardCharsets.UTF_8), true, seen));
        assertEquals(List.of("GET", "GET"), seen, "PingFederate renders the document for the HEAD");
        assertEquals(get.body.size(), head.contentLength);
        assertEquals(0, head.body.size());
    }

    @Test
    void anotherMethodOrANonHttpRequestPassesUntouched() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        List<ServletResponse> passed = new ArrayList<>();
        new AttestationMetadataFilter(AttestationMetadataConfigs::defaults).doFilter(request("POST", OIDC, ""), response,
                (req, resp) -> passed.add(resp));
        ServletRequest plain = mock(ServletRequest.class);
        new AttestationMetadataFilter(AttestationMetadataConfigs::defaults).doFilter(plain, response, (req, resp) -> passed.add(resp));
        ServletResponse plainResponse = mock(ServletResponse.class);
        new AttestationMetadataFilter(AttestationMetadataConfigs::defaults).doFilter(request("GET", OIDC, ""), plainResponse,
                (req, resp) -> passed.add(resp));
        assertEquals(List.of(response, response, plainResponse), passed);
    }

    @Test
    void theHeldResponseIsNotWrittenAsynchronously() {
        AttestationMetadataFilter.Held held = new AttestationMetadataFilter.Held(new Recorded());
        assertTrue(held.getOutputStream().isReady());
        assertThrows(IllegalStateException.class, () -> held.getOutputStream().setWriteListener(mock(WriteListener.class)));
        held.setIntHeader("Content-Length", 12);
        held.addIntHeader("Content-Length", 12);
        held.addIntHeader("X-Count", 3);
        held.setIntHeader("X-Other", 4);
        held.addHeader("X-Added", "a");
        assertNull(held.encoding());
        assertFalse(held.encoded());
    }

    @Test
    void theDefaultConstructorReadsTheFederationServletsSet() throws Exception {
        Recorded out = new Recorded();
        new AttestationMetadataFilter().doFilter(request("GET", OAS, ""), out,
                pingFederate(200, "application/json", PF_DOCUMENT.getBytes(StandardCharsets.UTF_8), false, new ArrayList<>()));
        assertEquals(AttestationMetadataConfig.current().advertised(), json(out).containsKey("challenge_endpoint"));
        new AttestationMetadataFilter().init(null);
        new AttestationMetadataFilter().destroy();
    }

    @Test
    void theDocumentIsNamedByItsPath() {
        assertEquals("openid-configuration", AttestationMetadataFilter.document(request("GET", OIDC + ";x", "")));
        assertEquals("oauth-authorization-server", AttestationMetadataFilter.document(request("GET", OAS, "")));
        assertEquals("other", AttestationMetadataFilter.document(request("GET", "/elsewhere", "")));
        HttpServletRequest noUri = mock(HttpServletRequest.class);
        assertEquals("other", AttestationMetadataFilter.document(noUri));
    }

    @Test
    void jsonIsTheApplicationJsonType() {
        assertTrue(AttestationMetadataFilter.isJson("application/json"));
        assertTrue(AttestationMetadataFilter.isJson(" Application/JSON; charset=UTF-8"));
        assertFalse(AttestationMetadataFilter.isJson("text/json"));
        assertFalse(AttestationMetadataFilter.isJson(null));
    }

    @Test
    void extendedIsNullForWhatItCannotExtend() {
        assertNull(AttestationMetadataFilter.extended("{".getBytes(StandardCharsets.UTF_8), AttestationMetadataConfigs.defaults(), ""));
        assertNull(AttestationMetadataFilter.extended("{\"issuer\":\"x\",\"token_endpoint_auth_methods_supported\":{}}"
                .getBytes(StandardCharsets.UTF_8), AttestationMetadataConfigs.defaults(), null));
    }

    /** An IOException from PingFederate's servlet propagates: nothing is sent in its place. */
    @Test
    void anExceptionFromPingFederatePropagates() {
        assertThrows(IOException.class, () -> run(AttestationMetadataConfigs::defaults, request("GET", OIDC, ""), (req, resp) -> {
            throw new IOException("broken pipe");
        }));
    }
}
