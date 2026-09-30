/*
 * The token endpoint's response belt: what PingFederate issued to an attested client leaves only when it is within the
 * attestation's ceiling.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.IssuedDetailsCriterion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IssuedDetailsBeltTest {
    private static final String CEILING = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"AMER\"],\"max_txn_eur\":500}]";
    private static final String WITHIN = "{\"access_token\":\"at\",\"refresh_token\":\"rt-1\",\"token_type\":\"Bearer\","
            + "\"authorization_details\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":100}]}";
    private static final String OVER = "{\"access_token\":\"at\",\"refresh_token\":\"rt-1\",\"token_type\":\"Bearer\","
            + "\"authorization_details\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"],\"max_txn_eur\":100}]}";

    private final List<Event> events = new ArrayList<>();
    private final List<String> revoked = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(e -> {
            if (IssuedDetailsCriterion.ISSUED_REFUSED.equals(e.code())) {
                this.events.add(e);
            }
        });
    }

    @AfterEach
    void release() {
        Events.reset();
    }

    /** An attestation as the belt reads it: only its payload, which the filter has already verified. */
    static String attestation(String details) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String claims = "{\"iss\":\"https://attester.example\",\"sub\":\"client-1\""
                + (details == null ? "" : ",\"authorization_details\":" + details) + "}";
        return b64.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(claims.getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    /** A request that carries an attestation, verified (the filter's published context) when {@code verified}. */
    static HttpServletRequest request(String attestation, boolean verified) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<String, Object> attributes = new HashMap<>();
        when(request.getHeader("OAuth-Client-Attestation")).thenReturn(attestation);
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get((String) i.getArgument(0)));
        doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1))).when(request).setAttribute(anyString(), org.mockito.ArgumentMatchers.any());
        if (verified) {
            attributes.put(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, Map.of("client_id", "client-1"));
        }
        return request;
    }

    /** The real response: status, headers, content type and length recorded, the body into {@code sink}. */
    static final class Real {
        final ByteArrayOutputStream sink = new ByteArrayOutputStream();
        final Map<String, String> headers = new LinkedHashMap<>();
        int status = 200;
        String contentType;
        Long contentLength;
        boolean flushed;
        final HttpServletResponse response = mock(HttpServletResponse.class);

        Real() throws Exception {
            ServletOutputStream stream = new ServletOutputStream() {
                @Override
                public void write(int b) {
                    Real.this.sink.write(b);
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(WriteListener l) {
                }
            };
            when(this.response.getOutputStream()).thenReturn(stream);
            java.io.PrintWriter writer = new java.io.PrintWriter(new java.io.OutputStreamWriter(stream, StandardCharsets.UTF_8), true);
            when(this.response.getWriter()).thenReturn(writer);
            when(this.response.getStatus()).thenAnswer(i -> this.status);
            when(this.response.getContentType()).thenAnswer(i -> this.contentType);
            doAnswer(i -> this.status = i.getArgument(0)).when(this.response).setStatus(anyInt());
            doAnswer(i -> this.contentType = i.getArgument(0)).when(this.response).setContentType(anyString());
            doAnswer(i -> this.contentLength = (long) (int) i.getArgument(0)).when(this.response).setContentLength(anyInt());
            doAnswer(i -> this.contentLength = i.getArgument(0)).when(this.response).setContentLengthLong(anyLong());
            doAnswer(i -> this.headers.put(i.getArgument(0), i.getArgument(1))).when(this.response).setHeader(anyString(), anyString());
            doAnswer(i -> this.headers.put(i.getArgument(0), i.getArgument(1))).when(this.response).addHeader(anyString(), anyString());
            doAnswer(i -> this.headers.put(i.getArgument(0), String.valueOf((int) i.getArgument(1)))).when(this.response)
                    .setIntHeader(anyString(), anyInt());
            doAnswer(i -> this.flushed = true).when(this.response).flushBuffer();
        }

        String body() {
            return this.sink.toString(StandardCharsets.UTF_8);
        }
    }

    /** PingFederate writing a response: status, content type, a content length, the body through the stream or the writer. */
    static FilterChain writes(int status, String contentType, byte[] body, boolean viaWriter) {
        return (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(status);
            out.setContentType(contentType);
            out.setContentLength(body.length);
            if (viaWriter) {
                out.getWriter().write(new String(body, StandardCharsets.UTF_8));
                out.getWriter().flush();
            } else {
                out.getOutputStream().write(body);
            }
            out.flushBuffer();
        };
    }

    /** A belt started as the container starts it: its part registered, the models loaded. */
    private IssuedDetailsBelt belt() {
        IssuedDetailsBelt belt = new IssuedDetailsBelt(RarModels::builtIn, token -> this.revoked.add(token));
        belt.init(null);
        return belt;
    }

    private IssuedDetailsBelt started() {
        return this.belt();
    }

    private Real through(IssuedDetailsBelt belt, HttpServletRequest request, FilterChain chain) throws Exception {
        Real real = new Real();
        belt.doFilter(request, real.response, chain);
        return real;
    }

    @Test
    @Requirement({"RFC9396 §7", "CAS §7.1"})
    void aTokenResponseWithinTheCeilingLeavesByteForByte() throws Exception {
        for (boolean viaWriter : new boolean[]{false, true}) {
            byte[] body = WITHIN.getBytes(StandardCharsets.UTF_8);
            Real real = this.through(this.started(), request(attestation(CEILING), true),
                    writes(200, "application/json;charset=utf-8", body, viaWriter));
            assertArrayEquals(body, real.sink.toByteArray());
            assertEquals(200, real.status);
            assertEquals(body.length, real.contentLength);
        }
        assertEquals(List.of(), this.events);
        assertEquals(List.of(), this.revoked);
    }

    /**
     * RFC 9396 §6: "Otherwise, the AS refuses the request with the error code invalid_authorization_details (similar to
     * invalid_scope)." The refused grant is revoked, and the event names the enforcer and the type, never a value.
     */
    @Test
    @Requirement({"RFC9396 §6", "RFC9396 §7", "CAS §7.1"})
    void aTokenResponseOverTheCeilingIsReplacedWith400AndItsGrantRevoked() throws Exception {
        Real real = this.through(this.belt(), request(attestation(CEILING), true),
                writes(200, "application/json", OVER.getBytes(StandardCharsets.UTF_8), false));
        assertEquals(400, real.status);
        Map<String, Object> error = JsonUtil.parseJson(real.body());
        assertEquals("invalid_authorization_details", error.get("error"));
        assertEquals(IssuedDetailsBelt.EXCEEDS_DESCRIPTION, error.get("error_description"));
        assertEquals("no-store", real.headers.get("Cache-Control"));
        assertEquals((long) real.sink.size(), real.contentLength);
        assertTrue(!real.body().contains("rt-1") && !real.body().contains("APAC"), "no token and no value leaves");
        assertEquals(List.of("rt-1"), this.revoked);
        Event event = this.events.get(0);
        assertEquals(IssuedDetailsCriterion.ISSUED_REFUSED, event.code());
        assertEquals("exceeds_ceiling", event.reason());
        assertEquals("client-1", event.subject());
        assertEquals(Map.of("enforcer", "response_belt", "detail_types", "sales_agent"), event.fields());
        assertEquals("attestation", event.component());
    }

    /** An attestation with no authorization_details is an empty ceiling, as at the token gate: nothing issued is within it. */
    @Test
    @Requirement("CAS §7.1")
    void anAttestationWithoutDetailsHoldsEveryIssuedDetailOut() throws Exception {
        Real real = this.through(this.belt(), request(attestation(null), true),
                writes(200, "application/json", WITHIN.getBytes(StandardCharsets.UTF_8), false));
        assertEquals(400, real.status);
    }

    @Test
    void aSuccessLargerThanTheBeltHoldsIsReplacedWith500() throws Exception {
        StringBuilder big = new StringBuilder("{\"access_token\":\"");
        while (big.length() <= IssuedDetailsBelt.LIMIT) {
            big.append("x");
        }
        byte[] body = big.append("\"}").toString().getBytes(StandardCharsets.UTF_8);
        Real real = this.through(this.belt(), request(attestation(CEILING), true), writes(200, "application/json", body, false));
        assertEquals(500, real.status);
        assertEquals("server_error", JsonUtil.parseJson(real.body()).get("error"));
        assertEquals("too_large", this.events.get(0).reason());
    }

    /** A body exactly at the limit is held and checked. */
    @Test
    void aSuccessOfExactlyTheLimitIsChecked() throws Exception {
        StringBuilder padded = new StringBuilder(OVER.substring(0, OVER.length() - 1)).append(",\"pad\":\"");
        while (padded.length() < IssuedDetailsBelt.LIMIT - 2) {
            padded.append("p");
        }
        byte[] body = padded.append("\"}").toString().getBytes(StandardCharsets.UTF_8);
        assertEquals(IssuedDetailsBelt.LIMIT, body.length);
        Real real = this.through(this.belt(), request(attestation(CEILING), true), writes(200, "application/json", body, false));
        assertEquals(400, real.status);
    }

    /** PingFederate 13.1.3 compresses no token response (U-0029); a body that says it is encoded goes out as it came. */
    @Test
    void anEncodedBodyGoesOutAsItCame() throws Exception {
        byte[] body = OVER.getBytes(StandardCharsets.UTF_8);
        Real real = this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(200);
            out.setContentType("application/json");
            out.setHeader("Content-Encoding", "gzip");
            out.getOutputStream().write(body);
        });
        assertArrayEquals(body, real.sink.toByteArray());
        assertEquals("gzip", real.headers.get("Content-Encoding"));
        assertEquals(List.of(), this.events);
    }

    @Test
    void anIdentityEncodingIsNoEncoding() throws Exception {
        Real real = this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(200);
            out.setContentType("application/json");
            out.addHeader("Content-Encoding", " identity ");
            out.getOutputStream().write(OVER.getBytes(StandardCharsets.UTF_8));
        });
        assertEquals(400, real.status);
    }

    /** A request without an attestation is not the belt's: the chain gets the same objects, and nothing is buffered. */
    @Test
    void aRequestWithoutAnAttestationPassesUntouchedAndUnbuffered() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Real real = new Real();
        List<Object> seen = new ArrayList<>();
        this.started().doFilter(request, real.response, (req, resp) -> {
            seen.add(req);
            seen.add(resp);
            ((HttpServletResponse) resp).getOutputStream().write(OVER.getBytes(StandardCharsets.UTF_8));
        });
        assertSame(request, seen.get(0));
        assertSame(real.response, seen.get(1));
        assertEquals(OVER, real.body());
        assertEquals(List.of(), this.events);
    }

    /**
     * An attestation the filter did not verify - refused, or passed through with no bridge key - writes straight through:
     * the body reaches the real response while PingFederate is still writing it.
     */
    @Test
    void anUnverifiedAttestationWritesStraightThrough() throws Exception {
        Real real = new Real();
        List<Integer> sizeWhileWriting = new ArrayList<>();
        this.belt().doFilter(request(attestation(CEILING), false), real.response, (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(200);
            out.setContentType("application/json");
            out.setContentLength(OVER.length());
            out.getWriter().write(OVER);
            out.getWriter().flush();
            out.flushBuffer();
            sizeWhileWriting.add(real.sink.size());
        });
        assertEquals(List.of(OVER.length()), sizeWhileWriting);
        assertEquals((long) OVER.length(), real.contentLength);
        assertTrue(real.flushed);
        assertEquals(OVER, real.body());
    }

    /** The verification is published inside the chain, after the belt wrapped the response: it is read at the first write. */
    @Test
    void theVerificationPublishedInsideTheChainIsWhatDecides() throws Exception {
        HttpServletRequest request = request(attestation(CEILING), false);
        Real real = this.through(this.belt(), request, (req, resp) -> {
            req.setAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, Map.of("client_id", "client-1"));
            writes(200, "application/json", OVER.getBytes(StandardCharsets.UTF_8), false).doFilter(req, resp);
        });
        assertEquals(400, real.status);
    }

    @Test
    void anErrorResponseGoesOutAsItCame() throws Exception {
        String error = "{\"error\":\"invalid_grant\",\"authorization_details\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"]}]}";
        Real real = this.through(this.belt(), request(attestation(CEILING), true),
                writes(400, "application/json", error.getBytes(StandardCharsets.UTF_8), true));
        assertEquals(400, real.status);
        assertEquals(error, real.body());
        assertEquals(List.of(), this.events);
    }

    /** An error too large to hold is not the belt's: what was held goes out, and the rest streams after it. */
    @Test
    void aLargeErrorStreamsOutWhole() throws Exception {
        byte[] body = new byte[IssuedDetailsBelt.LIMIT + 10];
        java.util.Arrays.fill(body, (byte) 'e');
        Real real = this.through(this.belt(), request(attestation(CEILING), true), writes(503, "text/html", body, false));
        assertArrayEquals(body, real.sink.toByteArray());
        assertEquals((long) body.length, real.contentLength);
        assertEquals(503, real.status);
    }

    @Test
    void aSuccessThatIsNotJsonOrCarriesNoDetailsGoesOutAsItCame() throws Exception {
        for (String[] response : new String[][]{{"text/plain", OVER}, {null, OVER}, {"application/json", "not json"},
                {"application/json", "[1,2]"}, {"application/json", "{\"access_token\":\"at\"}"},
                {"application/json", "{\"access_token\":\"at\",\"authorization_details\":[]}"}}) {
            Real real = this.through(this.belt(), request(attestation(CEILING), true),
                    writes(200, response[0], response[1].getBytes(StandardCharsets.UTF_8), false));
            assertEquals(response[1], real.body());
            assertEquals(200, real.status);
        }
        assertEquals(List.of(), this.events);
    }

    /** Details the model cannot read are refused, not passed: the question cannot be answered. */
    @Test
    void detailsThatAreNotAListOfObjectsAreRefused() throws Exception {
        for (String details : new String[]{"\"sales_agent\"", "[\"sales_agent\"]", "[{\"sales_regions\":[\"EMEA\"]}]"}) {
            this.events.clear();
            Real real = this.through(this.belt(), request(attestation(CEILING), true), writes(200, "application/json",
                    ("{\"access_token\":\"at\",\"authorization_details\":" + details + "}").getBytes(StandardCharsets.UTF_8), false));
            assertEquals(400, real.status, details);
            assertEquals("uncheckable", this.events.get(0).reason());
        }
    }

    @Test
    void aRevocationThatFailsOrFindsNothingStillRefuses() throws Exception {
        for (IssuedDetailsBelt.GrantRevoker revoker : List.<IssuedDetailsBelt.GrantRevoker>of(t -> false, t -> {
            throw new IllegalStateException("no grant manager");
        }, t -> {
            throw new NoClassDefFoundError("com/pingidentity/access/AccessGrantManagerAccessor");
        })) {
            IssuedDetailsBelt belt = new IssuedDetailsBelt(RarModels::builtIn, revoker);
            belt.init(null);
            Real real = this.through(belt, request(attestation(CEILING), true),
                    writes(200, "application/json", OVER.getBytes(StandardCharsets.UTF_8), false));
            assertEquals(400, real.status);
        }
    }

    @Test
    void aResponseWithoutARefreshTokenRevokesNothing() throws Exception {
        String over = OVER.replace("\"refresh_token\":\"rt-1\",", "");
        Real real = this.through(this.belt(), request(attestation(CEILING), true),
                writes(200, "application/json", over.getBytes(StandardCharsets.UTF_8), false));
        assertEquals(400, real.status);
        assertEquals(List.of(), this.revoked);
    }

    @Test
    void noModelsOrNoAttestationToReadIsUncheckable() throws Exception {
        Real noModels = this.through(new IssuedDetailsBelt(() -> null, t -> true), request(attestation(CEILING), true),
                writes(200, "application/json", WITHIN.getBytes(StandardCharsets.UTF_8), false));
        assertEquals(400, noModels.status);
        HttpServletRequest noHeader = request(attestation(CEILING), true);
        when(noHeader.getHeader("OAuth-Client-Attestation")).thenReturn(null);
        when(noHeader.getHeader("OAuth-Client-Attestation-PoP")).thenReturn("pop");
        Real real = this.through(this.belt(), noHeader, writes(200, "application/json", WITHIN.getBytes(StandardCharsets.UTF_8), false));
        assertEquals(400, real.status);
    }

    /** A content length set as a header is held with the body, and recomputed once the body is final. */
    @Test
    void aContentLengthHeaderIsHeldWithTheBody() throws Exception {
        byte[] body = WITHIN.getBytes(StandardCharsets.UTF_8);
        Real real = this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.setStatus(200);
            out.setContentType("application/json");
            out.setHeader("Content-Length", "999");
            out.setIntHeader("Content-Length", 998);
            out.addHeader("Content-Length", "not a number");
            out.setHeader("X-Other", "kept");
            out.getOutputStream().write(body);
        });
        assertEquals((long) body.length, real.contentLength);
        assertEquals(null, real.headers.get("Content-Length"));
        assertEquals("kept", real.headers.get("X-Other"));
        assertArrayEquals(body, real.sink.toByteArray());
    }

    /** A response PingFederate sends no body for keeps the length it set. */
    @Test
    void aResponseWithNoBodyKeepsItsLength() throws Exception {
        Real real = this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            ((HttpServletResponse) resp).setStatus(204);
            resp.setContentLength(0);
        });
        assertEquals(0L, real.contentLength);
        assertEquals(0, real.sink.size());
    }

    @Test
    void aPassedResponseTakesItsHeadersAndLengthDirectly() throws Exception {
        Real real = this.through(this.belt(), request(attestation(CEILING), false), (req, resp) -> {
            HttpServletResponse out = (HttpServletResponse) resp;
            out.getOutputStream();
            out.setContentLengthLong(5);
            out.setHeader("Content-Length", "6");
        });
        assertEquals("6", real.headers.get("Content-Length"));
        assertEquals(5L, real.contentLength);
    }

    /** PingFederate answering past the wrapper - sendError goes to the real response - leaves nothing for the belt to send. */
    @Test
    void aResponseCommittedPastTheBeltIsLeftAlone() throws Exception {
        Real real = new Real();
        when(real.response.isCommitted()).thenReturn(true);
        this.belt().doFilter(request(attestation(CEILING), true), real.response, (req, resp) -> {
            resp.getOutputStream().write('x');
            ((HttpServletResponse) resp).sendError(500);
        });
        assertEquals(0, real.sink.size());
        assertEquals(List.of(), this.events);
    }

    @Test
    void theHeldStreamIsNotAsynchronous() throws Exception {
        this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            ServletOutputStream stream = resp.getOutputStream();
            assertTrue(stream.isReady());
            assertSame(stream, resp.getOutputStream());
            assertThrows(IllegalStateException.class, () -> stream.setWriteListener(mock(WriteListener.class)));
        });
    }

    @Test
    void theTypesTheEventNamesAreCleanAndFew() {
        List<Map<String, Object>> details = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            details.add(Map.of("type", "t" + i));
        }
        assertEquals("t0,t1,t2,t3,t4,t5,t6,t7", IssuedDetailsCriterion.types(details));
        assertEquals("a?b?c,d", IssuedDetailsCriterion.types(List.of(Map.of("type", "a\nb,c"), Map.of("type", 7), Map.of("type", "d"))));
        assertEquals(64, IssuedDetailsCriterion.types(List.of(Map.of("type", "x".repeat(100)))).length());
    }

    @Test
    void theClientIsTheVerifiedOne() {
        assertEquals("client-1", IssuedDetailsBelt.clientOf(request(attestation(CEILING), true)));
        assertNull(IssuedDetailsBelt.clientOf(request(attestation(CEILING), false)));
        HttpServletRequest odd = request(attestation(CEILING), false);
        odd.setAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, Collections.singletonMap("client_id", 7));
        assertNull(IssuedDetailsBelt.clientOf(odd));
    }

    @Test
    void theIssuedDetailsAreReadFromTheResponse() {
        assertNull(IssuedDetailsBelt.issuedIn("{".getBytes(StandardCharsets.UTF_8)));
        assertNull(IssuedDetailsBelt.issuedIn("\"x\"".getBytes(StandardCharsets.UTF_8)));
        assertEquals(1, IssuedDetailsBelt.issuedIn(WITHIN.getBytes(StandardCharsets.UTF_8)).size());
        assertEquals(List.of(Map.of("_unreadable", Boolean.TRUE)),
                IssuedDetailsBelt.issuedIn("{\"authorization_details\":{}}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aBodyThatIsNotJsonRevokesNothing() {
        this.belt().revokeGrantOf("{".getBytes(StandardCharsets.UTF_8), "client-1");
        this.belt().revokeGrantOf("{\"refresh_token\":7}".getBytes(StandardCharsets.UTF_8), "client-1");
        assertEquals(List.of(), this.revoked);
    }

    /** Outside a booted PingFederate the SDK accessor has no grant manager; the belt logs that and refuses anyway. */
    @Test
    void pingFederatesRevocationNeedsABootedServer() {
        assertThrows(Throwable.class, () -> IssuedDetailsBelt.revokeInPingFederate("rt-1"));
    }

    @Test
    void theNonHttpRequestIsPassedOn() throws Exception {
        jakarta.servlet.ServletRequest request = mock(jakarta.servlet.ServletRequest.class);
        jakarta.servlet.ServletResponse response = mock(jakarta.servlet.ServletResponse.class);
        List<Object> seen = new ArrayList<>();
        this.belt().doFilter(request, response, (req, resp) -> seen.add(resp));
        assertSame(response, seen.get(0));
        this.belt().destroy();
    }

    /** A belt whose models cannot load has failed: attestation traffic is 503, and the belt holds nothing. */
    @Test
    void aBeltThatFailedToStartAnswersAttestationTraffic503() throws Exception {
        IssuedDetailsBelt belt = new IssuedDetailsBelt(() -> {
            throw new IllegalStateException("the RAR containment models could not be loaded");
        }, t -> true);
        belt.init(null);
        List<Object> seen = new ArrayList<>();
        Real real = this.through(belt, request(attestation(CEILING), true), (req, resp) -> seen.add(resp));
        assertEquals(503, real.status);
        assertEquals(List.of(), seen);
    }

    @Test
    void anHttpRequestWithAnotherResponseIsPassedOn() throws Exception {
        jakarta.servlet.ServletResponse response = mock(jakarta.servlet.ServletResponse.class);
        List<Object> seen = new ArrayList<>();
        this.belt().doFilter(request(attestation(CEILING), true), response, (req, resp) -> seen.add(resp));
        assertSame(response, seen.get(0));
    }

    @Test
    void onlyA2xxIsASuccess() {
        assertTrue(IssuedDetailsBelt.success(200) && IssuedDetailsBelt.success(299));
        assertTrue(!IssuedDetailsBelt.success(199) && !IssuedDetailsBelt.success(300) && !IssuedDetailsBelt.success(101));
    }

    @Test
    void aBodyThatIsNotAnObjectRevokesNothing() {
        this.belt().revokeGrantOf("[\"rt-1\"]".getBytes(StandardCharsets.UTF_8), "client-1");
        assertEquals(List.of(), this.revoked);
    }

    /** A response PingFederate writes nothing to, and gives no length, is left as it was. */
    @Test
    void aResponseWithNoBodyAndNoLengthIsLeftAlone() throws Exception {
        Real real = this.through(this.belt(), request(attestation(CEILING), true),
                (req, resp) -> ((HttpServletResponse) resp).setStatus(204));
        assertEquals(204, real.status);
        assertNull(real.contentLength);
        assertEquals(0, real.sink.size());
    }

    @Test
    void aLargeErrorWithNoLengthStreamsOutWhole() throws Exception {
        byte[] body = new byte[IssuedDetailsBelt.LIMIT + 10];
        java.util.Arrays.fill(body, (byte) 'e');
        Real real = this.through(this.belt(), request(attestation(CEILING), true), (req, resp) -> {
            ((HttpServletResponse) resp).setStatus(502);
            resp.getOutputStream().write(body);
        });
        assertArrayEquals(body, real.sink.toByteArray());
        assertNull(real.contentLength);
        assertEquals(502, real.status);
    }

    @Test
    void jsonIsJson() {
        assertTrue(IssuedDetailsBelt.isJson("Application/JSON; charset=UTF-8"));
        assertTrue(!IssuedDetailsBelt.isJson(null) && !IssuedDetailsBelt.isJson("text/json"));
    }
}
