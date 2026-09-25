package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.pf.testkit.AuditCapture;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;

/**
 * The end-to-end shape of the defect this guards against: an unauthenticated POST with an
 * <em>unsigned</em> entity statement naming an existing client id must be a 400 and must not reach
 * the client store at all — no lookup, no disable, no update.
 */
class OpenIdRegistrationServletTest {

    private static final String OP_ISSUER = "https://as.example.com";
    private static final String EXISTING_CLIENT = "https://rp.example.com";

    private static String unsignedEntityStatement(String sub) throws Exception {
        EllipticCurveJsonWebKey k = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        JwtClaims c = new JwtClaims();
        c.setIssuer(sub);
        c.setSubject(sub);
        c.setAudience(OP_ISSUER);
        c.setClaim("jwks", Map.of("keys", List.of(k.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setAlgorithmHeaderValue("none");
        jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        return jws.getCompactSerialization();
    }

    private static HttpServletRequest post(String contentType, String body) throws IOException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/register");
        when(req.getContentType()).thenReturn(contentType);
        ByteArrayInputStream bytes = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        when(req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener l) {}
        });
        return req;
    }

    private static final class Response {
        final HttpServletResponse mock = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();
        Response() throws IOException { when(mock.getWriter()).thenReturn(new PrintWriter(body)); }
    }

    @Test
    void unsignedStatementForAnExistingClientIsRejectedWithoutTouchingTheStore() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.get(EXISTING_CLIENT)).thenReturn(new Client());
        TrustChainValidator validator = mock(TrustChainValidator.class);
        RegistrationService service = new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP_ISSUER);
        Response resp = new Response();

        servlet.doPost(post("application/entity-statement+jwt", unsignedEntityStatement(EXISTING_CLIENT)), resp.mock);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        verify(resp.mock).setStatus(status.capture());
        assertEquals(400, status.getValue());
        assertTrue(resp.body.toString().contains("invalid_request"), resp.body.toString());
        verifyNoInteractions(store);      // never even looked up - the parser has nothing to act on
        verifyNoInteractions(validator);
    }

    /**
     * OpenID Federation 1.0 §3 through the endpoint: a signed, self-consistent registration statement
     * with no {@code typ} is a 400 before the trust chain is validated or the store consulted. The
     * validator would not catch it later - it is handed the body's {@code trust_chain} header, never
     * the body - so a request that got past the parser would be judged only on statements it carries.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void untypedStatementIsRejectedBeforeTheChainIsValidated() throws Exception {
        ClientStore store = mock(ClientStore.class);
        TrustChainValidator validator = mock(TrustChainValidator.class);
        RegistrationService service = new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP_ISSUER);
        Response resp = new Response();

        servlet.doPost(post("application/entity-statement+jwt", untypedSignedEntityStatement(EXISTING_CLIENT)), resp.mock);

        verify(resp.mock).setStatus(400);
        assertTrue(resp.body.toString().contains("typ"), resp.body.toString());
        verifyNoInteractions(store);
        verifyNoInteractions(validator);
    }

    /** Signed by the key its own jwks names, addressed to this OP, sub == iss - everything but typ. */
    private static String untypedSignedEntityStatement(String sub) throws Exception {
        EllipticCurveJsonWebKey k = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        k.setKeyId("rp-1");
        JwtClaims c = new JwtClaims();
        c.setIssuer(sub);
        c.setSubject(sub);
        c.setAudience(OP_ISSUER);
        c.setIssuedAtToNow();
        c.setExpirationTimeMinutesInTheFuture(10.0f);
        c.setClaim("jwks", Map.of("keys", List.of(k.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(k.getPrivateKey());
        jws.setKeyIdHeaderValue(k.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("trust_chain", List.of("leaf.statement.jwt", "anchor.statement.jwt"));
        return jws.getCompactSerialization();
    }

    @Test
    void unsupportedContentTypeIsA400() throws Exception {
        ClientStore store = mock(ClientStore.class);
        RegistrationService service = new RegistrationService(new RegistrationConfiguration("https://tc.example", false), mock(TrustChainValidator.class), store);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP_ISSUER);
        Response resp = new Response();

        servlet.doPost(post("text/plain", "hello"), resp.mock);

        verify(resp.mock).setStatus(400);
        verifyNoInteractions(store);
    }

    @Test
    void trustChainBodyOverTheLengthCapIsA400() throws Exception {
        ClientStore store = mock(ClientStore.class);
        RegistrationService service = new RegistrationService(new RegistrationConfiguration("https://tc.example", false), mock(TrustChainValidator.class), store);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP_ISSUER);
        Response resp = new Response();
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < ExplicitRegistrationRequest.MAX_TRUST_CHAIN_LENGTH + 1; i++) sb.append(i > 0 ? "," : "").append("\"a.b.c\"");
        sb.append("]");

        servlet.doPost(post("application/trust-chain+json", sb.toString()), resp.mock);

        verify(resp.mock).setStatus(400);
        verify(store, never()).disable(any());
        verify(store, never()).get(anyString());
    }

    /** A trust-chain+json body whose leaf is the RP's configuration, parseable enough to select. */
    private static String trustChainBody() {
        String leaf = com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt")
                .claim("iss", EXISTING_CLIENT).claim("sub", EXISTING_CLIENT)
                .claim("authority_hints", List.of("https://tc.example")).unsigned().sign(null, java.time.Clock.systemUTC());
        return "[\"" + leaf + "\"]";
    }

    @Test
    @Requirement("OIDFED §12.2.3(9)")
    void aRegistrationIsAnswered200WithTheSignedResponse() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        when(service.explicitRegister(any(ExplicitRegistrationRequest.class), org.mockito.ArgumentMatchers.eq(OP_ISSUER)))
                .thenReturn(new RegisteredClient(EXISTING_CLIENT, EXISTING_CLIENT, "https://tc.example", List.of(), Map.of(),
                        "registered", "signed.response.jwt", 1L));
        Response resp = new Response();

        new OpenIdRegistrationServlet(service, req -> OP_ISSUER).doPost(post("application/trust-chain+json", trustChainBody()), resp.mock);

        verify(resp.mock).setStatus(200);
        verify(resp.mock).setContentType("application/explicit-registration-response+jwt");
        assertEquals("signed.response.jwt", resp.body.toString());
    }

    @Test
    @Requirement("OIDFED §12.2.4(1)")
    void aRefusedRegistrationIsAnsweredWithItsStatusAndCode() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        when(service.explicitRegister(any(ExplicitRegistrationRequest.class), anyString()))
                .thenThrow(new RegistrationRejectedException(409, "invalid_client_metadata", "administered outside OpenID Federation"));
        Response resp = new Response();

        new OpenIdRegistrationServlet(service, req -> OP_ISSUER).doPost(post("application/trust-chain+json", trustChainBody()), resp.mock);

        verify(resp.mock).setStatus(409);
        assertTrue(resp.body.toString().contains("\"invalid_client_metadata\""), resp.body.toString());
        assertTrue(resp.body.toString().contains("administered outside"), resp.body.toString());
    }

    @Test
    void whatARefusedRegistrationAuditsCarriesTheCallersAddressAndTheScopeEndsWithTheRequest() throws Exception {
        try (AuditCapture audit = AuditCapture.install()) {
            TrustChainValidator validator = mock(TrustChainValidator.class);
            when(validator.validate(any(ValidationRequest.class))).thenThrow(new TrustChainValidationException(
                    TrustChainValidationException.Kind.SIGNATURE, EXISTING_CLIENT, EXISTING_CLIENT, "the leaf's signature does not verify"));
            RegistrationService service = new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator,
                    mock(ClientStore.class));
            HttpServletRequest req = post("application/trust-chain+json", trustChainBody());
            when(req.getMethod()).thenReturn("POST");
            when(req.getRemoteAddr()).thenReturn("192.0.2.44");
            Response resp = new Response();

            new OpenIdRegistrationServlet(service, r -> OP_ISSUER).service(req, resp.mock);

            assertTrue(resp.body.toString().contains("invalid_trust_chain"), resp.body.toString());
            assertEquals("192.0.2.44", audit.only(FederationEvents.REGISTRATION_REFUSED).remoteAddress());
            assertNull(PfRequestScope.current());
        }
    }

    @Test
    void aPathThisServletDoesNotServeIsNotFound() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/elsewhere");
        Response resp = new Response();

        new OpenIdRegistrationServlet(mock(RegistrationService.class), r -> OP_ISSUER).doPost(req, resp.mock);

        verify(resp.mock).setStatus(404);
    }
}
