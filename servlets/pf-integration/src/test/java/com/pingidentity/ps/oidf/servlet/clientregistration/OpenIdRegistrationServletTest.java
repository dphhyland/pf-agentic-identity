package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.pf.ClientStore;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
}
