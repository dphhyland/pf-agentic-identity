package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert;
import com.pingidentity.ps.oidf.servlet.oauth.RefusalLog;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicLong;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

/**
 * POST /federation/register reads at most {@code OIDF_REGISTRATION_MAX_BODY_BYTES} of a body (plan item S5c): a body
 * declared larger is refused before any of it is read, and one found larger at the cap is refused with nothing more
 * read - 413, and the registration service never asked.
 */
class OpenIdRegistrationBodyCapTest {
    private static final String OP = "https://op.example.com";

    /** A body of {@code size} bytes of 'a' that counts what is read from it. */
    private static final class CountingBody extends ServletInputStream {
        private final long size;
        private final AtomicLong read = new AtomicLong();

        CountingBody(long size) {
            this.size = size;
        }

        @Override
        public int read() {
            if (this.read.get() >= this.size) {
                return -1;
            }
            this.read.incrementAndGet();
            return 'a';
        }

        @Override public boolean isFinished() { return this.read.get() >= this.size; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(ReadListener l) { }
    }

    private static HttpServletRequest post(CountingBody body, long declared) throws IOException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/register");
        when(req.getContentType()).thenReturn("application/trust-chain+json");
        when(req.getContentLengthLong()).thenReturn(declared);
        when(req.getInputStream()).thenReturn(body);
        return req;
    }

    private static String refuse(OpenIdRegistrationServlet servlet, HttpServletRequest req, int status) throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter written = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(written));
        servlet.doPost(req, resp);
        verify(resp).setStatus(status);
        verify(resp, never()).setHeader("Retry-After", "2");
        return written.toString();
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aBodyDeclaredLargerThanTheCapIsRefusedWithoutReadingAnyOfIt() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        CountingBody body = new CountingBody(8_193);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP, 8_192);

        try (RefusalLog log = RefusalLog.open()) {
            String written = refuse(servlet, post(body, 8_193), 413);

            assertEquals(0, body.read.get());
            PublicErrorsAssert.assertGeneric("invalid_request", written);
            log.assertDetail("8192");
        }
        verifyNoInteractions(service);
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aBodyFoundLargerAtTheCapIsRefusedWithNothingMoreRead() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        CountingBody body = new CountingBody(1_000_000);
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP, 8_192);

        // Chunked: no length declared, so the cap is found by reading to it.
        refuse(servlet, post(body, -1L), 413);

        assertEquals(8_193, body.read.get(), "the cap and one byte more, to know it is past the cap - no more");
        verifyNoInteractions(service);
    }

    @Test
    void aBodyAtTheCapIsReadWhole() throws Exception {
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(mock(RegistrationService.class), req -> OP, 8);
        CountingBody body = new CountingBody(8);

        assertEquals("aaaaaaaa", servlet.readRequestBody(post(body, 8)));
    }

    @Test
    void aLengthThatUnderstatedTheBodyStillStopsAtTheCap() throws Exception {
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(mock(RegistrationService.class), req -> OP, 8);
        CountingBody body = new CountingBody(100);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> servlet.readRequestBody(post(body, 4)));

        assertEquals(413, e.status());
        assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind());
        assertEquals(9, body.read.get());
    }

    @Test
    void theCapIsReadFromTheRegistrationCatalogueWhenNotGiven() throws Exception {
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(mock(RegistrationService.class), req -> OP);
        CountingBody body = new CountingBody(65_537);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> servlet.readRequestBody(post(body, -1L)));

        assertTrue(e.getMessage().contains("65536") && e.getMessage().contains(OpenIdRegistrationServlet.MAX_BODY_BYTES_SETTING), e.getMessage());
        assertEquals(65_537, body.read.get());
    }

    @Test
    void aBusyRegistrationIsAnswered503WithAShortRetryAfter() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        when(service.explicitRegister(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(RegistrationRejectedException.busy("too many federation registrations are being resolved; try again shortly"));
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(service, req -> OP, 65_536);
        String chain = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
                RegistrationFixtures.chain("https://rp.example.com", RegistrationFixtures.ANCHOR, java.time.Clock.systemUTC()));
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/register");
        when(req.getContentType()).thenReturn("application/trust-chain+json");
        when(req.getContentLengthLong()).thenReturn(-1L);
        java.io.ByteArrayInputStream bytes = new java.io.ByteArrayInputStream(chain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener l) { }
        });
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        servlet.doPost(req, resp);

        verify(resp).setStatus(503);
        verify(resp).setHeader("Retry-After", "2");
    }

    @Test
    void aCapOutsideItsRangeFailsTheRequestNamingTheSetting() throws Exception {
        System.setProperty("oidf.registration.max.body.bytes", "4095");
        try {
            OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(mock(RegistrationService.class), req -> OP);
            HttpServletResponse resp = mock(HttpServletResponse.class);
            when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

            servlet.doPost(post(new CountingBody(10), 10), resp);

            verify(resp).setStatus(500);
            assertThrows(com.pingidentity.ps.oidf.platform.settings.SettingRefused.class,
                    () -> servlet.readRequestBody(post(new CountingBody(10), 10)));
        } finally {
            System.clearProperty("oidf.registration.max.body.bytes");
        }
    }

    @Test
    void aTrustChainBodyWhoseStatementIsNotAJwtIsA400NotA500() throws Exception {
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(mock(RegistrationService.class), req -> OP, 65_536);
        byte[] json = "[\"a.b.c\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.io.ByteArrayInputStream bytes = new java.io.ByteArrayInputStream(json);
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/register");
        when(req.getContentType()).thenReturn("application/trust-chain+json");
        when(req.getContentLengthLong()).thenReturn((long) json.length);
        when(req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener l) { }
        });

        try (RefusalLog log = RefusalLog.open()) {
            String written = refuse(servlet, req, 400);

            PublicErrorsAssert.assertGeneric("invalid_request", written);
            log.assertDetail("not a JWT");
        }
    }
}
