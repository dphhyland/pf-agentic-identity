package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

/** The reading of a PDP's status and media type that both dialects share. */
class PdpResponsesTest {

    @Test
    void aJsonTwoHundredIsReadAndAnEmptyBodyIsEmpty() throws Exception {
        assertEquals("{\"decision\":true}", PdpResponses.bodyOf(new HttpTransport.Response(200, "{\"decision\":true}"), "pdp"));
        assertEquals("", PdpResponses.bodyOf(new HttpTransport.Response(204, null, "application/json"), "pdp"));
        assertEquals("{}", PdpResponses.bodyOf(new HttpTransport.Response(200, "{}", "application/problem+json; charset=utf-8"), "pdp"));
    }

    @Test
    void notServingIsUnavailableAndEverythingElseIsARefusal() {
        for (int status : new int[] {429, 502, 503, 504}) {
            assertThrows(PdpUnavailableException.class,
                    () -> PdpResponses.bodyOf(new HttpTransport.Response(status, "later"), "pdp"), "HTTP " + status);
        }
        for (int status : new int[] {199, 300, 302, 400, 401, 403, 404, 405, 418, 500, 501}) {
            IOException e = assertThrows(IOException.class,
                    () -> PdpResponses.bodyOf(new HttpTransport.Response(status, "no"), "pdp"), "HTTP " + status);
            assertFalse(e instanceof PdpUnavailableException, "HTTP " + status);
            assertTrue(e.getMessage().contains("HTTP " + status), e.getMessage());
        }
    }

    @Test
    void aNonJsonTwoHundredIsARefusal() {
        for (String type : new String[] {null, "text/html", "text/plain; charset=utf-8", "application/xml", "application/jsonx"}) {
            IOException e = assertThrows(IOException.class,
                    () -> PdpResponses.bodyOf(new HttpTransport.Response(200, "{\"decision\":true}", type), "pdp"), String.valueOf(type));
            assertFalse(e instanceof PdpUnavailableException);
            assertTrue(e.getMessage().contains("Content-Type"), e.getMessage());
        }
        assertTrue(PdpResponses.isJson("application/json"));
        assertTrue(PdpResponses.isJson("Application/JSON; charset=utf-8"));
        assertTrue(PdpResponses.isJson("application/vnd.example+json"));
        assertFalse(PdpResponses.isJson("text/json+x"));
        assertFalse(PdpResponses.isJson(null));
    }

    @Test
    void anExcerptIsOneLineAndShort() {
        assertEquals("", PdpResponses.excerpt(null));
        assertEquals("a b c", PdpResponses.excerpt("  a\n b\t\tc "));
        String excerpt = PdpResponses.excerpt("x".repeat(500));
        assertEquals(203, excerpt.length());
        assertTrue(excerpt.endsWith("..."));
    }
}
