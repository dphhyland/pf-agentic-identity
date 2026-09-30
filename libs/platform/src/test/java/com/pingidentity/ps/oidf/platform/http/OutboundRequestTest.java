package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.platform.http.OutboundRequest.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** What a request may carry, and what it may not. */
class OutboundRequestTest {

    private static final URI URL = URI.create("https://example.com/");

    @Test
    void aRequestKeepsWhatItWasGivenAndCopiesItsBody() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        OutboundRequest request = OutboundRequest.builder(Method.POST, URL).header("Accept", "application/json")
                .body("application/json", body).connectTimeout(Duration.ofSeconds(1)).headerTimeout(Duration.ofSeconds(2))
                .maxBodyBytes(0).build();
        body[0] = 'x';
        assertEquals(Method.POST, request.method());
        assertEquals(URL, request.uri());
        assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8), request.body());
        request.body()[0] = 'y';
        assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8), request.body());
        assertEquals("Accept", request.headers().get(0)[0]);
        assertEquals("Content-Type", request.headers().get(1)[0]);
        request.headers().get(0)[1] = "changed";
        assertEquals("application/json", request.headers().get(0)[1]);
        assertEquals(Duration.ofSeconds(1), request.connectTimeout());
        assertEquals(Duration.ofSeconds(2), request.headerTimeout());
        assertEquals(0, request.maxBodyBytes());
    }

    @Test
    void theDefaultsAreTheClients() {
        OutboundRequest request = OutboundRequest.get("https://example.com/").build();
        assertNull(request.body());
        assertNull(request.connectTimeout());
        assertNull(request.headerTimeout());
        assertEquals(-1, request.maxBodyBytes());
        assertEquals(Method.POST, OutboundRequest.post("https://example.com/").body("text/plain", "x").build().method());
    }

    @Test
    void aGetCarriesNoBodyAndNoBodyIsTooBig() {
        assertThrows(IllegalArgumentException.class,
                () -> OutboundRequest.builder(Method.GET, URL).body("text/plain", new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> OutboundRequest.builder(Method.POST, URL)
                .body("text/plain", new byte[OutboundRequest.MAX_REQUEST_BODY_BYTES + 1]));
        assertEquals(OutboundRequest.MAX_REQUEST_BODY_BYTES, OutboundRequest.builder(Method.PUT, URL)
                .body("text/plain", new byte[OutboundRequest.MAX_REQUEST_BODY_BYTES]).build().body().length);
        assertThrows(NullPointerException.class, () -> OutboundRequest.builder(Method.POST, URL).body("t", (byte[]) null));
        assertThrows(NullPointerException.class, () -> OutboundRequest.builder(Method.POST, URL).body("t", (String) null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Host", "content-length", "Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Connection",
        "Upgrade", "TE", "Trailer", "Expect"})
    void theFramingHeadersAreTheClientsToWrite(String name) {
        assertThrows(IllegalArgumentException.class, () -> OutboundRequest.builder(Method.GET, URL).header(name, "x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Bad Name", "Bad:Name", "Bad\r\nName", "Ünicode", "(paren)", "a/b"})
    void aNameThatIsNotATokenIsRefused(String name) {
        assertThrows(IllegalArgumentException.class, () -> OutboundRequest.builder(Method.GET, URL).header(name, "x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"a\r\nX-Injected: 1", "a\nb", "a\rb", "nul\0", "del\u007f", "café", "\u0001"})
    void aValueThatCouldSplitTheMessageIsRefused(String value) {
        assertThrows(IllegalArgumentException.class, () -> OutboundRequest.builder(Method.GET, URL).header("X-A", value));
    }

    @Test
    void aValueMayHoldSpacesTabsAndPrintableAscii() {
        String value = "a b\tc ~!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}";
        assertEquals(value, OutboundRequest.builder(Method.GET, URL).header("X-Ok_1.2~", value).build().headers().get(0)[1]);
        assertEquals("", OutboundRequest.builder(Method.GET, URL).header("X-Empty", "").build().headers().get(0)[1]);
    }

    @Test
    void timeoutsMustBePositiveAndCapsNotNegative() {
        OutboundRequest.Builder builder = OutboundRequest.builder(Method.GET, URL);
        assertThrows(IllegalArgumentException.class, () -> builder.connectTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> builder.headerTimeout(Duration.ofMillis(-1)));
        assertThrows(NullPointerException.class, () -> builder.connectTimeout(null));
        assertThrows(IllegalArgumentException.class, () -> builder.maxBodyBytes(-1));
        assertThrows(NullPointerException.class, () -> OutboundRequest.builder(null, URL));
        assertThrows(NullPointerException.class, () -> OutboundRequest.builder(Method.GET, null));
        assertThrows(NullPointerException.class, () -> builder.header(null, "x"));
        assertThrows(NullPointerException.class, () -> builder.header("x", null));
    }
}
