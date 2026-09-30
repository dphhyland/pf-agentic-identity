package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The page an authorization request refused before PingFederate sees it is answered with (OpenID Federation 1.0 §12.1.3). */
class FederationErrorPageTest {

    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final StringWriter body = new StringWriter();

    private String render(FederationErrorPage page, String error, String description, String trackingId) throws IOException {
        when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
        page.write(this.response, 400, error, description, trackingId);
        return this.body.toString();
    }

    @Test
    @Requirement("OIDFED §12.1.3(2)")
    void theEndUserIsToldWhatWentWrongOnAPageThatCannotBeFramedOrCached() throws IOException {
        String page = this.render(FederationErrorPage.builtIn(), "invalid_trust_chain", "no route to a trusted anchor", "tid-1");

        verify(this.response).setStatus(400);
        verify(this.response).setContentType("text/html;charset=UTF-8");
        verify(this.response).setHeader("Cache-Control", "no-store");
        verify(this.response).setHeader("X-Frame-Options", "DENY");
        assertTrue(page.contains("invalid_trust_chain"));
        assertTrue(page.contains(PublicErrors.generic("invalid_trust_chain")));
        assertFalse(page.contains("no route to a trusted anchor"), "the detail is logged, never shown (H-FED-4)");
        assertTrue(page.contains("tid-1"));
    }

    @Test
    void everyValueIsEscapedAndSubstitutedOnce() throws IOException {
        String page = this.render(FederationErrorPage.builtIn(), "<b>", "\"'&${trackingId}", "${error}");

        assertTrue(page.contains("&lt;b&gt;"));
        assertTrue(page.contains("<code>${error}</code>"), "a placeholder in a value stays text");
        assertFalse(page.contains("<b>"));
        assertFalse(page.contains("&amp;"), "the detail is never on the page");
        assertEquals("&quot;&#39;&amp;", FederationErrorPage.escape("\"'&"));
    }

    @Test
    void anOperatorsPageIsUsedWhenOneIsNamed(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("error.html");
        Files.writeString(file, "<p>${error}|${errorDescription}|${trackingId}|${other}</p>", StandardCharsets.UTF_8);

        assertEquals("<p>e|" + PublicErrors.DEFAULT + "|t|${other}</p>", this.render(FederationErrorPage.from(file.toString()), "e", "d", "t"));
    }

    @Test
    void withNoTrackingIdThePageCarriesAGeneratedReferenceAndTheLogTheDetail() throws IOException {
        try (RefusalLog log = RefusalLog.open()) {
            String page = this.render(FederationErrorPage.builtIn(), "invalid_trust_chain", "https://evil.example says no", null);
            assertFalse(page.contains("evil"));
            String line = log.last();
            String reference = line.substring(line.indexOf("ref=") + 4, line.indexOf(' ', line.indexOf("ref=")));
            assertTrue(reference.startsWith(PublicErrors.GENERATED_PREFIX + "-") && page.contains(reference), page);
            assertTrue(line.contains("https://evil.example says no"), line);
        }
    }

    @Test
    void aPageThatIsNamedButMissingIsAnError() {
        assertThrows(IOException.class, () -> FederationErrorPage.from("/nonexistent/error.html"));
    }

    @Test
    void noPageNamedIsTheBuiltInOne() throws IOException {
        assertTrue(this.render(FederationErrorPage.from(null), "e", "d", "t").contains("Sign-in could not continue"));
    }
}
