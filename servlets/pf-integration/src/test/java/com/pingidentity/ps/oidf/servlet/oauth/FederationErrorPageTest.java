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
        assertTrue(page.contains("no route to a trusted anchor"));
        assertTrue(page.contains("tid-1"));
    }

    @Test
    void everyValueIsEscapedAndSubstitutedOnce() throws IOException {
        String page = this.render(FederationErrorPage.builtIn(), "<b>", "\"'&${trackingId}", null);

        assertTrue(page.contains("&lt;b&gt;"));
        assertTrue(page.contains("&quot;&#39;&amp;${trackingId}"), "a placeholder in a value stays text");
        assertFalse(page.contains("<b>"));
    }

    @Test
    void anOperatorsPageIsUsedWhenOneIsNamed(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("error.html");
        Files.writeString(file, "<p>${error}|${errorDescription}|${trackingId}|${other}</p>", StandardCharsets.UTF_8);

        assertEquals("<p>e|d|t|${other}</p>", this.render(FederationErrorPage.from(file.toString()), "e", "d", "t"));
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
