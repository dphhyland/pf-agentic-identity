/*
 * The page an authorization request this server refuses is answered with.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An authorization request refused before PingFederate sees it is answered with a page, never a redirect. OpenID
 * Federation 1.0 §12.1.3: an OP that "fails to establish trust with the RP ... MUST treat the redirection URI as
 * invalid and not perform redirection" - the redirect URI is the untrusted RP's own claim. The End-User is told
 * what went wrong instead, and given the tracking id to quote.
 *
 * <p>The page is an operator's HTML file ({@code OIDF_FEDERATION_ERROR_PAGE}) with {@code ${error}},
 * {@code ${errorDescription}} and {@code ${trackingId}} in it, or a plain built-in one. The End-User has not
 * authenticated and the RP is not trusted, so {@code ${errorDescription}} is the error code's fixed description
 * ({@link PublicErrors#generic}) and {@code ${trackingId}} the correlation id; the detail the caller passes, which can
 * name the client the request chose, goes to {@code server.log} under that id and never onto the page (plan item
 * H-FED-4). Every value is HTML-escaped all the same.
 */
public final class FederationErrorPage {
    private static final String BUILT_IN = """
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sign-in could not continue</title>
            <style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:#1f2933}
            code{background:#f0f2f5;padding:.1rem .3rem;border-radius:3px}</style></head>
            <body>
            <h1>Sign-in could not continue</h1>
            <p>The application that sent you here could not be trusted, so you have not been sent back to it.</p>
            <p><code>${error}</code> - ${errorDescription}</p>
            <p>If you need help, quote this reference: <code>${trackingId}</code></p>
            </body>
            </html>
            """;

    private final String template;

    private FederationErrorPage(String template) {
        this.template = template;
    }

    /** The built-in page. */
    public static FederationErrorPage builtIn() {
        return new FederationErrorPage(BUILT_IN);
    }

    /**
     * The operator's page from {@code path}, or the built-in one when it is null.
     *
     * @throws IOException when a page is named and cannot be read - a deployment error, reported at start
     */
    public static FederationErrorPage from(String path) throws IOException {
        return path == null ? builtIn() : new FederationErrorPage(Files.readString(Path.of(path), StandardCharsets.UTF_8));
    }

    /**
     * Writes the page: {@code status}, HTML, never cached or framed. {@code detail} is logged, not shown; {@code trackingId}
     * is the correlation id the page and the log line carry, or null for {@link PublicErrors#correlationId()}.
     */
    public void write(HttpServletResponse response, int status, String error, String detail, String trackingId) throws IOException {
        String correlationId = trackingId == null ? PublicErrors.correlationId() : trackingId;
        String description = PublicErrors.generic(error);
        PublicErrors.refused("Authorization endpoint filter", status, error, detail, correlationId);
        response.setStatus(status);
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
        java.util.Map<String, String> values = java.util.Map.of("error", escape(error), "errorDescription", escape(description),
                "trackingId", escape(correlationId));
        // One pass: a value that happens to contain a placeholder is never substituted into.
        java.util.regex.Matcher placeholder = PLACEHOLDER.matcher(this.template);
        StringBuilder page = new StringBuilder();
        while (placeholder.find()) {
            placeholder.appendReplacement(page, java.util.regex.Matcher.quoteReplacement(values.get(placeholder.group(1))));
        }
        placeholder.appendTail(page);
        try (PrintWriter out = response.getWriter()) {
            out.write(page.toString());
        }
    }

    private static final java.util.regex.Pattern PLACEHOLDER = java.util.regex.Pattern.compile("\\$\\{(error|errorDescription|trackingId)}");

    static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
