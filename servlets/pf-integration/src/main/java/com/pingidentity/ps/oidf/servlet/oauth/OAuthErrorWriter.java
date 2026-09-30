/*
 * How a filter in front of PingFederate's OAuth endpoints refuses a request.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;

/**
 * Writes an RFC 6749 §5.2 error response - {@code {"error", "error_description"}} as {@code application/json},
 * never cached - for a filter that refuses a request before PingFederate has authenticated the client. RFC 6749 §5.2
 * makes the description optional: "error_description OPTIONAL. Human-readable ASCII [USASCII] text providing
 * additional information, used to assist the client developer in understanding the error that occurred." The caller
 * has not authenticated, so it is told only the fixed description of the error code and a correlation id
 * ({@link PublicErrors}); the detail the filter passes is logged under that id and never written to the response
 * (plan item H-FED-4). The description is kept inside the character set §5.2 allows ("MUST NOT include characters
 * outside the set %x20-21 / %x23-5B / %x5D-7E"), here rather than by {@link OAuthErrorDescriptionFilter}, which is
 * mapped over some endpoints and not others.
 */
public final class OAuthErrorWriter {
    private OAuthErrorWriter() {
    }

    /**
     * Refuses with {@code status} and {@code error}; {@code detail} goes to {@code server.log} only.
     *
     * @return the correlation id the response and the log line carry
     */
    public static String write(HttpServletResponse response, int status, String error, String detail) throws IOException {
        String correlationId = PublicErrors.correlationId();
        String description = PublicErrors.refused("OAuth endpoint filter", status, error, detail, correlationId);
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        try (PrintWriter out = response.getWriter()) {
            out.write(JsonUtil.toJson(Map.of("error", error, "error_description", OAuthErrorDescriptionFilter.withinSet(description))));
        }
        return correlationId;
    }
}
