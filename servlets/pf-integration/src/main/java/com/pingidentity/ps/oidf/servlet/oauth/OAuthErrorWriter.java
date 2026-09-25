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
 * never cached - for a filter that refuses a request before PingFederate sees it. The description is always
 * this module's own text, never a library message that could carry a token, and it is kept inside the
 * character set §5.2 allows here rather than left to {@link OAuthErrorDescriptionFilter}, which is mapped
 * over some endpoints and not others.
 */
public final class OAuthErrorWriter {
    private OAuthErrorWriter() {
    }

    public static void write(HttpServletResponse response, int status, String error, String description) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        try (PrintWriter out = response.getWriter()) {
            out.write(JsonUtil.toJson(Map.of("error", error, "error_description", OAuthErrorDescriptionFilter.withinSet(description))));
        }
    }
}
