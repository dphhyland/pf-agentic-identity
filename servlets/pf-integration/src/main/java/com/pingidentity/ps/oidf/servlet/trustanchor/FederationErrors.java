/*
 * How every federation servlet answers a failure.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * Writes the OpenID Federation 1.0 §8.9 error response - {@code {"error", "error_description"}} as
 * {@code application/json} with the status the error SHOULD carry - and logs it the PingFederate way: a
 * refused request is one INFO line with no stack trace (it is the caller's doing, and a stack trace per bad
 * request buries the log), an upstream that could not be reached is a WARN, and only a fault of ours is an
 * ERROR with its stack. The description of a server error is never the exception's message, which can
 * carry internals; it is logged instead.
 */
public final class FederationErrors {
    private static final Log LOGGER = LogFactory.getLog(FederationErrors.class);
    static final String SERVER_ERROR_DESCRIPTION = "the server encountered an unexpected condition";

    private FederationErrors() {
    }

    /** Whatever a handler threw: a classified federation failure, a bad request, or a fault of ours. */
    public static void write(HttpServletResponse resp, Exception e) throws IOException {
        if (e instanceof FederationException federation) {
            write(resp, federation.error(), federation.description(), federation);
        } else if (e instanceof IllegalArgumentException) {
            write(resp, FederationError.INVALID_REQUEST, e.getMessage(), e);
        } else {
            write(resp, FederationError.SERVER_ERROR, e.getMessage(), e);
        }
    }

    public static void write(HttpServletResponse resp, FederationError error, String description, Throwable cause) throws IOException {
        write(resp, error.httpStatus(), error.code(), description, cause);
    }

    /** For callers whose refusals carry their own status and code (a registration rejection). */
    public static void write(HttpServletResponse resp, int status, String code, String description, Throwable cause) throws IOException {
        String shown = status >= 500 && status != 503 ? SERVER_ERROR_DESCRIPTION : String.valueOf(description);
        String line = "status=" + status + " error=" + code + " desc=" + LogSafe.quoted(String.valueOf(description));
        if (status == 503) {
            LOGGER.warn("Federation endpoint temporarily unavailable: " + line);
        } else if (status >= 500) {
            LOGGER.error("Federation endpoint failed: " + line, cause);
        } else {
            LOGGER.info("Federation endpoint refused a request: " + line);
        }
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(Map.of("error", code, "error_description", shown)));
        }
    }
}
