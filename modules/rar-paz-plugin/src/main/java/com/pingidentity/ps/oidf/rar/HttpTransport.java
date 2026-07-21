/*
 * Minimal HTTP POST abstraction so the governance-engine client is unit-testable without a network.
 */
package com.pingidentity.ps.oidf.rar;

import java.io.IOException;
import java.util.Map;

/** A single POST call. Implemented by {@link JdkHttpTransport}; stubbed in tests. */
public interface HttpTransport {

    Response post(String url, String body, Map<String, String> headers) throws IOException;

    /** The status and body of an HTTP response. */
    final class Response {
        private final int status;
        private final String body;

        public Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public int status() { return status; }
        public String body() { return body; }
    }
}
