/*
 * Minimal HTTP POST abstraction so the governance-engine client is unit-testable without a network.
 */
package com.pingidentity.ps.oidf.rar;

import java.io.IOException;
import java.util.Map;

/**
 * A single POST call. Implemented by {@link PdpTransport} (platform's outbound client), guarded by
 * {@link CircuitBreaker.Guarded}; stubbed in tests.
 *
 * <p>A transport throws {@link PdpUnavailableException} for the failures that mean the PDP was not reached -
 * connect, reset, deadline - and any other {@link IOException} for a failure that happened while talking to
 * it, a TLS handshake included. The distinction is what fail-open turns on.
 */
public interface HttpTransport {

    Response post(String url, String body, Map<String, String> headers) throws IOException;

    /** The status, body and media type of an HTTP response. */
    final class Response {
        private final int status;
        private final String body;
        private final String contentType;

        /** A JSON response; tests and older transports that never looked at the media type use this. */
        public Response(int status, String body) {
            this(status, body, PdpResponses.APPLICATION_JSON);
        }

        public Response(int status, String body, String contentType) {
            this.status = status;
            this.body = body;
            this.contentType = contentType;
        }

        public int status() { return status; }
        public String body() { return body; }

        /** The {@code Content-Type} header as sent, or {@code null} when there was none. */
        public String contentType() { return contentType; }
    }
}
