/*
 * Why an outbound request did not produce a response.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.io.IOException;
import java.util.Objects;

/**
 * An outbound request that produced no response, with the {@link Reason} as data so a caller can count, log or
 * retry by it without reading the message. A response with any status is not an exception: {@link OutboundHttp}
 * returns it.
 */
public final class OutboundHttpException extends IOException {
    private static final long serialVersionUID = 1L;

    /** Why there is no response. */
    public enum Reason {
        /** The URL breaks the address policy's URL rules: scheme, host, credentials or port. */
        REFUSED_URL,
        /** The host resolves to an address the policy refuses. */
        REFUSED_ADDRESS,
        /** The host did not resolve. */
        UNRESOLVED,
        /** The caller's {@link Budget} had no time or request left. */
        BUDGET_EXHAUSTED,
        /** The bulkhead for the host would not let the request in before the deadline. */
        BULKHEAD_FULL,
        /** No checked address accepted a connection. */
        CONNECT_FAILED,
        /** The connect deadline passed while connecting or during the TLS handshake. */
        CONNECT_TIMEOUT,
        /** The TLS handshake failed: an untrusted chain, a certificate that does not name the host, or a protocol error. */
        TLS,
        /** The header deadline passed before the response's status line and headers arrived. */
        HEADER_TIMEOUT,
        /** The total deadline passed. */
        DEADLINE,
        /** The response body is, or declares itself, larger than the cap. */
        BODY_TOO_LARGE,
        /** The response is not well-formed HTTP/1.1 within the limits, or it ended early. */
        MALFORMED_RESPONSE,
        /** Any other I/O failure. */
        IO
    }

    private final Reason reason;

    public OutboundHttpException(Reason reason, String message) {
        this(reason, message, null);
    }

    public OutboundHttpException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    public Reason reason() {
        return this.reason;
    }
}
