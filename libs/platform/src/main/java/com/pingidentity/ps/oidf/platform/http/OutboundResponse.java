/*
 * A response: status, headers, the capped body and the address it came from.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A response of any status: {@link OutboundHttp} throws only when there is no response, never for a status, so a
 * caller always sees the code. The body was read whole, within the cap and the deadline.
 */
public final class OutboundResponse {

    /** A response header as received. */
    public record Header(String name, String value) {
    }

    private final int status;
    private final String reason;
    private final List<Header> headers;
    private final byte[] body;
    private final InetSocketAddress remoteAddress;

    OutboundResponse(int status, String reason, List<Header> headers, byte[] body, InetSocketAddress remoteAddress) {
        this.status = status;
        this.reason = reason;
        this.headers = List.copyOf(headers);
        this.body = body;
        this.remoteAddress = remoteAddress;
    }

    public int status() {
        return this.status;
    }

    /** The reason phrase, which may be empty. */
    public String reason() {
        return this.reason;
    }

    /** Whether the status is 2xx. */
    public boolean successful() {
        return this.status >= 200 && this.status < 300;
    }

    /** Every header, in the order received. */
    public List<Header> headers() {
        return this.headers;
    }

    /** The first value of header {@code name}, compared without case. */
    public Optional<String> header(String name) {
        for (Header header : this.headers) {
            if (header.name().equalsIgnoreCase(name)) {
                return Optional.of(header.value());
            }
        }
        return Optional.empty();
    }

    /** Every value of header {@code name}, compared without case, in the order received. */
    public List<String> headers(String name) {
        List<String> values = new ArrayList<>();
        for (Header header : this.headers) {
            if (header.name().equalsIgnoreCase(name)) {
                values.add(header.value());
            }
        }
        return values;
    }

    /** The body; empty when there was none. */
    public byte[] body() {
        return this.body.clone();
    }

    /** The body decoded as UTF-8. */
    public String bodyText() {
        return new String(this.body, StandardCharsets.UTF_8);
    }

    /** The checked address the connection went to. */
    public InetSocketAddress remoteAddress() {
        return this.remoteAddress;
    }

    @Override
    public String toString() {
        return "OutboundResponse[" + this.status + " from " + this.remoteAddress + ", " + this.body.length + " bytes]";
    }
}
