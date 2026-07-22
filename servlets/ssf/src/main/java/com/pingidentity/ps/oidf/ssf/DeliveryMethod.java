/*
 * SSF delivery method URNs (RFC 8935 push, RFC 8936 poll).
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * The two Security Event Token delivery methods this transmitter supports, identified by the URNs SSF uses in
 * {@code delivery_methods_supported} and in a stream's {@code delivery.method}: push over HTTP (RFC 8935) and
 * poll-based delivery (RFC 8936).
 */
public enum DeliveryMethod {
    PUSH("urn:ietf:rfc:8935"),
    POLL("urn:ietf:rfc:8936");

    private final String urn;

    DeliveryMethod(String urn) {
        this.urn = urn;
    }

    public String urn() {
        return this.urn;
    }

    public static DeliveryMethod fromUrn(String urn) {
        if (urn != null) {
            for (DeliveryMethod m : values()) {
                if (m.urn.equals(urn)) {
                    return m;
                }
            }
        }
        throw new IllegalArgumentException("unsupported delivery method: " + urn);
    }
}
