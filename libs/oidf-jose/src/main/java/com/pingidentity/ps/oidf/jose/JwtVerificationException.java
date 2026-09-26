/*
 * A JWT rejection whose message is safe to log and to send back to a caller.
 */
package com.pingidentity.ps.oidf.jose;

import java.util.List;
import java.util.Locale;

/**
 * Why a JWT was refused, in a form that never carries the token.
 *
 * <p>jose4j's own exceptions put the whole compact serialization in the message when a signature
 * fails ({@code "Invalid JWS Signature: " + jws}), and the whole claims set when a claim check fails
 * ({@code "JWT (claims->{...}) rejected"}). Every caller here logged that message or copied it into an
 * {@code error_description}, so a rejected client attestation, PoP or entity statement ended up in
 * {@code server.log} and in the HTTP response verbatim. This type replaces them at the one place they
 * arise ({@link JwtCodec}): the message is a fixed sentence per {@link Reason}, the jose4j exception is
 * deliberately <em>not</em> chained as the cause (a stack trace prints the cause's message too), and
 * the jose4j error codes are kept as numbers for diagnostics.
 */
public final class JwtVerificationException extends Exception {
    private static final long serialVersionUID = 1L;

    /** The stable reason codes. {@link #code()} is the lower-case name, suitable for an event field. */
    public enum Reason {
        EXPIRED("the token has expired"),
        NOT_YET_VALID("the token is not yet valid"),
        SIGNATURE("the signature does not verify"),
        ISSUER("the issuer is not the expected one"),
        AUDIENCE("the audience is not the expected one"),
        SUBJECT("the subject is missing or not the expected one"),
        ALGORITHM("the signing algorithm is not accepted"),
        KEY("no usable key matches the token's key id"),
        TYP("the typ header is missing or not the expected type"),
        MALFORMED("the token is not a well-formed JWT"),
        MISSING_CLAIM("a required claim is missing"),
        OTHER("the token could not be verified");

        private final String description;

        Reason(String description) {
            this.description = description;
        }

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }

        public String description() {
            return this.description;
        }
    }

    private final Reason reason;
    private final String detail;
    private final List<Integer> joseErrorCodes;

    public JwtVerificationException(Reason reason) {
        this(reason, null, List.of());
    }

    /**
     * @param detail a short, caller-safe qualifier such as a claim name ({@code "exp"}); never a token,
     *               never a value the caller supplied
     */
    public JwtVerificationException(Reason reason, String detail) {
        this(reason, detail, List.of());
    }

    public JwtVerificationException(Reason reason, String detail, List<Integer> joseErrorCodes) {
        super(message(reason, detail));
        this.reason = reason == null ? Reason.OTHER : reason;
        this.detail = detail;
        this.joseErrorCodes = joseErrorCodes == null ? List.of() : List.copyOf(joseErrorCodes);
    }

    private static String message(Reason reason, String detail) {
        Reason r = reason == null ? Reason.OTHER : reason;
        return "JWT rejected (" + r.code() + "): " + r.description() + (detail == null || detail.isBlank() ? "" : " [" + detail + "]");
    }

    public Reason reason() {
        return this.reason;
    }

    /** The lower-case reason code, e.g. {@code "signature"}. */
    public String code() {
        return this.reason.code();
    }

    /** The caller-safe qualifier passed at construction, or {@code null}. */
    public String detail() {
        return this.detail;
    }

    public boolean isExpired() {
        return this.reason == Reason.EXPIRED;
    }

    /** The jose4j {@code ErrorCodes} values behind this rejection, for diagnostics; empty when none applied. */
    public List<Integer> joseErrorCodes() {
        return this.joseErrorCodes;
    }
}
