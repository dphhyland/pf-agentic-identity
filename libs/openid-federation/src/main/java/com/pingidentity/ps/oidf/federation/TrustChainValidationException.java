/*
 * Why a trust chain was refused.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.Locale;

/**
 * A trust chain that did not validate, with what kind of check refused it and which statement it was.
 *
 * <p>The {@link Kind} is for logs, events and tests; the {@link FederationError} is what a federation
 * endpoint answers: {@code invalid_metadata} for a policy conflict (OpenID Federation 1.0 §8.9 "Metadata or
 * Metadata Policy values are invalid or conflict"), {@code invalid_trust_anchor} when no configured anchor
 * can be used, {@code not_found} when the subject's own Entity Configuration cannot be had,
 * {@code temporarily_unavailable} when an entity could not be reached, {@code invalid_trust_chain} for
 * everything else.
 */
public final class TrustChainValidationException extends FederationException {
    private static final long serialVersionUID = 1L;

    /** What refused the chain. {@link #code()} is the lower-case name, for an event's {@code reason}. */
    public enum Kind {
        TYP, ALG, KID, MISSING_CLAIM, IAT, EXP, SIGNATURE, CRIT, SYNTAX, ROUTE, ANCHOR, CONSTRAINT, POLICY,
        BUDGET, PEER_CHAIN, TRANSPORT, SUBJECT;

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

    private final Kind kind;
    private final String issuer;
    private final String subject;

    public TrustChainValidationException(Kind kind, String issuer, String subject, String description) {
        this(kind, issuer, subject, description, null);
    }

    public TrustChainValidationException(Kind kind, String issuer, String subject, String description, Throwable cause) {
        super(errorFor(kind), description, cause);
        this.kind = kind;
        this.issuer = issuer;
        this.subject = subject;
    }

    private static FederationError errorFor(Kind kind) {
        if (kind == Kind.POLICY) {
            return FederationError.INVALID_METADATA;
        }
        if (kind == Kind.ANCHOR) {
            return FederationError.INVALID_TRUST_ANCHOR;
        }
        if (kind == Kind.TRANSPORT) {
            return FederationError.TEMPORARILY_UNAVAILABLE;
        }
        if (kind == Kind.SUBJECT) {
            return FederationError.NOT_FOUND;
        }
        return FederationError.INVALID_TRUST_CHAIN;
    }

    public Kind kind() {
        return this.kind;
    }

    /** The {@code iss} of the statement that failed, when one is known. */
    public String issuer() {
        return this.issuer;
    }

    /** The {@code sub} of the statement that failed, when one is known. */
    public String subject() {
        return this.subject;
    }
}
