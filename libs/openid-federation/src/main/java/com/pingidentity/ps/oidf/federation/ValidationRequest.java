/*
 * One request to establish trust in an Entity.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.List;
import java.util.Objects;

/**
 * What a caller asks a {@link TrustChainValidator} to establish: trust in {@code subject}, starting from any
 * statements it was handed, ending at one of the anchors it may name.
 *
 * <p>Build one with {@link #forSubject}. Everything but the subject is optional.
 */
public final class ValidationRequest {
    private final String subject;
    private final List<String> presentedChain;
    private final String opIssuer;
    private final List<String> requestedAnchors;
    private final List<String> peerTrustChain;
    private final long maxLeafAgeSeconds;
    private final long maxAnchorAgeSeconds;
    private final long maxPresentedEntryAgeSeconds;
    private final boolean includeAnchorConfiguration;
    private final int maxFetches;

    private ValidationRequest(Builder b) {
        this.subject = b.subject;
        this.presentedChain = b.presentedChain;
        this.opIssuer = b.opIssuer;
        this.requestedAnchors = b.requestedAnchors;
        this.peerTrustChain = b.peerTrustChain;
        this.maxLeafAgeSeconds = b.maxLeafAgeSeconds;
        this.maxAnchorAgeSeconds = b.maxAnchorAgeSeconds;
        this.maxPresentedEntryAgeSeconds = b.maxPresentedEntryAgeSeconds;
        this.includeAnchorConfiguration = b.includeAnchorConfiguration;
        this.maxFetches = b.maxFetches;
    }

    /** @param subject the Entity Identifier of the Trust Chain subject (§4.1) */
    public static Builder forSubject(String subject) {
        return new Builder(subject);
    }

    public String subject() {
        return this.subject;
    }

    /** Statements the caller was handed (a {@code trust_chain} header or body), in any order. Never null. */
    public List<String> presentedChain() {
        return this.presentedChain;
    }

    /**
     * The OP establishing trust, or null. It is the one {@code aud} the subject's Entity Configuration may
     * carry (an Explicit Registration request, §12.2.1) and the subject of any {@link #peerTrustChain()}.
     */
    public String opIssuer() {
        return this.opIssuer;
    }

    /** The anchors the caller will accept (the resolve endpoint's {@code trust_anchor}); empty means any configured. */
    public List<String> requestedAnchors() {
        return this.requestedAnchors;
    }

    /** A {@code peer_trust_chain} about {@link #opIssuer()} to validate alongside (§4.4). Never null. */
    public List<String> peerTrustChain() {
        return this.peerTrustChain;
    }

    /** Maximum age, from {@code iat}, of a cached or presented statement about the subject; -1 for none. */
    public long maxLeafAgeSeconds() {
        return this.maxLeafAgeSeconds;
    }

    /** Maximum age, from {@code iat}, of a cached or presented statement about anything else; -1 for none. */
    public long maxAnchorAgeSeconds() {
        return this.maxAnchorAgeSeconds;
    }

    /** Presented statements older than this (from {@code iat}) are dropped before resolution; -1 for none. */
    public long maxPresentedEntryAgeSeconds() {
        return this.maxPresentedEntryAgeSeconds;
    }

    /**
     * End the returned chain with the anchor's Entity Configuration even when it was not presented. §4 says a
     * chain "logically always ends with" it but MAY omit it; validation never needs it, because the anchor's
     * keys are configured. Asked for, it is fetched once (usually from cache) and verified against those
     * keys; if it cannot be fetched it is left out.
     */
    public boolean includeAnchorConfiguration() {
        return this.includeAnchorConfiguration;
    }

    /**
     * At most this many fetches for this request, within the validator's own limit; -1 (the default) is the
     * validator's limit. 0 validates the presented statements alone - nothing fetched, nothing from cache - which
     * is how a chain handed over by someone other than its subject is checked without letting them choose what
     * this server fetches.
     */
    public int maxFetches() {
        return this.maxFetches;
    }

    public static final class Builder {
        private final String subject;
        private List<String> presentedChain = List.of();
        private String opIssuer;
        private List<String> requestedAnchors = List.of();
        private List<String> peerTrustChain = List.of();
        private long maxLeafAgeSeconds = -1L;
        private long maxAnchorAgeSeconds = -1L;
        private long maxPresentedEntryAgeSeconds = -1L;
        private boolean includeAnchorConfiguration;
        private int maxFetches = -1;

        private Builder(String subject) {
            this.subject = Objects.requireNonNull(subject, "subject");
        }

        /** Null and blank entries are dropped: they are nothing the caller presented. */
        public Builder presentedChain(List<String> chain) {
            this.presentedChain = nonBlank(chain);
            return this;
        }

        public Builder opIssuer(String issuer) {
            this.opIssuer = issuer;
            return this;
        }

        public Builder requestedAnchors(List<String> anchors) {
            this.requestedAnchors = nonBlank(anchors);
            return this;
        }

        public Builder peerTrustChain(List<String> chain) {
            this.peerTrustChain = nonBlank(chain);
            return this;
        }

        private static List<String> nonBlank(List<String> values) {
            List<String> out = new java.util.ArrayList<>();
            if (values != null) {
                for (String value : values) {
                    if (value != null && !value.isBlank()) {
                        out.add(value);
                    }
                }
            }
            return List.copyOf(out);
        }

        public Builder maxLeafAgeSeconds(long seconds) {
            this.maxLeafAgeSeconds = seconds;
            return this;
        }

        public Builder maxAnchorAgeSeconds(long seconds) {
            this.maxAnchorAgeSeconds = seconds;
            return this;
        }

        public Builder maxPresentedEntryAgeSeconds(long seconds) {
            this.maxPresentedEntryAgeSeconds = seconds;
            return this;
        }

        public Builder includeAnchorConfiguration(boolean include) {
            this.includeAnchorConfiguration = include;
            return this;
        }

        public Builder maxFetches(int fetches) {
            this.maxFetches = fetches;
            return this;
        }

        public ValidationRequest build() {
            return new ValidationRequest(this);
        }
    }
}
