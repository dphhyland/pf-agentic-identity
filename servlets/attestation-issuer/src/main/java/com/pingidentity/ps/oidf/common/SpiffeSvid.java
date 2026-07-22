/*
 * Parsed, validated SPIFFE JWT-SVID.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;

/**
 * Immutable view of a validated SPIFFE JWT-SVID. A JWT-SVID is deliberately minimal (SPIFFE spec): the
 * SPIFFE ID is the {@code sub} ({@code spiffe://<trust-domain>/<path>}), {@code aud} is the array of
 * intended recipients, plus {@code exp}/{@code iat}. Produced by {@link SpiffeSvidValidator} only after
 * the signature and claims have been verified.
 */
public final class SpiffeSvid {
    private final String spiffeId;
    private final String trustDomain;
    private final String path;
    private final List<String> audiences;
    private final long expEpochSeconds;
    private final long iatEpochSeconds;
    private final String raw;

    public SpiffeSvid(String spiffeId, String trustDomain, String path, List<String> audiences,
                      long expEpochSeconds, long iatEpochSeconds, String raw) {
        this.spiffeId = spiffeId;
        this.trustDomain = trustDomain;
        this.path = path;
        this.audiences = List.copyOf(audiences);
        this.expEpochSeconds = expEpochSeconds;
        this.iatEpochSeconds = iatEpochSeconds;
        this.raw = raw;
    }

    /** The full SPIFFE ID, {@code spiffe://<trust-domain>/<path>}. */
    public String spiffeId() {
        return this.spiffeId;
    }

    /** The trust domain component (the authority of the SPIFFE ID URI). */
    public String trustDomain() {
        return this.trustDomain;
    }

    /** The workload path component (path of the SPIFFE ID URI, leading '/' included), or empty. */
    public String path() {
        return this.path;
    }

    public List<String> audiences() {
        return this.audiences;
    }

    public long expEpochSeconds() {
        return this.expEpochSeconds;
    }

    public long iatEpochSeconds() {
        return this.iatEpochSeconds;
    }

    /** The raw compact JWT-SVID (carried into the attestation's {@code workload.svid} for re-verification). */
    public String raw() {
        return this.raw;
    }

    /**
     * Parses a {@code spiffe://<trust-domain>/<path>} identifier into its trust-domain and path parts.
     *
     * @throws IssuanceException {@code invalid_svid} if the value is not a well-formed SPIFFE ID
     */
    public static String[] parseId(String spiffeId) throws IssuanceException {
        if (spiffeId == null || !spiffeId.startsWith("spiffe://")) {
            throw IssuanceException.invalidSvid("SVID 'sub' is not a spiffe:// identifier");
        }
        String rest = spiffeId.substring("spiffe://".length());
        int slash = rest.indexOf('/');
        String trustDomain = slash < 0 ? rest : rest.substring(0, slash);
        String path = slash < 0 ? "" : rest.substring(slash);
        if (trustDomain.isBlank()) {
            throw IssuanceException.invalidSvid("SPIFFE ID has no trust domain: " + spiffeId);
        }
        return new String[]{trustDomain, path};
    }
}
