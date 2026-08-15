/*
 * A validated instance identity — the workload-side half of attestation issuance, format-neutral.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A validated instance identity, independent of the attestation <em>format</em> that proved it. A SPIFFE
 * JWT-SVID, a cloud platform's signed workload token, a digital wallet's Wallet Instance Attestation (WIA),
 * or a platform device attestation each validate to one of these.
 * {@link InstanceAttestationValidator}s produce it; {@link AttestationMinter} consumes it. This is what
 * makes the instance-identity layer pluggable — SPIFFE is one format, not the only one.
 *
 * <p>{@code subject} is the stable instance identifier a client's {@code attestation_instances} binding is
 * matched against (the SPIFFE ID; the wallet instance id). {@code format} labels the proving format
 * ({@code "spiffe"}, {@code "wallet"}) and becomes {@code workload.attested_by}. {@code trustDomain} is the
 * format's trust root (the SPIFFE trust domain; the wallet provider entity id), or null. When the instance
 * attestation itself binds a key — a WIA carries the instance's {@code cnf.jwk} — {@code boundKey} holds
 * it, and the issuance endpoint requires it to equal the key being bound. {@code workloadClaims} are the
 * format-specific members embedded under the minted attestation's {@code workload}.
 */
public final class InstanceIdentity {
    private final String format;
    private final String subject;
    private final String trustDomain;
    private final Map<String, Object> boundKey;
    private final Map<String, Object> workloadClaims;
    private final long expEpochSeconds;

    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds) {
        this.format = format;
        this.subject = subject;
        this.trustDomain = trustDomain;
        this.boundKey = boundKey == null ? null
                : Collections.unmodifiableMap(new LinkedHashMap<>(boundKey));
        this.workloadClaims = workloadClaims == null ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(workloadClaims));
        this.expEpochSeconds = expEpochSeconds;
    }

    /** Builds the identity for a validated SPIFFE JWT-SVID (the original, and still default, format). */
    public static InstanceIdentity ofSpiffe(SpiffeSvid svid) {
        LinkedHashMap<String, Object> workload = new LinkedHashMap<>();
        workload.put("spiffe_id", svid.spiffeId());
        workload.put("svid", svid.raw());
        return new InstanceIdentity(SpiffeInstanceAttestationValidator.FORMAT, svid.spiffeId(),
                svid.trustDomain(), null, workload, svid.expEpochSeconds());
    }

    /** The proving format ({@code "spiffe"}, {@code "wallet"}, …); surfaced as {@code workload.attested_by}. */
    public String format() {
        return this.format;
    }

    /** The stable instance identifier a client binding is matched against. */
    public String subject() {
        return this.subject;
    }

    /** The format's trust root (SPIFFE trust domain / wallet provider entity id), or null. */
    public String trustDomain() {
        return this.trustDomain;
    }

    /**
     * The key this instance attestation binds (a WIA {@code cnf.jwk}); null when the format binds no key
     * (a SPIFFE SVID does not). When non-null, the issuance endpoint requires it to equal the presented
     * {@code instance_key} — so the attestation being consumed is about the very key being bound.
     */
    public Map<String, Object> boundKey() {
        return this.boundKey;
    }

    /** Format-specific members embedded under the minted attestation's {@code workload}. */
    public Map<String, Object> workloadClaims() {
        return this.workloadClaims;
    }

    /** The instance attestation's expiry, epoch seconds. */
    public long expEpochSeconds() {
        return this.expEpochSeconds;
    }
}
