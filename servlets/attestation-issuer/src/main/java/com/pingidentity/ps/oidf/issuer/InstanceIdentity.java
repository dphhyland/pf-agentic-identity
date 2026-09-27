/*
 * A validated instance identity - the workload-side half of attestation issuance, format-neutral.
 */
package com.pingidentity.ps.oidf.issuer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A validated instance identity, independent of the attestation <em>format</em> that proved it. A SPIFFE
 * JWT-SVID, a cloud platform's signed workload token, a digital wallet's Wallet Instance Attestation (WIA),
 * or a platform device attestation each validate to one of these.
 * {@link InstanceAttestationValidator}s produce it; {@link AttestationMinter} consumes it. This is what
 * makes the instance-identity layer pluggable - SPIFFE is one format, not the only one.
 *
 * <p>{@code subject} is the stable instance identifier a client's {@code attestation_instances} binding is
 * matched against (the SPIFFE ID; the wallet instance id). {@code format} labels the proving format
 * ({@code "spiffe"}, {@code "wallet"}) and becomes {@code workload.attested_by}. {@code trustDomain} is the
 * format's trust root (the SPIFFE trust domain; the wallet provider entity id), or null. When the instance
 * attestation itself binds a key - a WIA carries the instance's {@code cnf.jwk} - {@code boundKey} holds
 * it, and the issuance endpoint requires it to equal the key being bound. {@code workloadClaims} are the
 * format-specific members embedded under the minted attestation's {@code workload}.
 *
 * <p>The evidence itself never leaves the attester. What the attestation carries about it is its SHA-256
 * ({@code evidenceDigest}, lower-case hex of the compact form as presented), the evidence type that validated
 * it ({@code evidenceType}, the client's {@code attestation_evidence} id) and its expiry - enough for an
 * auditor holding a captured token to match it, and for the attester to bind the evidence to the first key
 * that presents it, and nothing anyone downstream could present to the attester. 0.3.0 embedded the raw
 * token as {@code workload.svid} and {@code workload.instance_attestation} (finding F-0002).
 * {@code audiences} is the evidence's {@code aud}, kept so the attester can refuse evidence minted for more
 * than one audience when it is told to.
 */
public final class InstanceIdentity {
    private final String format;
    private final String subject;
    private final String trustDomain;
    private final Map<String, Object> boundKey;
    private final Map<String, Object> workloadClaims;
    private final long expEpochSeconds;
    private final String evidenceType;
    private final String evidenceDigest;
    private final List<String> audiences;

    /**
     * An identity with no evidence digest: for a validator that has no evidence token to digest (a device
     * attestation whose evidence is not a single string). The minted attestation then carries
     * {@code instance_attestation_exp} alone, and the attester does not bind the evidence.
     */
    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds) {
        this(format, subject, trustDomain, boundKey, workloadClaims, expEpochSeconds, null, null, List.of());
    }

    /**
     * @param evidenceType   the evidence type id that validated the instance ({@code spiffe-jwt}, {@code wallet-instance-attestation}, ...)
     * @param evidenceDigest {@link #sha256Hex} of the evidence as presented, or null when there is none to digest
     * @param audiences      the evidence's {@code aud} values, in order; empty when unknown
     */
    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds, String evidenceType,
                            String evidenceDigest, List<String> audiences) {
        this.format = format;
        this.subject = subject;
        this.trustDomain = trustDomain;
        this.boundKey = boundKey == null ? null
                : Collections.unmodifiableMap(new LinkedHashMap<>(boundKey));
        this.workloadClaims = workloadClaims == null ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(workloadClaims));
        this.expEpochSeconds = expEpochSeconds;
        this.evidenceType = evidenceType;
        this.evidenceDigest = evidenceDigest;
        this.audiences = audiences == null ? List.of() : List.copyOf(audiences);
    }

    /**
     * Builds the identity for a validated SPIFFE JWT-SVID (the original, and still default, format) presented
     * as {@code spiffe-jwt} evidence.
     */
    public static InstanceIdentity ofSpiffe(SpiffeSvid svid) {
        return ofSpiffe(svid, AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT);
    }

    /**
     * Builds the identity for a validated SPIFFE JWT-SVID reached through {@code evidenceType} - the SVID
     * itself, or a cloud platform token mapped onto a SPIFFE identity. The raw token is digested, never kept.
     */
    public static InstanceIdentity ofSpiffe(SpiffeSvid svid, String evidenceType) {
        LinkedHashMap<String, Object> workload = new LinkedHashMap<>();
        workload.put("spiffe_id", svid.spiffeId());
        return new InstanceIdentity(SpiffeInstanceAttestationValidator.FORMAT, svid.spiffeId(),
                svid.trustDomain(), null, workload, svid.expEpochSeconds(), evidenceType,
                sha256Hex(svid.raw()), svid.audiences());
    }

    /** SHA-256 of the UTF-8 bytes of {@code evidence}, lower-case hex - what {@code sha256sum} prints for it. */
    public static String sha256Hex(String evidence) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(evidence.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** The proving format ({@code "spiffe"}, {@code "wallet"}, ...); surfaced as {@code workload.attested_by}. */
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
     * {@code instance_key} - so the attestation being consumed is about the very key being bound.
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

    /** The evidence type id that validated this instance, or null for the digest-less constructor. */
    public String evidenceType() {
        return this.evidenceType;
    }

    /** SHA-256 of the evidence as presented, lower-case hex; null when the format has no single token to digest. */
    public String evidenceDigest() {
        return this.evidenceDigest;
    }

    /** The evidence's {@code aud} values; empty when unknown. */
    public List<String> audiences() {
        return this.audiences;
    }
}
