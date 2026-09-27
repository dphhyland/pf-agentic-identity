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
import java.util.SortedMap;
import java.util.SortedSet;

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
 * <p>The evidence itself never leaves the attester. What the attestation carries about it is a digest
 * ({@code evidenceDigest}, see {@link #evidenceDigest(String)}: the SHA-256 of what the evidence's signature
 * covers), the evidence type that validated it ({@code evidenceType}, the client's {@code attestation_evidence}
 * id) and its expiry - enough for an auditor holding a captured token to match it, and for the attester to bind
 * the evidence to the first key that presents it, and nothing anyone downstream could present to the attester.
 * 0.3.0 embedded the raw token as {@code workload.svid} and {@code workload.instance_attestation} (finding F-0002).
 * {@code audiences} is the evidence's {@code aud}, kept so the attester can refuse evidence minted for more
 * than one audience when it is told to.
 *
 * <p>{@code selectors} are what the validator proved about the instance, in one namespace (plan item X-B01, see
 * {@link EvidenceSelectors}): built only inside a validator, from claims of evidence it verified, after every check
 * passed. Nothing the servlet does afterwards - binding metadata, introspected attributes, the caller-asserted
 * context - can add to them, because this class has no way to change them once built. The minted attestation does
 * not carry them.
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
    private final long iatEpochSeconds;
    private final EvidenceSelectors selectors;

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
     * An identity whose evidence carries no {@code iat}, or whose {@code iat} the validator does not report.
     *
     * @param evidenceType   the evidence type id that validated the instance ({@code spiffe-jwt}, {@code wallet-instance-attestation}, ...)
     * @param evidenceDigest {@link #evidenceDigest(String)} of the evidence, or null when there is none to digest
     * @param audiences      the evidence's {@code aud} values, in order; empty when unknown
     */
    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds, String evidenceType,
                            String evidenceDigest, List<String> audiences) {
        this(format, subject, trustDomain, boundKey, workloadClaims, expEpochSeconds, evidenceType, evidenceDigest,
                audiences, 0L);
    }

    /**
     * @param iatEpochSeconds the evidence's {@code iat}, epoch seconds, or 0 when it has none; the attester caps the
     *                        evidence's whole lifetime ({@code exp - iat}) as well as what is left of it
     */
    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds, String evidenceType,
                            String evidenceDigest, List<String> audiences, long iatEpochSeconds) {
        this(format, subject, trustDomain, boundKey, workloadClaims, expEpochSeconds, evidenceType, evidenceDigest,
                audiences, iatEpochSeconds, EvidenceSelectors.none());
    }

    /**
     * @param selectors what the validator proved about the instance ({@link EvidenceSelectors}); only a validator in
     *                  this package can build a non-empty set
     */
    public InstanceIdentity(String format, String subject, String trustDomain, Map<String, Object> boundKey,
                            Map<String, Object> workloadClaims, long expEpochSeconds, String evidenceType,
                            String evidenceDigest, List<String> audiences, long iatEpochSeconds,
                            EvidenceSelectors selectors) {
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
        this.iatEpochSeconds = iatEpochSeconds;
        this.selectors = selectors == null ? EvidenceSelectors.none() : selectors;
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
        return ofSpiffe(svid, evidenceType, EvidenceSelectors.none());
    }

    /**
     * As {@link #ofSpiffe(SpiffeSvid, String)}, with the selectors the validator proved from the same evidence.
     */
    public static InstanceIdentity ofSpiffe(SpiffeSvid svid, String evidenceType, EvidenceSelectors selectors) {
        LinkedHashMap<String, Object> workload = new LinkedHashMap<>();
        workload.put("spiffe_id", svid.spiffeId());
        return new InstanceIdentity(SpiffeInstanceAttestationValidator.FORMAT, svid.spiffeId(),
                svid.trustDomain(), null, workload, svid.expEpochSeconds(), evidenceType,
                evidenceDigest(svid.raw()), svid.audiences(), svid.iatEpochSeconds(), selectors);
    }

    /**
     * The digest an attestation carries for its evidence, and the key the evidence is bound under: the SHA-256,
     * lower-case hex, of the evidence's JWS Signing Input (RFC 7515 §2) - its first two segments, header '.'
     * payload, exactly the bytes its signature covers. Call it only on a compact JWS whose signature has verified.
     *
     * <p>The signature segment is left out on purpose. A verifier accepts many strings for one signed token: with
     * trailing whitespace, with padding or stray characters in the signature, with non-canonical trailing bits,
     * and for ECDSA the {@code (r, n-s)} twin. A digest over the whole string would give each of those a binding
     * of its own, so a thief could re-encode stolen evidence and present it as new. Nothing in the first two
     * segments can change without breaking the signature. Two tokens with the same header and payload are
     * therefore the same evidence, whatever their signatures. An auditor holding a captured token computes the
     * same value with {@code printf %s "${token%.*}" | sha256sum}.
     *
     * @throws IllegalArgumentException when {@code compactJws} has fewer than two '.' separators
     */
    public static String evidenceDigest(String compactJws) {
        int headerEnd = compactJws.indexOf('.');
        int payloadEnd = headerEnd < 0 ? -1 : compactJws.indexOf('.', headerEnd + 1);
        if (payloadEnd < 0) {
            throw new IllegalArgumentException("evidence is not a compact JWS: it has fewer than three segments");
        }
        return sha256Hex(compactJws.substring(0, payloadEnd));
    }

    /** SHA-256 of the UTF-8 bytes of {@code value}, lower-case hex - what {@code sha256sum} prints for it. */
    public static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
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

    /** {@link #evidenceDigest(String)} of the evidence; null when the format has no single token to digest. */
    public String evidenceDigest() {
        return this.evidenceDigest;
    }

    /** The evidence's {@code aud} values; empty when unknown. */
    public List<String> audiences() {
        return this.audiences;
    }

    /** The evidence's {@code iat}, epoch seconds; 0 when it has none or the validator does not report it. */
    public long iatEpochSeconds() {
        return this.iatEpochSeconds;
    }

    /**
     * What the validator proved about this instance: {@code <source>:<name>} to a sorted set of values, sorted and
     * unmodifiable; empty when the validator declares no selectors. See {@link EvidenceSelectors} for what reaches it
     * and what does not.
     */
    public SortedMap<String, SortedSet<String>> selectors() {
        return this.selectors.asMap();
    }
}
