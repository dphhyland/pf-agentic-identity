/*
 * Seam: validates a workload's instance-attestation of one format into a format-neutral InstanceIdentity.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * Validates a workload's instance attestation of one <em>format</em> and returns a validated
 * {@link InstanceIdentity}. SPIFFE JWT-SVIDs ({@link SpiffeInstanceAttestationValidator}), the cloud
 * platform token variants ({@link GkeTokenValidator}, {@link GcpSaTokenValidator},
 * {@link EksTokenValidator}, {@link AwsStsWebIdentityValidator}) and digital wallet WIAs
 * ({@link WalletInstanceAttestationValidator}) are implementations; device attestations (WebAuthn, Android
 * Key Attestation, Apple App Attest) could be more. The issuance endpoint selects an implementation per
 * request via {@link InstanceAttestationValidators}, so the instance-identity layer is pluggable without
 * touching the downstream binding, entitlement and minting steps.
 *
 * <p>The <em>client</em> layer (which client, and what it may be granted) is resolved separately by an
 * {@link IssuanceClientResolver}; this interface is only the <em>instance</em> layer (which running
 * instance is asking). The two meet in the servlet.
 *
 * <p>Implementations describe themselves — {@link #id()}, {@link #format()},
 * {@link #requiresTrustDomain()}, {@link #title()}, {@link #description()} — so that config validation and
 * the attester discovery document derive from the registry rather than from hand-maintained lists.
 */
public interface InstanceAttestationValidator {

    /**
     * The stable evidence-type id this validator handles — the accepted value of a client's
     * {@code attestation_evidence} property (e.g. {@code spiffe-jwt}, {@code gke-sa-token}).
     */
    String id();

    /**
     * The instance-attestation <em>format family</em> ({@code "spiffe"}, {@code "wallet"}, {@code "device"}).
     * Several ids may share one format: every cloud platform token still resolves to a SPIFFE identity, so
     * they are all {@code "spiffe"}. Becomes {@code workload.attested_by} on the minted attestation.
     */
    String format();

    /**
     * Whether this evidence type needs the client to configure {@code attestation_trust_domain}. True when
     * the SPIFFE ID is <em>synthesised</em> from a foreign identity (an AWS role ARN, a GCP service-account
     * email) rather than carried in the evidence — without a trust domain those identifiers are unanchored.
     */
    default boolean requiresTrustDomain() {
        return false;
    }

    /**
     * Whether this evidence type needs the client to configure a SPIFFE trust bundle
     * ({@code attestation_spiffe_bundle} or {@code attestation_bundle_url}). True for every format that
     * verifies the presented token against bundle keys; false for a wallet WIA, whose trust root is its
     * provider, resolved through an {@link AttesterKeyResolver}.
     */
    default boolean requiresTrustBundle() {
        return true;
    }

    /** Short human-readable name, surfaced in the attester discovery document. */
    String title();

    /** One-line description of what this validator accepts, surfaced in the discovery document. */
    String description();

    /**
     * Validates the presented instance attestation against the resolved client config.
     *
     * <p>{@code bundleKeys} is passed in rather than read off the config because its source varies (inline
     * {@code attestation_spiffe_bundle} vs a fetched, cached {@code attestation_bundle_url}) and resolving
     * that is the servlet's concern. Formats that establish trust some other way — a wallet WIA resolves its
     * provider's keys through an {@link AttesterKeyResolver} — ignore it.
     *
     * @param presented  the compact instance attestation (a JWT-SVID, a platform token, a WIA, …)
     * @param bundleKeys the client's resolved trust-bundle keys, possibly empty
     * @param config     the resolved client issuance config (expected audience / trust-domain pin)
     * @return the validated, format-neutral instance identity
     * @throws IssuanceException on any validation failure
     */
    InstanceIdentity validate(String presented, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException;
}
