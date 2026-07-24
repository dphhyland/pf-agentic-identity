/*
 * Seam: validates a workload's identity evidence into a SPIFFE identity.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * Validates the {@code svid} field of an issuance request — whatever evidence format the client is
 * configured for — into a {@link SpiffeSvid}. Implementations must verify the evidence cryptographically
 * against {@code bundleKeys} and enforce the config's audience and trust-domain expectations; everything
 * downstream (binding lookup, minting, the attestation's {@code workload} claim) consumes only the
 * returned {@link SpiffeSvid} and never re-inspects the raw evidence.
 *
 * <p>The bundle keys are passed in rather than read off the config because their source varies (inline
 * {@code attestation_spiffe_bundle} vs a fetched {@code attestation_bundle_url}) and resolving that is the
 * servlet's concern.
 */
public interface EvidenceValidator {
    SpiffeSvid validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException;
}
