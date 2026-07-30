/*
 * The SPIFFE implementation of InstanceAttestationValidator.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * The SPIFFE implementation of {@link InstanceAttestationValidator}: it validates a SPIFFE JWT-SVID against
 * the client's SPIFFE trust bundle (delegating to {@link SpiffeSvidValidator}) and adapts the result to a
 * format-neutral {@link InstanceIdentity}. This is the original instance-identity path — infrastructure
 * workloads that receive an SVID from a SPIFFE runtime (SPIRE) — now expressed as one pluggable format
 * rather than the only one.
 *
 * <p>The trust domain is carried in the SVID itself, so no {@code attestation_trust_domain} is required;
 * contrast the cloud platform validators, which synthesise a SPIFFE ID and therefore do need one.
 */
public final class SpiffeInstanceAttestationValidator implements InstanceAttestationValidator {

    /** The format label for SPIFFE, used in selection and as {@code workload.attested_by}. */
    public static final String FORMAT = "spiffe";

    private final SpiffeSvidValidator delegate;

    public SpiffeInstanceAttestationValidator() {
        this(new SpiffeSvidValidator());
    }

    public SpiffeInstanceAttestationValidator(SpiffeSvidValidator delegate) {
        this.delegate = delegate;
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT;
    }

    @Override
    public String format() {
        return FORMAT;
    }

    @Override
    public String title() {
        return "SPIFFE JWT-SVID";
    }

    @Override
    public String description() {
        return "A SPIFFE JWT-SVID issued by a SPIFFE runtime (SPIRE), verified against the client's "
                + "SPIFFE trust bundle. The SPIFFE ID is carried in the SVID's 'sub'.";
    }

    @Override
    public InstanceIdentity validate(String presented, List<JsonWebKey> bundleKeys,
                                     AttestationIssuanceConfig config) throws IssuanceException {
        SpiffeSvid svid = this.delegate.validate(
                presented, bundleKeys, config.issuer(), config.expectedTrustDomain());
        return InstanceIdentity.ofSpiffe(svid);
    }
}
