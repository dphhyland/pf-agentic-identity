/*
 * EvidenceValidator for SPIFFE JWT-SVIDs (the default evidence type).
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * The {@code spiffe-jwt} evidence type: a SPIFFE JWT-SVID validated by {@link SpiffeSvidValidator}
 * exactly as before the evidence-type seam existed. Kept as a thin adapter so the SVID validator stays
 * independently testable and unchanged.
 */
public final class SpiffeJwtEvidenceValidator implements EvidenceValidator {

    private final SpiffeSvidValidator validator;

    public SpiffeJwtEvidenceValidator() {
        this(new SpiffeSvidValidator());
    }

    public SpiffeJwtEvidenceValidator(SpiffeSvidValidator validator) {
        this.validator = validator;
    }

    @Override
    public SpiffeSvid validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        return this.validator.validate(evidence, bundleKeys, config.issuer(), config.expectedTrustDomain());
    }
}
