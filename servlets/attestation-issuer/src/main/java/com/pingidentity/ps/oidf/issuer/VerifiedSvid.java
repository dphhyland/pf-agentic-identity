/*
 * A SPIFFE-shaped identity a validator verified, with the selectors it proved from the same evidence.
 */
package com.pingidentity.ps.oidf.issuer;

/**
 * What a cloud-token validator's verification returns: the SPIFFE identity it mapped the token onto, and the
 * {@link EvidenceSelectors} it built from the token's verified claims. Package-private: the validators'
 * {@code validateSvid} keeps returning the bare {@link SpiffeSvid}, and {@code validate} hands both on to
 * {@link InstanceIdentity#ofSpiffe(SpiffeSvid, String, EvidenceSelectors)}.
 */
record VerifiedSvid(SpiffeSvid svid, EvidenceSelectors selectors) {
}
