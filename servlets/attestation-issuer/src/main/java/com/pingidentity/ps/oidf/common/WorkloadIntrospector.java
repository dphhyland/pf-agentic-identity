/*
 * Seam: enrich a validated workload identity with additional attributes for the issuance policy.
 */
package com.pingidentity.ps.oidf.common;

import java.util.Map;

/**
 * After the evidence is validated into a {@link SpiffeSvid}, the attester may <em>introspect</em> the
 * workload further — beyond what the bare SVID carries — and feed the result into the attestation and the
 * issuance/downscoping policy. The canonical source is <strong>SPIRE registration selectors</strong>:
 * given the SPIFFE ID, look up how that workload was attested (its {@code k8s:ns}, {@code k8s:sa},
 * {@code unix:uid}, {@code docker:image}, … selectors) and surface them as workload attributes.
 *
 * <p>Returned attributes are merged into the attestation's {@code workload.attributes} and are available
 * to condition the granted entitlement (e.g. downscope unless {@code k8s:ns:demo} is present). Returning
 * an empty map leaves the attestation unchanged.
 */
public interface WorkloadIntrospector {

    /** Attributes discovered for this validated workload identity; empty if none / not applicable. */
    Map<String, Object> introspect(SpiffeSvid svid);

    /** A no-op introspector — the SVID's own attributes are used unchanged. */
    static WorkloadIntrospector none() {
        return svid -> Map.of();
    }
}
