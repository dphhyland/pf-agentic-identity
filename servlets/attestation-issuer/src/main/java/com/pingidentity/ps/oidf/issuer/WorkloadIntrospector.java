/*
 * Seam: enrich a validated workload identity with additional attributes for the issuance policy.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Map;

/**
 * After the evidence is validated into an {@link InstanceIdentity}, the attester may <em>introspect</em>
 * the workload further — beyond what the attestation itself carries — and feed the result into the minted
 * attestation and the issuance/downscoping policy. The canonical source is <strong>SPIRE registration
 * selectors</strong>: given the instance subject (a SPIFFE ID), look up how that workload was attested (its
 * {@code k8s:ns}, {@code k8s:sa}, {@code unix:uid}, {@code docker:image}, … selectors) and surface them as
 * workload attributes.
 *
 * <p>Returned attributes are merged into the attestation's {@code workload.attributes} and are available
 * to condition the granted entitlement (e.g. downscope unless {@code k8s:ns:demo} is present). Returning
 * an empty map leaves the attestation unchanged — which is the expected outcome for a format whose
 * subject means nothing to the introspection source.
 */
public interface WorkloadIntrospector {

    /** Attributes discovered for this validated instance identity; empty if none / not applicable. */
    Map<String, Object> introspect(InstanceIdentity instance);

    /** A no-op introspector — the instance's own attributes are used unchanged. */
    static WorkloadIntrospector none() {
        return instance -> Map.of();
    }
}
