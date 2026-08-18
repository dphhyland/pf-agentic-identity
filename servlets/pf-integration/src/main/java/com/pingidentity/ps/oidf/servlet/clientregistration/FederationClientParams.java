package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.List;

/**
 * The PingFederate extended-property names this module writes onto a federation-registered client.
 *
 * <p>PF rejects an {@code extended_parameters} entry whose name is not declared server-side, so this
 * list must match {@code deploy/pingfederate/terraform/extended-properties.tf}. It exists as a single
 * constant precisely so the two cannot drift: {@code status} in particular is load-bearing — it is the
 * only thing distinguishing a client this module registered from one an administrator created, and
 * both registration paths refuse to touch a client that lacks it.
 */
final class FederationClientParams {

    /** Registration provenance: {@code registered} (§12.2 explicit) or {@code auto_registered} (§12.1). */
    static final String STATUS = "status";

    static final List<String> EXTENDED_PARAM_NAMES = List.of(
            STATUS,
            "trust_chain",
            "application_type",
            "subject_type",
            "contacts",
            "token_endpoint_auth_method",
            "attestation_required");

    private FederationClientParams() {
    }
}
