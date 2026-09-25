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

    /** When the registration ends, in epoch seconds: never later than its trust chain (§12.3). */
    static final String EXPIRES_AT = "federation_registration_expires_at";

    /** The Trust Anchor the registration's chain reached. */
    static final String TRUST_ANCHOR = "federation_trust_anchor";

    /** The Entity Type the client was registered from: {@code openid_relying_party} or {@code oauth_client}. */
    static final String ENTITY_TYPE = "federation_entity_type";

    /**
     * When this module disabled the client because its registration expired, in epoch seconds. Only a client
     * carrying it is enabled again by a renewal: one disabled without it was disabled by an operator.
     */
    static final String DISABLED_AT = "federation_registration_disabled_at";

    static final List<String> EXTENDED_PARAM_NAMES = List.of(
            STATUS,
            "trust_chain",
            "application_type",
            "subject_type",
            "contacts",
            "attestation_required",
            EXPIRES_AT,
            TRUST_ANCHOR,
            ENTITY_TYPE,
            DISABLED_AT);

    private FederationClientParams() {
    }
}
