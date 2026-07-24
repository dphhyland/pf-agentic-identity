# Extended-property NAME declarations — superset of deploy/pingfederate/terraform/extended-properties.tf
# plus the Phase-2 evidence-adapter names (attestation_evidence / attestation_bundle_url /
# attestation_evidence_issuer).
#
# ⚠️ SINGLETON — LAST-WRITER-WINS. This resource REPLACES the whole /extendedProperties list on apply.
# The demo PF boots from the same data.zip as the Railway deployment, so the live list should already
# equal the verification+issuance names below minus the three new ones; still, ADOPT the live list first:
#     terraform plan -generate-config-out=generated.tf     # after uncommenting the import block
# and reconcile before the first apply.

import {
  to = pingfederate_extended_properties.props
  id = "extended_properties"
}

resource "pingfederate_extended_properties" "props" {
  items = [
    # ── attestation-based client auth (verification side) ──
    { name = "attestation_required", description = "Marks the client as requiring attestation" },
    { name = "attestation_pop_max_age", description = "Max age (s) of the PoP JWT iat" },
    { name = "attestation_dpop_max_age", description = "Max age (s) of the DPoP proof iat" },
    { name = "attestation_clock_skew", description = "Allowed clock skew (s)" },
    { name = "attestation_challenge_required", description = "Require a server-issued challenge" },
    { name = "attestation_expected_htu", description = "Pin the DPoP htu behind a reverse proxy" },
    { name = "attestation_accepted_algs", description = "Allowed attestation signing algs", multi_valued = true },
    { name = "attestation_pop_algs", description = "Allowed PoP signing algs", multi_valued = true },
    { name = "attestation_dpop_algs", description = "Allowed DPoP signing algs", multi_valued = true },
    { name = "attestation_required_claims", description = "claims the attestation must carry", multi_valued = true },

    # ── attestation issuance (the hosted attester) ──
    { name = "attestation_issuer", description = "Attester iss and required evidence aud" },
    { name = "attestation_spiffe_bundle", description = "Inline trust-bundle JWKS used to verify evidence" },
    { name = "attestation_signing_key_ref", description = "OpenBao transit key name for the attester" },
    { name = "attestation_signing_jwk", description = "Inline attester private JWK (dev/demo)" },
    { name = "attestation_instances", description = "SPIFFE-ID bindings (JSON array)" },
    { name = "attestation_issued_ttl", description = "Lifetime (s) of the minted attestation" },
    { name = "attestation_trust_domain", description = "Pin the accepted trust domain (required for gke-sa-token)" },
    { name = "attestation_entitlement", description = "Optional client-level RFC 9396 ceiling" },

    # ── evidence adapter (Phase 2) ──
    { name = "attestation_evidence", description = "Evidence type: spiffe-jwt (default) | gke-sa-token" },
    { name = "attestation_bundle_url", description = "Fetched trust-bundle JWKS URL (alternative to inline)" },
    { name = "attestation_evidence_issuer", description = "Pin the evidence iss (e.g. GKE cluster issuer URL)" },
  ]
}
