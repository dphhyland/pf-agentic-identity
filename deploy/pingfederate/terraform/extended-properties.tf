# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Extended-property NAME declarations (server singleton). PF only accepts an oauth_client
# `extended_parameters` entry whose name is declared here (/extendedProperties). The attestation
# issuance clients (attestation-demo-clients.tf) introduce new names, so they must appear below.
#
# ⚠️ SINGLETON — LAST-WRITER-WINS. This resource REPLACES the whole /extendedProperties list on apply.
# Before applying, ADOPT the live list so nothing already declared is dropped:
#     import { to = pingfederate_extended_properties.props  id = "extended_properties" }   # confirm id
#     terraform plan -generate-config-out=generated.tf     # writes the CURRENT items
# then merge the current items with the attestation_* names below. The set here reflects the names the
# module reads (README.md "Per-client tuning" + docs/attestation-issuance.md) but MAY be missing
# site-specific names already present on the live server — reconcile before apply.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

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

    # ── attestation issuance (the hosted attester) — new ──
    { name = "attestation_issuer", description = "Attester iss and required SVID aud" },
    { name = "attestation_spiffe_bundle", description = "SPIFFE trust-bundle JWKS used to verify SVIDs" },
    { name = "attestation_signing_key_ref", description = "OpenBao transit key name for the attester" },
    { name = "attestation_signing_jwk", description = "Inline attester private JWK (dev/demo)" },
    { name = "attestation_instances", description = "SPIFFE-ID bindings (JSON array)" },
    { name = "attestation_issued_ttl", description = "Lifetime (s) of the minted attestation" },
    { name = "attestation_trust_domain", description = "Optional: pin the accepted SVID trust domain" },
    { name = "attestation_entitlement", description = "Optional client-level RFC 9396 ceiling" },
  ]
}
