# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Demo clients for the hosted attester (/federation/attestation) — the pf-demo-ui "Attestation minting"
# section. Each client's attestation_* extended properties configure the AttestationIssuanceServlet:
# a SPIFFE workload presents its JWT-SVID and PF mints a Client Attestation signed with THIS client's
# attester key. The two clients differ only in where that key lives — inline JWK vs OpenBao transit —
# which is the toggle the demo shows. See docs/attestation-issuance.md.
#
# These are NEW clients (created, not imported). Their extended-property NAMES must be declared in
# pingfederate_extended_properties first — see extended-properties.tf.
#
# NOTE (loop-to-token): for a minted attestation to also be ACCEPTED at the token endpoint, PF's verifier
# must trust the attester key — the inline client reuses the pre-trusted `mock-attester-1` key; the vault
# key's public JWK must be added to oidf-mock-attesters.json (a deploy step). The demo's mint section
# itself only needs issuance.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

variable "demo_attest_client_secret" {
  description = "Demo-only client secret for the attestation-demo clients (throwaway; matches the pf-demo-ui default)"
  type        = string
  default     = "demo-secret-123"
  sensitive   = true
}

locals {
  # The attester identity: the minted attestation's `iss` AND the required SVID `aud`. Shared by both clients.
  demo_attester_issuer = "https://attester.example.com"

  # The demo SPIFFE trust-domain bundle (public). Its PRIVATE half is served to the browser via the
  # pf-demo-ui /config (DEMO_TD_PRIVATE_JWK) to sign demo SVIDs. Demo-only key.
  demo_spiffe_bundle = jsonencode({
    keys = [{
      kty = "EC", kid = "7ijwHrcSPSmDv-UfM3wlQEgpdZJDrM4yYU1XUtiXsHM", crv = "P-256",
      x   = "Kp2RkAdN8-BTBWXMvgYlJpWq-ccIsxtvOzINuaFvUbQ",
      y   = "ceNtnwRomicS7uydIiiK1Mq4zE_SAPMj5QQQbVn0qG4",
      use = "sig", alg = "ES256"
    }]
  })

  # One SPIFFE-ID binding: the payment-agent, entitled to EMEA, with per-instance metadata that rides into
  # the minted attestation's workload.attributes.
  demo_instances = jsonencode([{
    spiffe_id   = "spiffe://banking.demo/payment-agent"
    entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
    metadata    = { region = "EMEA", environment = "prod" }
  }])

  # The inline attester key = the pre-trusted mock-attester-1 (its public half is already in
  # oidf-mock-attesters.json), so an inline-minted attestation also verifies at the token endpoint.
  demo_inline_signing_jwk = jsonencode({
    kty = "EC", kid = "mock-attester-1", crv = "P-256",
    x   = "c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag",
    y   = "ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI",
    d   = "9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84"
  })

  # The shared attestation_* extended properties both clients carry (everything except the signer choice).
  demo_attestation_common = {
    attestation_issuer      = { values = [local.demo_attester_issuer] }
    attestation_spiffe_bundle = { values = [local.demo_spiffe_bundle] }
    attestation_instances   = { values = [local.demo_instances] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
  }
}

# ── Inline-JWK attester: signs with an in-config private JWK ─────────────────────────────────────
resource "pingfederate_oauth_client" "demo_attest_inline" {
  client_id            = "demo-attest-inline"
  name                 = "Demo attester — inline JWK"
  grant_types          = ["CLIENT_CREDENTIALS"]
  client_auth          = { type = "SECRET", secret = var.demo_attest_client_secret } # demo secret; the attestation hook is the real client auth
  restrict_scopes      = false
  bypass_approval_page  = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  extended_parameters = merge(local.demo_attestation_common, {
    attestation_signing_jwk = { values = [local.demo_inline_signing_jwk] }
  })
}

# ── OpenBao-transit attester: signs via the vault; the private key never leaves it ──────────────
resource "pingfederate_oauth_client" "demo_attest_vault" {
  client_id            = "demo-attest-vault"
  name                 = "Demo attester — OpenBao transit"
  grant_types          = ["CLIENT_CREDENTIALS"]
  client_auth          = { type = "SECRET", secret = var.demo_attest_client_secret }
  restrict_scopes      = false
  bypass_approval_page  = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  extended_parameters = merge(local.demo_attestation_common, {
    # The OpenBao transit key name (already provisioned on the `openbao` Railway service, type ecdsa-p256).
    # Requires OIDF_OPENBAO_URL / OIDF_OPENBAO_TOKEN on the PF runtime for the signer to reach the vault.
    attestation_signing_key_ref = { values = ["attestation-es256"] }
  })
}
