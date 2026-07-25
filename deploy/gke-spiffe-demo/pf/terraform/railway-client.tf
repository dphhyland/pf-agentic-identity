# The OAuth client the Railway workload authenticates as. In CIMD mode the attester reads this client's
# SPIFFE binding + trust config from the hosted CIMD document, NOT from PF extended properties — so this
# resource only needs to make the client EXIST for the token endpoint (secret + the attestation gate on
# the access-token mapping). No attestation_* properties are set here.

resource "pingfederate_oauth_client" "demo_attest_railway" {
  client_id                        = "demo-attest-railway"
  name                             = "Demo attester — Railway workload (SPIFFE via CIMD)"
  grant_types                      = ["CLIENT_CREDENTIALS"]
  client_auth                      = { type = "PRIVATE_KEY_JWT" }
  jwks_settings                    = { jwks = var.bridge_public_jwks }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  # Issue JWT access tokens (decodable) rather than opaque reference tokens.
  default_access_token_manager_ref         = { id = "attestJwtATM" }
  restrict_to_default_access_token_manager = true

  extended_parameters = {
    attestation_required = { values = ["true"] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
