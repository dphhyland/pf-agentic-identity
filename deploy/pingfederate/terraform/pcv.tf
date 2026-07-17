# Credentials for PingFederate's OAuth Administrative Web Service.
#
# /pf-ws/rest/oauth/users/{user}/grants -- the Persistent Grant Management API the
# GM API reads grants from -- is part of the OAuth *Administrative* Web Service, and
# that service authenticates with HTTP Basic against a password credential validator.
# It does not accept the bearer token from atm_id_for_oauth_grant_management: that
# setting governs a different surface. A bearer against this endpoint is answered
# with "HTTP Basic authentication is required".
#
# So the GM API service account lives here. This is the account behind
# PINGFED_ADMIN_USER / PINGFED_ADMIN_PASS in .env, and it is a service identity for
# reading grants -- not a PingFederate console administrator.

resource "pingfederate_password_credential_validator" "gm_api_service" {
  validator_id = "gmApiService"
  name         = "GM API service account"

  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }

  attribute_contract = {
    extended_attributes = []
  }

  configuration = {
    fields           = []
    sensitive_fields = []
    tables = [
      {
        name = "Users"
        rows = [
          {
            default_row = false
            fields = [
              { name = "Username", value = var.gm_service_username },
              { name = "Relax Password Requirements", value = "true" },
            ]
            sensitive_fields = [
              { name = "Password", value = var.gm_service_password },
              { name = "Confirm Password", value = var.gm_service_password },
            ]
          },
        ]
      },
    ]
  }
}
