# The two clients in the demo, and they play very different roles.

# acme-budgeting is the TPP: the client a user consents to. Its grants are the
# things the Grant Evaluation API later answers questions about.
#
# authorization_detail_types is what lets this client ask for RFC 9396 consent: the
# fine-grained "these accounts, these actions" record the PDP decides against. A scope
# cannot name an account; this can.
#
# These types only exist because plugins/authorization-detail-processor is deployed --
# PingFederate refuses to declare a type without a processor to validate it, and ships
# none.
resource "pingfederate_oauth_client" "acme_budgeting" {
  client_id = "acme-budgeting"
  name      = "Acme Budgeting"

  # CLIENT_CREDENTIALS is what makes the Open Banking case work: a TPP holding a
  # long-lived consent asks whether it still covers an account, with no user present.
  # The subject comes off the grant, so no user token is needed.
  grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN", "CLIENT_CREDENTIALS"]

  redirect_uris = [
    "http://localhost:8081/callback",
    "https://demo-production-0792.up.railway.app/callback",
  ]

  client_auth = {
    type   = "SECRET"
    secret = var.tpp_client_secret
  }

  restrict_scopes = true
  restricted_scopes = [
    "openid",
    "accounts.read",
    "payments.write",
    # The Grant Management scopes. Each operation requires exactly its own, so a
    # client registered only to evaluate cannot thereby read or revoke -- which is
    # why they are listed separately rather than as one blanket permission.
    "grant_management_query",
    "grant_management_revoke",
    "grant_management_evaluate",
  ]

  # authorization_detail_types are supplied by pf-rar-paz-plugin, not by this repo.
  # Re-add them once that processor is deployed and its types are declared -- see
  # ../README.md. They cannot be listed here without a processor to validate them.

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.gm_jwt.manager_id
  }

  # The consent must outlive any one token; that is the whole premise of asking
  # about it later.
  persistent_grant_expiration_type      = "OVERRIDE_SERVER_DEFAULT"
  persistent_grant_expiration_time      = 90
  persistent_grant_expiration_time_unit = "DAYS"
}

# gm-api is not a user-facing client at all. It is the GM API service itself,
# authenticating to PingFederate's Persistent Grant Management web service to read
# the grants it evaluates. Client credentials only: there is no user in this leg.
#
# Its token must carry scope_for_oauth_grant_management (see oauth-server-settings.tf)
# or PF will refuse the grant management endpoints.
resource "pingfederate_oauth_client" "gm_api" {
  client_id = "gm-api"
  name      = "Grant Management API service"

  grant_types = ["CLIENT_CREDENTIALS"]

  client_auth = {
    type   = "SECRET"
    secret = var.gm_api_client_secret
  }

  restrict_scopes = true
  restricted_scopes = [
    "grant_management_query",
    "grant_management_evaluate",
    "grant_management_revoke",
    "grant_management_update",
  ]

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.gm_jwt.manager_id
  }
}
