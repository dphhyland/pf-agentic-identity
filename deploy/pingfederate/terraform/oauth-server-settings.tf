# OAuth authorization server settings: the scope vocabulary, and the two settings
# that make PF's Persistent Grant Management API answer at all.
#
# atm_id_for_oauth_grant_management + scope_for_oauth_grant_management are the pair
# that matter. Without them /pf-ws/rest/oauth/users/{user}/grants has no access token
# manager to validate a bearer against, and the GM API cannot read a grant. This is
# the setting a fresh PF leaves empty, and the reason the demo could not use a real
# PingFederate until now.

resource "pingfederate_oauth_server_settings" "settings" {
  authorization_code_entropy = 30
  authorization_code_timeout = 60
  refresh_rolling_interval   = 0
  refresh_token_length       = 42

  default_scope_description = "Grant Evaluation API demo"

  scopes = [
    # Consent scopes: the coarse gate the PDP checks before it looks at the RAR.
    {
      name        = "accounts.read"
      description = "Read your account balances and transactions"
      dynamic     = false
    },
    {
      name        = "payments.write"
      description = "Initiate payments from your accounts"
      dynamic     = false
    },

    # Grant Management API scopes, per section 6.7.1 of the draft.
    {
      name        = "grant_management_query"
      description = "Read your grants"
      dynamic     = false
    },
    {
      name        = "grant_management_evaluate"
      description = "Evaluate access against your grants"
      dynamic     = false
    },
    {
      name        = "grant_management_revoke"
      description = "Revoke your grants"
      dynamic     = false
    },
    {
      name        = "grant_management_update"
      description = "Update your grants"
      dynamic     = false
    },
  ]

  # HTTP Basic credentials for the OAuth Administrative Web Service, which is the
  # surface /pf-ws/rest/oauth/users/{user}/grants lives on. Without this the GM API
  # cannot read a grant at all.
  admin_web_service_pcv_ref = {
    id = pingfederate_password_credential_validator.gm_api_service.validator_id
  }

  # These govern OAuth-token access to grant management, which is a separate surface
  # from the Basic-authenticated admin web service above. Set for completeness; the
  # GM API's grant client authenticates with Basic.
  atm_id_for_oauth_grant_management = pingfederate_oauth_access_token_manager.gm_jwt.manager_id
  scope_for_oauth_grant_management  = "grant_management_query"

  # Persistent grants must outlive the token, or there would be nothing to evaluate
  # later. This is what makes a grant a durable record of consent rather than a
  # side effect of a token.
  persistent_grant_lifetime               = 90
  persistent_grant_lifetime_unit          = "DAYS"
  persistent_grant_idle_timeout           = 30
  persistent_grant_idle_timeout_time_unit = "DAYS"
  roll_refresh_token_values               = true

  # Interim: the consent rides as a grant attribute.
  #
  # PingFederate has native RFC 9396 support but ships no AuthorizationDetailProcessor,
  # and no RAR type can be declared without one -- so a stock PF cannot accept
  # authorization_details from a client at all. Until a processor is wired up, the
  # consent has to be injected server-side, which is what this attribute carries.
  #
  # This is a known lie: the "consent" is a constant from grant-mapping.tf, not
  # something a user chose. pf-rar-paz-plugin is the fix and is already deployed to
  # this PF (it registers as "Attestation-aware RAR to PingAuthorize"); it needs a
  # PingAuthorize governance-engine endpoint configured before it can take over. See
  # ../README.md.
  persistent_grant_contract = {
    extended_attributes = [
      { name = "authorization_details" },
    ]
  }
}
