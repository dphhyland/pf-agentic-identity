# How a login becomes a grant, and how a grant becomes a token.

locals {
  # The consent, pinned. This is the one place the demo knowingly lies: a constant,
  # not something Alice chose. It exists only because a stock PingFederate cannot
  # accept authorization_details without an AuthorizationDetailProcessor.
  #
  # pf-rar-paz-plugin replaces this. It is deployed to this PF already and registers
  # as "Attestation-aware RAR to PingAuthorize", governing each consent request
  # against PingAuthorize policy (requested subset of attested). Once its PDP URL is
  # configured, delete this local and the grant-attribute fulfilment below, and the
  # client sends real authorization_details instead.
  #
  # It is Alice's: three accounts, reads only. The gap against what she actually
  # holds (policy/entitlements.yaml -- she closed 222, is view-only on 444) is the
  # point of the demo, and survives either way.
  demo_consent = jsonencode([
    {
      type      = "account_information"
      actions   = ["read_balance", "read_transactions"]
      locations = ["111", "222", "444"]
    }
  ])
}

# Login -> persistent grant.
#
# USER_KEY is what the grant is filed under, and it is what the GM API looks a grant
# up by: GET /pf-ws/rest/oauth/users/{USER_KEY}/grants. It must therefore match the
# claim named by GRANT_USER_KEY_CLAIM in the GM API's .env, or the API will ask
# PingFederate for grants belonging to nobody.
resource "pingfederate_oauth_idp_adapter_mapping" "html_form" {
  mapping_id = pingfederate_idp_adapter.html_form.adapter_id

  attribute_contract_fulfillment = {
    "USER_NAME" = {
      source = { type = "ADAPTER" }
      value  = "username"
    }
    "USER_KEY" = {
      source = { type = "ADAPTER" }
      value  = "username"
    }
    # Interim, until pf-rar-paz-plugin has a PDP configured. Remove this the moment
    # it does: it would otherwise overwrite what the user actually approved.
    "authorization_details" = {
      source = { type = "TEXT" }
      value  = local.demo_consent
    }
  }

  attribute_sources = []
  issuance_criteria = {
    conditional_criteria = []
  }
}

# Persistent grant -> access token claims.
#
# The JWT ATM stamps the grant's id into the token by itself, as the agid claim --
# that is the "Access Grant GUID Claim Name" field. It is what lets the client name
# the grant it wants evaluated, so the client never has to be told its grant id out
# of band.
resource "pingfederate_oauth_access_token_mapping" "html_form" {
  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.gm_jwt.manager_id
  }

  context = {
    type = "IDP_ADAPTER"
    context_ref = {
      id = pingfederate_idp_adapter.html_form.adapter_id
    }
  }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "OAUTH_PERSISTENT_GRANT" }
      value  = "USER_KEY"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  attribute_sources = []
  issuance_criteria = {
    conditional_criteria = []
  }
}
