# The reference (opaque-token) access-token manager. Captured from the live server before the
# 2026-07-30 teardown rehearsal, which exposed it as the one object the from-zero rebuild could not
# create: attest_cc_mapping references it, but nothing managed it. It came from the original agentic
# demo's config archive rather than from any code in this repo.
#
# Nothing in the current demo issues reference tokens - every attestation client is pinned to
# attestJwtATM - but the mapping that points here is still live, so the honest fix is to manage the
# manager rather than delete a live object during a rebuild.

# Adopted on servers where it already exists; recover-config.sh strips this block so a from-zero
# rebuild CREATES it instead.
import {
  to = pingfederate_oauth_access_token_manager.attest_atm
  id = "attestATM"
}

resource "pingfederate_oauth_access_token_manager" "attest_atm" {
  manager_id = "attestATM"
  name       = "Attestation Reference ATM"

  plugin_descriptor_ref = { id = "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin" }

  configuration = {
    fields = [
      { name = "Token Length", value = "28" },
      { name = "Token Lifetime", value = "120" },
      { name = "Lifetime Extension Policy", value = "NONE" },
      { name = "Lifetime Extension Threshold Percentage", value = "30" },
      { name = "Mode for Synchronous RPC", value = "3" },
      { name = "RPC Timeout", value = "500" },
      { name = "Expand Scope Groups", value = "false" },
    ]
  }

  attribute_contract = {
    extended_attributes = [{ name = "sub" }, { name = "client_id" }]
  }
}
