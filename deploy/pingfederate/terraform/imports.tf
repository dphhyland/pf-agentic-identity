# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Adoption of the EXISTING live pingfederate-runtime config (import, never recreate).
#
# These import{} blocks enumerate every config object currently running in prod (enumerated from the
# live configArchive extracted 2026-07-14). They are the input to config generation:
#
#     terraform plan -generate-config-out=generated.tf
#
# Terraform writes the EXACT current body of each object into generated.tf. Review it, move the bodies
# into per-type .tf files (or keep generated.tf), re-plan until the only diff is intended, then apply
# and export (see README.md). The import id for every PF resource is the object's own id.
#
# NOT MANAGEABLE HERE (provider gap): the `rarPazProc` authorization-detail processor — the
# pingidentity/pingfederate provider has no authorization_detail_processor resource. It stays an
# unmanaged carve-out inside data.zip. (It is also currently inert in prod: its plugin jar isn't
# deployed — see the pf-license-and-prod-topology note.)
#
# EXCLUDED deliberately: the runtime-registered dynamic client
# `https://pf-demo-ui-…/e/prodtok-…` (created by OIDF §12.1 auto-registration at token time; it
# regenerates and must not be pinned in source).
# ─────────────────────────────────────────────────────────────────────────────────────────────────

# ── OAuth clients (id = client_id) ──────────────────────────────────────────────────────────────
import {
  to = pingfederate_oauth_client.rp_example
  id = "https://rp.example.com"
}
import {
  to = pingfederate_oauth_client.northwind_webapp
  id = "northwind-webapp"
}
import {
  to = pingfederate_oauth_client.agent_account
  id = "urn:agent:northwind-account:v1"
}
import {
  to = pingfederate_oauth_client.agent_concierge
  id = "urn:agent:northwind-concierge:v1"
}
import {
  to = pingfederate_oauth_client.agent_payments
  id = "urn:agent:northwind-payments:v1"
}

# ── Access Token Managers (id = instance id) ────────────────────────────────────────────────────
import {
  to = pingfederate_oauth_access_token_manager.attest_atm
  id = "attestATM"
}
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_atm
  id = "attestJwtATM"
}
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_acct
  id = "attestJwtAcct"
}
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_pmts
  id = "attestJwtPmts"
}
import {
  to = pingfederate_oauth_access_token_manager.user_jwt_atm
  id = "userJwtATM"
}

# ── IdP token processors (id = processor id) — the token-exchange subject side ───────────────────
import {
  to = pingfederate_idp_token_processor.subject_jwt_proc
  id = "subjectJwtProc"
}
import {
  to = pingfederate_idp_token_processor.subject_token_proc
  id = "subjectTokenProc"
}

# ── OAuth Token Exchange processor policy (id = policy id) — user_to_agent (RFC 8693 act chain) ──
import {
  to = pingfederate_oauth_token_exchange_processor_policy.user_to_agent
  id = "userToAgentTE"
}

# ── Password credential validator (id = pcv id) ─────────────────────────────────────────────────
import {
  to = pingfederate_password_credential_validator.user_pcv
  id = "userpcv"
}

# ── IdP adapter (id = adapter id) — HTML Form login ─────────────────────────────────────────────
import {
  to = pingfederate_idp_adapter.htmlform
  id = "htmlform"
}

# ── Access token mappings (id = "CONTEXT|atmId") ────────────────────────────────────────────────
# The OIDF client_credentials mapping that carries the federation gate is authored explicitly in
# access-token-mappings.tf (its issuance_criteria is the reason this whole module exists — do not let
# generate-config-out overwrite it). Enumerate the REST via `GET /oauth/accessTokenMappings` (see
# helpers/list-config-ids.sh) and add an import{} + resource per mapping id printed there, e.g.:
#
#   import {
#     to = pingfederate_oauth_access_token_mapping.te_account
#     id = "TOKEN_EXCHANGE_PROCESSOR_POLICY|attestJwtAcct"
#   }
