# The PF's own public issuer, declared rather than poked in through the admin API.
#
# Learned the hard way in the 2026-07-30 full rebuild: serverSettings was set via the admin API, then
# a deployment env change rolled the pod, which re-imported the baked data.zip and silently REVERTED
# the issuer to the old value. Every hop then returned 200 except the token endpoint, which rejected
# the PoP with "Expected one of [..., http://<old-ip>]".
#
# Managed here, it survives a re-bake and is reapplied by terraform on any drift.
import {
  to = pingfederate_server_settings.settings
  id = "server_settings_singleton"
}

resource "pingfederate_server_settings" "settings" {
  federation_info = {
    base_url = var.pf_public_base_url
    # The provider requires a non-empty saml_2_entity_id even though this deployment is OAuth-only
    # and the live server has none. A placeholder is harmless here - no SAML connection references it
    # - and it is the price of making base_url declarative, which is what actually matters.
    saml_2_entity_id = "urn:pf-spiffe-demo"
  }
}

variable "pf_public_base_url" {
  description = "This PF's public issuer - the LoadBalancer URL. Changes on every cluster rebuild."
  type        = string
}
