# PF server settings — the base URL is the one value here that matters to this module.
#
# PF computes from federation_info.base_url: the OAuth `issuer` in /.well-known/openid-configuration,
# the advertised token endpoint, the audiences it accepts on a private_key_jwt client assertion, and
# (through OAuthIssuerUtils.getIssuerValue) the `iss`/`sub` of the OIDF module's entity statement at
# /.well-known/openid-federation. Before this resource, base_url was whatever the archive said — and the
# archive was exported from the old EKS rig, so staging advertised
# http://ae546b15c1b884e858e24d0c021d7e20-548341687.ap-southeast-2.elb.amazonaws.com and the demo UI had
# to send that as PF_TOKEN_AUD. Now it is local.pf_base_url, keyed by var.environment (variables.tf).
#
# SINGLETON — adopt, don't create. The import id is a placeholder (the provider ignores it).
# Only federation_info is authored. If the first plan shows contact_info / notifications being cleared,
# the live server carries values there — capture them (comment this resource, plan -generate-config-out,
# fold the generated blocks in here) rather than letting the apply drop them.
import {
  to = pingfederate_server_settings.this
  id = "server_settings"
}

resource "pingfederate_server_settings" "this" {
  federation_info = {
    base_url = local.pf_base_url
    # The live archive has entityID="" (it was loaded via the drop-in-deployer, which skips admin-API
    # validation); the admin API requires a value, so pin it to the same origin — nothing here does SAML.
    saml_2_entity_id = local.pf_base_url
  }
  # Live defaults, pinned so the plan is exactly the base URL (the provider nulls unset nested blocks).
  notifications = {
    expired_certificate_administrative_console_warning_days  = 14
    expiring_certificate_administrative_console_warning_days = 14
    notify_admin_user_password_changes                       = false
    thread_pool_exhaustion_notification_settings = {
      email_address       = ""
      notification_mode   = "LOGGING_ONLY"
      thread_dump_enabled = true
    }
  }
}
