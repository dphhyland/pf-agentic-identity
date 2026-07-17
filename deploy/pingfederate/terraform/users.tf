# The demo users, and the login form they authenticate at.
#
# These are the people whose consent the Grant Evaluation API answers questions
# about. Their entitlements live separately, in the PDP's system of record
# (policy/entitlements.yaml) -- deliberately not here, because PingFederate is the
# authority on the grant, not on what a subject holds.

resource "pingfederate_password_credential_validator" "demo_users" {
  validator_id = "demoUsers"
  name         = "Demo users"

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
          for u in var.demo_users : {
            default_row = false
            fields = [
              { name = "Username", value = u },
              { name = "Relax Password Requirements", value = "true" },
            ]
            sensitive_fields = [
              { name = "Password", value = var.demo_user_password },
              { name = "Confirm Password", value = var.demo_user_password },
            ]
          }
        ]
      },
    ]
  }
}

resource "pingfederate_idp_adapter" "html_form" {
  adapter_id = "demoHtmlForm"
  name       = "Demo login form"

  plugin_descriptor_ref = {
    id = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
  }

  configuration = {
    tables = [
      {
        name = "Credential Validators"
        rows = [
          {
            default_row = false
            fields = [
              {
                name  = "Password Credential Validator Instance"
                value = pingfederate_password_credential_validator.demo_users.validator_id
              },
            ]
          },
        ]
      },
    ]
    fields = [
      { name = "Challenge Retries", value = "3" },
    ]
  }

  # The adapter hands the authenticated username downstream; the grant is keyed
  # off it.
  attribute_contract = {
    core_attributes = [
      { name = "username", pseudonym = true },
    ]
  }

  attribute_mapping = {
    attribute_sources = []
    attribute_contract_fulfillment = {
      "username" = {
        source = { type = "ADAPTER" }
        value  = "username"
      }
    }
    issuance_criteria = {
      conditional_criteria = []
    }
  }
}
