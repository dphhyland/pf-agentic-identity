# The JWT access token manager for the Grant Evaluation demo.
#
# Two fields here carry the whole demo:
#   "Access Grant GUID Claim Name"     -> agid, the persistent grant's id. This is what lets a
#                                         client name the grant it wants evaluated.
#   "Authorization Details Claim Name" -> authorization_details, the RFC 9396 consent.
#
# "Use Centralized Signing Key" publishes the verification key to PF's /pf/JWKS, which is what
# the GM API's middleware validates inbound tokens against.

resource "pingfederate_oauth_access_token_manager" "gm_jwt" {
  access_control_settings = {
    allowed_clients = [
    ]
    restrict_clients = false
  }
  attribute_contract = {
    default_subject_attribute = null
    extended_attributes = [
      {
        multi_valued = false
        name         = "client_id"
      },
      {
        multi_valued = false
        name         = "sub"
      },
    ]
  }
  configuration = {
    fields = [
      {
        name  = "Access Grant GUID Claim Name"
        value = "agid"
      },
      {
        name  = "Active Signing Certificate Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Encryption Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Key ID"
        value = ""
      },
      {
        name  = "Asymmetric Encryption JWKS URL"
        value = ""
      },
      {
        name  = "Asymmetric Encryption Key"
        value = ""
      },
      {
        name  = "Audience Claim Value"
        value = var.gm_audience # RFC 8707: tokens minted for the bank RS
      },
      {
        name  = "Authorization Details Claim Name"
        value = "authorization_details"
      },
      {
        name  = "Client ID Claim Name"
        value = "client_id"
      },
      {
        name  = "Default JWKS URL Cache Duration"
        value = "720"
      },
      {
        name  = "Enable Token Revocation"
        value = "false"
      },
      {
        name  = "Expand Scope Groups"
        value = "false"
      },
      {
        name  = "Include Issued At Claim"
        value = "true"
      },
      {
        name  = "Include JWE Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include JWE X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Include Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Issuer Claim Value"
        value = var.pf_issuer # RFC 9068 iss; must match subjectJwtProc's Issuer so delegated tokens can be flatten-exchange subjects
      },
      {
        name  = "JWE Algorithm"
        value = ""
      },
      {
        name  = "JWE Content Encryption Algorithm"
        value = ""
      },
      {
        name  = "JWKS Endpoint Cache Duration"
        value = "720"
      },
      {
        name  = "JWKS Endpoint Path"
        value = ""
      },
      {
        name  = "JWS Algorithm"
        value = "RS256"
      },
      {
        name  = "JWT ID Claim Length"
        value = "22"
      },
      {
        name  = "Not Before Claim Offset"
        value = ""
      },
      {
        name  = "Publish Key ID X.509 URL"
        value = "false"
      },
      {
        name  = "Publish Keys to the PingFederate JWKS Endpoint"
        value = "false"
      },
      {
        name  = "Publish Thumbprint X.509 URL"
        value = "false"
      },
      {
        name  = "Scope Claim Name"
        value = "scope"
      },
      {
        name  = "Space Delimit Scope Values"
        value = "true"
      },
      {
        name  = "Token Lifetime"
        value = "720"
      },
      {
        name  = "Type Header Value"
        value = "at+jwt"
      },
      {
        name  = "Use Centralized Signing Key"
        value = "true"
      },
    ]
    sensitive_fields = [
    ]
    tables = [
      {
        name = "Symmetric Keys"
        rows = null
      },
      {
        name = "Certificates"
        rows = null
      },
    ]
  }
  manager_id = "gmJwt"
  name       = "Grant Evaluation JWT"
  parent_ref = null
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }
  selection_settings = {
    resource_uris = []
  }
  session_validation_settings = {
    check_session_revocation_status = false
    check_valid_authn_session       = false
    include_session_id              = false
    update_authn_session_activity   = false
  }
  token_endpoint_attribute_contract = {
    attributes = [
    ]
  }
}
