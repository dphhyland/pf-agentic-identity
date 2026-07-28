# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "subjectJwtProc"
resource "pingfederate_idp_token_processor" "subject_jwt_proc" {
  attribute_contract = {
    core_attributes = [
      {
        masked = false
        name   = "sub"
      },
    ]
    extended_attributes = [
      {
        masked = false
        name   = "acr"
      },
      {
        masked = false
        name   = "act"
      },
      {
        masked = false
        name   = "scope"
      },
    ]
    mask_ognl_values = false
  }
  configuration = {
    fields = [
      {
        name  = "Expiry Tolerance"
        value = "0"
      },
      {
        name  = "Issuer"
        value = "http://35.223.142.97"
      },
      {
        name  = "JWKS Endpoint URI"
        value = "http://localhost:9080/pf/JWKS"
      },
      {
        name  = "Preserve JWT Claim Types"
        value = "false"
      },
    ]
    sensitive_fields = [
    ]
    tables = [
    ]
  }
  name       = "Subject JWT Processor (user token)"
  parent_ref = null
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor"
  }
  processor_id = "subjectJwtProc"
}

# __generated__ by Terraform from "attestJwtATM"
resource "pingfederate_oauth_access_token_manager" "attest_jwt_atm" {
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
        name         = "act"
      },
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
        value = ""
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
        value = "http://35.223.142.97"
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
  manager_id = "attestJwtATM"
  name       = "Attestation JWT ATM"
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
