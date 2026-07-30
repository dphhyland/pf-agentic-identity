# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "demo-attest-eks"
resource "pingfederate_oauth_client" "demo_attest_eks" {
  allow_authentication_api_init                = false
  authorization_detail_types                   = []
  bypass_activation_code_confirmation_override = null
  bypass_approval_page                         = true
  ciba_delivery_mode                           = null
  ciba_notification_endpoint                   = null
  ciba_polling_interval                        = null
  ciba_request_object_signing_algorithm        = null
  ciba_require_signed_requests                 = null
  ciba_user_code_supported                     = null
  client_auth = {
    client_cert_issuer_dn     = null
    client_cert_subject_dn    = null
    enforce_replay_prevention = false
    secondary_secrets = [
    ]
    secret                                = null # sensitive
    token_endpoint_auth_signing_algorithm = null
    type                                  = "PRIVATE_KEY_JWT"
  }
  client_id                           = "demo-attest-eks"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtATM"
  }
  description                          = null
  device_flow_setting_type             = "SERVER_DEFAULT"
  device_polling_interval_override     = null
  enable_cookieless_authentication_api = false
  enabled                              = true
  exclusive_scopes                     = []
  extended_parameters = {
    attestation_bundle_url = {
      values = ["https://oidc.eks.ap-southeast-2.amazonaws.com/id/DE6B6D49900B87B9BF65A45D4822CD7D/keys"]
    }
    attestation_evidence = {
      values = ["eks-sa-token"]
    }
    attestation_evidence_issuer = {
      values = ["https://oidc.eks.ap-southeast-2.amazonaws.com/id/DE6B6D49900B87B9BF65A45D4822CD7D"]
    }
    attestation_instances = {
      values = ["[{\"spiffe_id\": \"spiffe://eks.demo.aws/ns/demo/sa/payment-agent\", \"entitlement\": [{\"type\": \"sales_agent\", \"actions\": [\"read_accounts\", \"create_opportunity\", \"submit_quote\"], \"sales_regions\": [\"EMEA\"]}], \"metadata\": {\"region\": \"EMEA\", \"environment\": \"eks\", \"attestor\": \"eks-irsa\"}}]"]
    }
    attestation_issued_ttl = {
      values = ["300"]
    }
    attestation_issuer = {
      values = ["https://attester.example.com"]
    }
    attestation_required = {
      values = ["true"]
    }
    attestation_signing_jwk = {
      values = ["{\"crv\":\"P-256\",\"d\":\"9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84\",\"kid\":\"mock-attester-1\",\"kty\":\"EC\",\"x\":\"c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag\",\"y\":\"ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI\"}"]
    }
    attestation_trust_domain = {
      values = ["eks.demo.aws"]
    }
  }
  grant_types = ["CLIENT_CREDENTIALS"]
  jwks_settings = {
    jwks = jsonencode({
      keys = [{
        alg = "ES256"
        crv = "P-256"
        kid = "cJ-4Fg9oUAar1TNoqvgJdERxxSZfTPnNiUJ_JT1Jvcc"
        kty = "EC"
        use = "sig"
        x   = "U-bngOnyFXIBhOTJzM_YpYqTHMJkH3tFPkOxUSHdCDk"
        y   = "l-8dfaxrOmY5MfiEg3r6-mnqhZxvXVDAuo9YEBfB0c8"
      }]
    })
    jwks_url = null
  }
  jwt_secured_authorization_response_mode_content_encryption_algorithm = null
  jwt_secured_authorization_response_mode_encryption_algorithm         = null
  jwt_secured_authorization_response_mode_signing_algorithm            = null
  lockout_max_malicious_actions                                        = null
  lockout_max_malicious_actions_type                                   = "SERVER_DEFAULT"
  logo_url                                                             = null
  name                                                                 = "Demo attester - EKS IRSA workload"
  offline_access_require_consent_prompt                                = "SERVER_DEFAULT"
  oidc_policy = {
    back_channel_logout_uri                         = null
    grant_access_session_revocation_api             = false
    grant_access_session_session_management_api     = false
    id_token_content_encryption_algorithm           = null
    id_token_encryption_algorithm                   = null
    id_token_signing_algorithm                      = null
    logout_mode                                     = "NONE"
    logout_uris                                     = null
    pairwise_identifier_user_type                   = false
    ping_access_logout_capable                      = false
    policy_group                                    = null
    post_logout_redirect_uris                       = null
    sector_identifier_uri                           = null
    user_info_response_content_encryption_algorithm = null
    user_info_response_encryption_algorithm         = null
    user_info_response_signing_algorithm            = null
  }
  pending_authorization_timeout_override               = null
  persistent_grant_expiration_type                     = "SERVER_DEFAULT"
  persistent_grant_idle_timeout                        = 0
  persistent_grant_idle_timeout_time_unit              = "DAYS"
  persistent_grant_idle_timeout_type                   = "SERVER_DEFAULT"
  persistent_grant_reuse_grant_types                   = []
  persistent_grant_reuse_type                          = "SERVER_DEFAULT"
  redirect_uris                                        = []
  refresh_rolling                                      = "SERVER_DEFAULT"
  refresh_token_rolling_grace_period                   = null
  refresh_token_rolling_grace_period_type              = "SERVER_DEFAULT"
  refresh_token_rolling_interval                       = null
  refresh_token_rolling_interval_type                  = "SERVER_DEFAULT"
  request_object_signing_algorithm                     = null
  request_policy_ref                                   = null
  require_dpop                                         = false
  require_jwt_secured_authorization_response_mode      = false
  require_offline_access_scope_to_issue_refresh_tokens = "SERVER_DEFAULT"
  require_proof_key_for_code_exchange                  = false
  require_pushed_authorization_requests                = false
  require_signed_requests                              = false
  restrict_scopes                                      = false
  restrict_to_default_access_token_manager             = true
  restricted_response_types                            = []
  restricted_scopes                                    = []
  token_exchange_processor_policy_ref                  = null
  token_introspection_content_encryption_algorithm     = null
  token_introspection_encryption_algorithm             = null
  token_introspection_signing_algorithm                = null
  user_authorization_url_override                      = null
  validate_using_all_eligible_atms                     = false
}

# __generated__ by Terraform from "demo-attest-agentcore"
resource "pingfederate_oauth_client" "demo_attest_agentcore" {
  allow_authentication_api_init                = false
  authorization_detail_types                   = []
  bypass_activation_code_confirmation_override = null
  bypass_approval_page                         = true
  ciba_delivery_mode                           = null
  ciba_notification_endpoint                   = null
  ciba_polling_interval                        = null
  ciba_request_object_signing_algorithm        = null
  ciba_require_signed_requests                 = null
  ciba_user_code_supported                     = null
  client_auth = {
    client_cert_issuer_dn     = null
    client_cert_subject_dn    = null
    enforce_replay_prevention = false
    secondary_secrets = [
    ]
    secret                                = null # sensitive
    token_endpoint_auth_signing_algorithm = null
    type                                  = "PRIVATE_KEY_JWT"
  }
  client_id                           = "demo-attest-agentcore"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtATM"
  }
  description                          = null
  device_flow_setting_type             = "SERVER_DEFAULT"
  device_polling_interval_override     = null
  enable_cookieless_authentication_api = false
  enabled                              = true
  exclusive_scopes                     = []
  extended_parameters = {
    attestation_bundle_url = {
      values = ["https://a188ffe2-94b1-49e6-a35a-a937a3f68d5b.tokens.sts.global.api.aws/.well-known/jwks.json"]
    }
    attestation_evidence = {
      values = ["aws-sts-web-identity"]
    }
    attestation_evidence_issuer = {
      values = ["https://a188ffe2-94b1-49e6-a35a-a937a3f68d5b.tokens.sts.global.api.aws"]
    }
    attestation_instances = {
      values = ["[{\"entitlement\":[{\"actions\":[\"read_accounts\",\"create_opportunity\",\"submit_quote\"],\"sales_regions\":[\"EMEA\"],\"type\":\"sales_agent\"}],\"metadata\":{\"attestor\":\"aws-outbound-identity-federation\",\"environment\":\"agentcore\",\"region\":\"EMEA\"},\"spiffe_id\":\"spiffe://971422710168.aws.demo/aws/971422710168/role/agentcore-attest-demo\"}]"]
    }
    attestation_issued_ttl = {
      values = ["300"]
    }
    attestation_issuer = {
      values = ["https://attester.example.com"]
    }
    attestation_required = {
      values = ["true"]
    }
    attestation_signing_jwk = {
      values = ["{\"crv\":\"P-256\",\"d\":\"9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84\",\"kid\":\"mock-attester-1\",\"kty\":\"EC\",\"x\":\"c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag\",\"y\":\"ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI\"}"]
    }
    attestation_trust_domain = {
      values = ["971422710168.aws.demo"]
    }
  }
  grant_types = ["CLIENT_CREDENTIALS", "TOKEN_EXCHANGE"]
  jwks_settings = {
    jwks = jsonencode({
      keys = [{
        alg = "ES256"
        crv = "P-256"
        kid = "cJ-4Fg9oUAar1TNoqvgJdERxxSZfTPnNiUJ_JT1Jvcc"
        kty = "EC"
        use = "sig"
        x   = "U-bngOnyFXIBhOTJzM_YpYqTHMJkH3tFPkOxUSHdCDk"
        y   = "l-8dfaxrOmY5MfiEg3r6-mnqhZxvXVDAuo9YEBfB0c8"
      }]
    })
    jwks_url = null
  }
  jwt_secured_authorization_response_mode_content_encryption_algorithm = null
  jwt_secured_authorization_response_mode_encryption_algorithm         = null
  jwt_secured_authorization_response_mode_signing_algorithm            = null
  lockout_max_malicious_actions                                        = null
  lockout_max_malicious_actions_type                                   = "SERVER_DEFAULT"
  logo_url                                                             = null
  name                                                                 = "Demo attester - Bedrock AgentCore agent"
  offline_access_require_consent_prompt                                = "SERVER_DEFAULT"
  oidc_policy = {
    back_channel_logout_uri                         = null
    grant_access_session_revocation_api             = false
    grant_access_session_session_management_api     = false
    id_token_content_encryption_algorithm           = null
    id_token_encryption_algorithm                   = null
    id_token_signing_algorithm                      = null
    logout_mode                                     = "NONE"
    logout_uris                                     = null
    pairwise_identifier_user_type                   = false
    ping_access_logout_capable                      = false
    policy_group                                    = null
    post_logout_redirect_uris                       = null
    sector_identifier_uri                           = null
    user_info_response_content_encryption_algorithm = null
    user_info_response_encryption_algorithm         = null
    user_info_response_signing_algorithm            = null
  }
  pending_authorization_timeout_override               = null
  persistent_grant_expiration_type                     = "SERVER_DEFAULT"
  persistent_grant_idle_timeout                        = 0
  persistent_grant_idle_timeout_time_unit              = "DAYS"
  persistent_grant_idle_timeout_type                   = "SERVER_DEFAULT"
  persistent_grant_reuse_grant_types                   = []
  persistent_grant_reuse_type                          = "SERVER_DEFAULT"
  redirect_uris                                        = []
  refresh_rolling                                      = "SERVER_DEFAULT"
  refresh_token_rolling_grace_period                   = null
  refresh_token_rolling_grace_period_type              = "SERVER_DEFAULT"
  refresh_token_rolling_interval                       = null
  refresh_token_rolling_interval_type                  = "SERVER_DEFAULT"
  request_object_signing_algorithm                     = null
  request_policy_ref                                   = null
  require_dpop                                         = false
  require_jwt_secured_authorization_response_mode      = false
  require_offline_access_scope_to_issue_refresh_tokens = "SERVER_DEFAULT"
  require_proof_key_for_code_exchange                  = false
  require_pushed_authorization_requests                = false
  require_signed_requests                              = false
  restrict_scopes                                      = false
  restrict_to_default_access_token_manager             = true
  restricted_response_types                            = []
  restricted_scopes                                    = []
  token_exchange_processor_policy_ref                  = null
  token_introspection_content_encryption_algorithm     = null
  token_introspection_encryption_algorithm             = null
  token_introspection_signing_algorithm                = null
  user_authorization_url_override                      = null
  validate_using_all_eligible_atms                     = false
}

# __generated__ by Terraform from "demo-attest-gke-native"
resource "pingfederate_oauth_client" "demo_attest_gke_native" {
  allow_authentication_api_init                = false
  authorization_detail_types                   = []
  bypass_activation_code_confirmation_override = null
  bypass_approval_page                         = true
  ciba_delivery_mode                           = null
  ciba_notification_endpoint                   = null
  ciba_polling_interval                        = null
  ciba_request_object_signing_algorithm        = null
  ciba_require_signed_requests                 = null
  ciba_user_code_supported                     = null
  client_auth = {
    client_cert_issuer_dn     = null
    client_cert_subject_dn    = null
    encrypted_secret          = "OBF:JWE:eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiR3NHNmFxWUJhTyIsInZlcnNpb24iOiIxMy4wLjMuMCJ9..CkyFIWEReOXtB7nrBNYWUw.kFkl-1pwS4n8tyeHwHOA5-iPGcD85GrrfpmyOWuXtSfvzER3IKaan1JpM-4Hm912hU-yAlw8mJhaZFGzEEDITRAwChb9Pxf-zBLCr84DLZQ.FeD5KGcKUKgBctPuR0wTvg"
    enforce_replay_prevention = false
    secondary_secrets = [
    ]
    secret                                = null # sensitive
    token_endpoint_auth_signing_algorithm = null
    type                                  = "PRIVATE_KEY_JWT"
  }
  client_id                           = "demo-attest-gke-native"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtATM"
  }
  description                          = null
  device_flow_setting_type             = "SERVER_DEFAULT"
  device_polling_interval_override     = null
  enable_cookieless_authentication_api = false
  enabled                              = true
  exclusive_scopes                     = []
  extended_parameters = {
    attestation_bundle_url = {
      values = ["https://container.googleapis.com/v1/projects/pf-spiffe-demo-4412/locations/us-east1-b/clusters/spiffe-demo-e/jwks"]
    }
    attestation_evidence = {
      values = ["gke-sa-token"]
    }
    attestation_evidence_issuer = {
      values = ["https://container.googleapis.com/v1/projects/pf-spiffe-demo-4412/locations/us-east1-b/clusters/spiffe-demo-e"]
    }
    attestation_instances = {
      values = ["[{\"entitlement\":[{\"actions\":[\"read_accounts\",\"create_opportunity\",\"submit_quote\"],\"sales_regions\":[\"EMEA\"],\"type\":\"sales_agent\"}],\"metadata\":{\"attestor\":\"gke-workload-identity\",\"environment\":\"gke\",\"region\":\"EMEA\"},\"spiffe_id\":\"spiffe://pf-spiffe-demo-4412.svc.id.goog/ns/demo/sa/payment-agent\"}]"]
    }
    attestation_issued_ttl = {
      values = ["300"]
    }
    attestation_issuer = {
      values = ["https://attester.example.com"]
    }
    attestation_required = {
      values = ["true"]
    }
    attestation_signing_jwk = {
      values = ["{\"crv\":\"P-256\",\"d\":\"9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84\",\"kid\":\"mock-attester-1\",\"kty\":\"EC\",\"x\":\"c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag\",\"y\":\"ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI\"}"]
    }
    attestation_trust_domain = {
      values = ["pf-spiffe-demo-4412.svc.id.goog"]
    }
  }
  grant_types = ["CLIENT_CREDENTIALS", "TOKEN_EXCHANGE"]
  jwks_settings = {
    jwks = jsonencode({
      keys = [{
        alg = "ES256"
        crv = "P-256"
        kid = "cJ-4Fg9oUAar1TNoqvgJdERxxSZfTPnNiUJ_JT1Jvcc"
        kty = "EC"
        use = "sig"
        x   = "U-bngOnyFXIBhOTJzM_YpYqTHMJkH3tFPkOxUSHdCDk"
        y   = "l-8dfaxrOmY5MfiEg3r6-mnqhZxvXVDAuo9YEBfB0c8"
      }]
    })
    jwks_url = null
  }
  jwt_secured_authorization_response_mode_content_encryption_algorithm = null
  jwt_secured_authorization_response_mode_encryption_algorithm         = null
  jwt_secured_authorization_response_mode_signing_algorithm            = null
  lockout_max_malicious_actions                                        = null
  lockout_max_malicious_actions_type                                   = "SERVER_DEFAULT"
  logo_url                                                             = null
  name                                                                 = "Demo attester — GKE native identity"
  offline_access_require_consent_prompt                                = "SERVER_DEFAULT"
  oidc_policy = {
    back_channel_logout_uri                         = null
    grant_access_session_revocation_api             = false
    grant_access_session_session_management_api     = false
    id_token_content_encryption_algorithm           = null
    id_token_encryption_algorithm                   = null
    id_token_signing_algorithm                      = null
    logout_mode                                     = "NONE"
    logout_uris                                     = null
    pairwise_identifier_user_type                   = false
    ping_access_logout_capable                      = false
    policy_group                                    = null
    post_logout_redirect_uris                       = null
    sector_identifier_uri                           = null
    user_info_response_content_encryption_algorithm = null
    user_info_response_encryption_algorithm         = null
    user_info_response_signing_algorithm            = null
  }
  pending_authorization_timeout_override               = null
  persistent_grant_expiration_type                     = "SERVER_DEFAULT"
  persistent_grant_idle_timeout                        = 0
  persistent_grant_idle_timeout_time_unit              = "DAYS"
  persistent_grant_idle_timeout_type                   = "SERVER_DEFAULT"
  persistent_grant_reuse_grant_types                   = []
  persistent_grant_reuse_type                          = "SERVER_DEFAULT"
  redirect_uris                                        = []
  refresh_rolling                                      = "SERVER_DEFAULT"
  refresh_token_rolling_grace_period                   = null
  refresh_token_rolling_grace_period_type              = "SERVER_DEFAULT"
  refresh_token_rolling_interval                       = null
  refresh_token_rolling_interval_type                  = "SERVER_DEFAULT"
  request_object_signing_algorithm                     = null
  request_policy_ref                                   = null
  require_dpop                                         = false
  require_jwt_secured_authorization_response_mode      = false
  require_offline_access_scope_to_issue_refresh_tokens = "SERVER_DEFAULT"
  require_proof_key_for_code_exchange                  = false
  require_pushed_authorization_requests                = false
  require_signed_requests                              = false
  restrict_scopes                                      = false
  restrict_to_default_access_token_manager             = true
  restricted_response_types                            = []
  restricted_scopes                                    = []
  token_exchange_processor_policy_ref                  = null
  token_introspection_content_encryption_algorithm     = null
  token_introspection_encryption_algorithm             = null
  token_introspection_signing_algorithm                = null
  user_authorization_url_override                      = null
  validate_using_all_eligible_atms                     = false
}
