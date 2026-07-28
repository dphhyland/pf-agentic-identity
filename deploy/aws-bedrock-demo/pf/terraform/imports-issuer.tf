# Adopt the JWT access-token manager and the local subject-token processor so EKS-issued tokens
# carry `iss` = this PF's public issuer, and local subject tokens validate against it. Mirrors
# deploy/gke-spiffe-demo/pf/terraform/imports-issuer.tf — see there for the "Invalid Issuer" story.
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_atm
  id = "attestJwtATM"
}
import {
  to = pingfederate_idp_token_processor.subject_jwt_proc
  id = "subjectJwtProc"
}
