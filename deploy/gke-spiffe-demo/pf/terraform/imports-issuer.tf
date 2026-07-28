# Adopt the JWT access-token manager and the local subject-token processor so the issued tokens
# carry an `iss` claim (the PF's public issuer) and the exchange plane validates it. Without a
# stamped issuer the JWT token processor rejects every subject token with "Invalid Issuer" — and
# tokens without iss/aud are bearer-valid everywhere, so this is also the hardening fix.
# Bodies in adopted-issuer.tf (generated from the running PF, then the two issuer fields set).
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_atm
  id = "attestJwtATM"
}
import {
  to = pingfederate_idp_token_processor.subject_jwt_proc
  id = "subjectJwtProc"
}
