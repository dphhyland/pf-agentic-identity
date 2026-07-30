# Adopt the attestation clients. They arrive via the baked config archive on any PF built from the
# image, so a terraform run with fresh state must IMPORT them, not create them - otherwise every one
# fails with "Client ID is already in use" (found during the 2026-07-30 full rebuild).
#
# recover-config.sh strips these blocks for the genuine from-zero case, where nothing pre-exists.
import {
  to = pingfederate_oauth_client.demo_attest_gke
  id = "demo-attest-gke"
}
import {
  to = pingfederate_oauth_client.demo_attest_gke_native[0]
  id = "demo-attest-gke-native"
}
import {
  to = pingfederate_oauth_client.demo_attest_gke_delivery[0]
  id = "demo-attest-gke-delivery"
}
import {
  to = pingfederate_oauth_client.demo_attest_agent_engine[0]
  id = "demo-attest-agent-engine"
}
import {
  to = pingfederate_oauth_client.demo_attest_agentcore
  id = "demo-attest-agentcore"
}
import {
  to = pingfederate_oauth_client.demo_attest_railway
  id = "demo-attest-railway"
}
