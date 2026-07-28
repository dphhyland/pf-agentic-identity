# Adopt the three live attestation clients this exchange plane touches. Bodies live in
# adopted-clients.tf (generated from the running PF, then edited); clients.tf.example is the
# original authoring template, kept for the extended-parameter documentation.
import {
  to = pingfederate_oauth_client.demo_attest_eks
  id = "demo-attest-eks"
}
import {
  to = pingfederate_oauth_client.demo_attest_agentcore
  id = "demo-attest-agentcore"
}
import {
  to = pingfederate_oauth_client.demo_attest_gke_native
  id = "demo-attest-gke-native"
}
