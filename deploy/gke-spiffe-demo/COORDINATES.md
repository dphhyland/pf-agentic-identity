# Live coordinates

Rebuilt 2026-07-30 from scratch (full project deletion + rebuild).

| | |
|---|---|
| GCP project | `pf-spiffe-demo-4412` |
| Cluster | `spiffe-demo-e` (us-east1-b) — us-central1 was stocked out |
| kubectl context | `gke_pf-spiffe-demo-4412_us-east1-b_spiffe-demo-e` |
| Trust domain | `pf-spiffe-demo-4412.svc.id.goog` |
| Registry | `us-central1-docker.pkg.dev/pf-spiffe-demo-4412/demo` |
| GKE PF / federation anchor | http://34.138.163.107 |
| Chain agent A (demo console) | http://35.196.205.152 |
| Chain agent C | http://104.196.159.49 |
| EKS PF (federation leaf) | http://ae546b15c1b884e858e24d0c021d7e20-548341687.ap-southeast-2.elb.amazonaws.com |
| EKS cluster | `attest-demo` (ap-southeast-2), OIDC id `DE6B6D49900B87B9BF65A45D4822CD7D` |
| Mock resource | http://a5d9618937ebc4b8e8b831f99000f5e8-1804855991.ap-southeast-2.elb.amazonaws.com |
| AgentCore runtime | `attest_demo_agent-Vg5f0w4y4J` |

Images: GKE `pingfederate:rebuild2`, `agent:rebuild`, `chain-agent:rebuild`;
AWS `pingfederate:rebuild2`, `agentcore-agent:chain-v2`, `mock-resource:v1`.

**The published explainers still reference the old project and IPs.** They need updating before
this is shown.
