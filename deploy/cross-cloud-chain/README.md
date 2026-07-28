# Cross-cloud agent chain

Four services and one resource, spanning GCP and AWS. A single call to agent A drives a request
through three agents in two clouds and into a resource server that can prove who asked for what.

```
A  GKE, ns demo, SA payment-agent      client demo-attest-gke-native     gets its own token (GKE AS)
     │  invokes over the AWS API (AgentCore is reachable only that way)
B  Bedrock AgentCore Runtime           client demo-attest-agentcore      exchanges A's token at the GKE AS
     │  HTTP
C  GKE, ns demo, SA delivery-agent     client demo-attest-gke-delivery   exchanges B's token at the EKS AS
     │  HTTP, Bearer
R  mock resource on EKS                                                  verifies + decides
```

Every agent authenticates the same way and never holds a secret: it proves what it is with platform
evidence (GKE projected SA token / AWS `sts:GetWebIdentityToken`), turns that into a Client
Attestation **at its own local attester**, and presents that attestation to whichever Authorization
Server it needs — its own cloud's or the other one's. The attestation is portable; only the PoP is
minted per target, from the audience that target advertises in
`/.well-known/client-attester`.

Each exchange adds one layer to the RFC 8693 actor chain, so the token that reaches the resource
reads: `sub` = the workload the request started from, `act` = `{C, {B, {A}}}`.

## Run it

```sh
curl -s -X POST http://<agent-a-ip>/run | jq
```

The response carries a per-hop trace (which client, which AS, the resulting token claims) and the
resource's decision.

## What the resource does

Verifies the token against the issuer's published keys, walks the `act` chain, and authorizes. The
decision goes to a PingAuthorize AuthZEN PDP when `AUTHZEN_PDP_URL` is set — use the **native
(servlet) AuthZEN adapter** — and otherwise falls to a built-in rule so the demo runs without a PDP.
Both paths get identical inputs (subject, action, resource, actor chain as context).

Verified rejections: no token (401); a token from an issuer this resource does not trust (401);
a tampered signature (401, "signature does not verify"); and a valid token from the right issuer
whose final actor is not the expected delegate (403) — the case that matters, because it is a real
token being presented by a party that was never delegated to.

## Deploy

Images are layered on the existing demo images so they build as a COPY rather than a
cross-architecture `pip install` (which takes many minutes under emulation on an arm64 laptop):
`chain-agent` on the GKE agent image, `mock-resource` on `eks-workload`, agent B on
`agentcore-agent` (arm64).

`k8s/` holds the manifests; substitute IMAGE_*, EKS_PF_URL, RESOURCE_URL and AGENTCORE_ARN_VALUE.
Agent A additionally needs the `aws-invoke` secret (an access key used only to reach the AgentCore
control API — the transport to B, not an identity credential).
