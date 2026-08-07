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

An optional **third cloud** slots in between C and the resource — see
[the Azure leg](#the-azure-leg-optional-third-cloud) below.

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

## The Azure leg (optional third cloud)

`./deploy-azure-leg.sh` inserts a fourth agent, on Azure, between C and the resource:

```
… C  GKE delivery-agent      exchanges B's token at the EKS AS
     │  HTTP, Bearer
  D  AKS or Azure Container Apps   client demo-attest-aks-chain   exchanges C's token at EXCHANGE_PF_URL
     │  HTTP, Bearer
  R  mock resource                                                verifies + decides
```

The act chain that reaches the resource then nests four deep — `{D, {C, {B, {A}}}}` — with `sub` still
naming the GKE workload the whole thing started from, across three clouds.

**D is a transparent interposer.** It accepts exactly the call C already makes to the resource
(`Authorization: Bearer` + the request body) and makes exactly the call the resource already expects,
so inserting it needs no change to any existing agent — only rewiring, which the script does: C's
`NEXT_HOP_URL` moves to D, and the resource's `TRUSTED_ISSUER`/`REQUIRED_FINAL_ACTOR` move to the AS D
exchanges at and to D's client id. Re-running `./deploy.sh` puts both back, which is the back-out path.

Point `EXCHANGE_PF_URL` at the **Azure** PF for a genuine three-AS chain (the resource then trusts the
Azure AS), or at the **EKS** PF to leave the resource's trust pinning exactly as it was — D still
attests in Azure either way, which is the part that matters.

**What only this leg can show.** Copilot Studio agents share one Microsoft-owned blueprint per tenant,
so an individual Copilot agent has no cryptographic evidence of its own — only the workload hosting D
does. Its identity can therefore only be *asserted*. Give D an asserted Entra Agent ID (per-request
`X-Copilot-Agent-Id`, or the `ASSERTED_COPILOT_AGENT_ID` default) and it sends that as
`asserted_context` on its mint; the attester's `EntraDirectoryAssertedContextResolver` resolves it
against `OIDF_ENTRA_AGENT_DIRECTORY` and **narrows — never extends** — what D is entitled to. So the
narrowing lands mid-delegation, on a real chain, rather than as a special case at the edge. D's trace
reports the evidenced ceiling and the asserted block separately, so which half is proven stays legible.

Background on the validators and the resolver: [`../azure-aks-demo`](../azure-aks-demo/README.md).

**Status: not yet run.** No Azure subscription has been opened, so unlike everything above, this leg
has never touched live infrastructure. What is verified is `azure/test_agent_d.py` — an offline test
(fake attester, fake AS, fake resource, real HTTP against the agent) covering both evidence paths, the
asserted-context narrowing, an unknown oid being refused, the four-deep act chain, and the
interposer contract. Run it with `python3 azure/test_agent_d.py`.
