# Azure AKS + Entra Agent ID demo

The Azure leg of the cross-cloud rig, alongside `deploy/gke-spiffe-demo` and `deploy/aws-bedrock-demo`.
Same attester and `ClientAttestationAuthFilter` model as both — the new server-side code is two Azure
evidence validators (`AksWorkloadIdentityValidator`, `AzureManagedIdentityValidator`) plus one genuinely
new capability neither of the other two clouds needed: an **`AssertedContextResolver`** second-stage SPI
(`EntraDirectoryAssertedContextResolver`) and an **A2A-fronted gateway** that uses it.

## Two evidence paths, plus one asserted-context narrowing

| Path | Evidence | Validated against | SPIFFE ID |
|---|---|---|---|
| **AKS workload** (`aks-sa-token`) | Workload Identity Federation projected SA token | the cluster OIDC JWKS (`<issuer>openid/v1/jwks`) | `spiffe://<aks-td>/ns/demo/sa/gateway-agent` |
| **Azure Container Apps / VM / Functions** (`azure-mi-token`) | Entra-signed managed-identity token via IMDS | the tenant's JWKS (`login.microsoftonline.com/<tenant>/discovery/v2.0/keys`) | `spiffe://<azure-mi-td>/azure/mi/<oid>` |

Why two, mirroring GCP's `gke-sa-token`/`gcp-id-token` split and AWS's `eks-sa-token`/`aws-sts-web-identity`
split: AKS's path is the direct K8s-projected-token analogue of GKE/EKS; the managed-identity path covers
Azure compute that isn't Kubernetes at all (Container Apps, VMs, Functions) — the shape GCP's Agent Engine
and AWS's Bedrock AgentCore cover on their clouds.

**Why this leaf isn't just "Azure's version of the same two-path pattern."** Copilot Studio agents share
**one Microsoft-owned blueprint per tenant** — unlike a GKE/EKS/AKS pod or a Bedrock AgentCore execution
role, an individual Copilot agent has **no cryptographic evidence of its own**, not even the fallback
"hosting workload's own credential" trick AgentCore and Agent Engine both use elsewhere in this rig (see
`deploy/aws-bedrock-demo/agentcore/agent.py`'s docstring and `deploy/gke-spiffe-demo/agent-engine/agent.py`
for that pattern). The only real evidence obtainable here is for the **workload hosting the gateway**
(`azure-mi-token`, above) — the Copilot agent's own identity can only ever be **asserted** (unverified
caller-supplied metadata) on top of that one evidenced identity.

That is what `AssertedContextResolver` (`servlets/attestation-issuer`) and
`EntraDirectoryAssertedContextResolver` add: a second-stage hook, opt-in per client
(`attestation_asserted_context_resolver`), that runs *after* evidence validation succeeds and resolves an
asserted Entra Agent ID `oid` against a directory (`OIDF_ENTRA_AGENT_DIRECTORY`, a servlet-level env var —
see the attester's own deployment config, not a per-client PF property) to **narrow** — never extend — the
evidenced client's ceiling. `agent-runtime/gateway.py` is the A2A (Agent2Agent) front door that threads a
caller-asserted `copilot_agent_id` into that resolver on each `message/send`; A2A itself is new to this
repo (every other cross-agent hop uses plain HTTP+Bearer — see `deploy/cross-cloud-chain/`).

## Prerequisites (what's needed before this can actually deploy)

1. **Azure subscription** with a principal that can create AKS clusters, ACR, Container Apps, and managed
   identities. Starting role: `Contributor` on a dedicated resource group (tighten later).
2. **Region** with AKS + Container Apps availability (default `australiaeast` in `azure/bootstrap.sh`).
3. No account-level one-time enable step is needed (unlike AWS's Outbound Identity Federation) — AKS
   Workload Identity Federation (`--enable-oidc-issuer --enable-workload-identity`) and managed identities
   are both per-resource, created directly by `azure/bootstrap.sh`.
4. The gateway's managed identity needs no special role assignment for attestation itself (IMDS is ambient
   on any Azure compute the identity is attached to) — only whatever downstream resource access the demo
   eventually wants to grant it.

## Deploy (when an Azure subscription is opened — **not yet run**)

```sh
# 1. Azure side: AKS (OIDC issuer + workload identity), ACR, gateway managed identity, Container Apps env.
./azure/bootstrap.sh
# prints AKS_CLUSTER_ISSUER, AKS_JWKS_URL, AZURE_TENANT_ID, GATEWAY_IDENTITY_OID/CLIENT_ID, ACR_LOGIN_SERVER

# 2. PingFederate on AKS — reuse the baked-config image from the GKE build, or rebuild from
#    deploy/pingfederate. Same manifests as deploy/gke-spiffe-demo/pf, plus the pf-bridge-key secret
#    (azure/bootstrap.sh copies it from a running GKE cluster when GKE_CONTEXT is set).

# 3. Terraform: the two Azure clients (private_key_jwt + bridge). Copy the shared PF config files
#    (extended-properties, attestJwtATM ATM, the client_credentials access-token mapping) from
#    deploy/gke-spiffe-demo/pf/terraform, fold in pf/terraform/extended-properties-addition.tf.example
#    (registers attestation_asserted_context_resolver — required before demo_attest_azure_gateway's
#    opt-in takes effect), copy pf/terraform/clients.tf.example to clients.tf, then:
cd pf/terraform
export TF_VAR_pf_admin_password=... TF_VAR_bridge_public_jwks="$(cat ../../bridge-public.jwks)"
export TF_VAR_attester_signing_jwk="$(cat ../../attester-signing.jwk)"
export TF_VAR_aks_cluster_issuer="$AKS_CLUSTER_ISSUER" TF_VAR_aks_jwks_url="$AKS_JWKS_URL"
export TF_VAR_azure_tenant_id="$AZURE_TENANT_ID" TF_VAR_azure_mi_trust_domain="${AZURE_TENANT_ID}.azure.demo"
export TF_VAR_agent_execution_identity_oid="$GATEWAY_IDENTITY_OID"
terraform init && terraform apply

# 4. Set the attester's OWN directory env var (servlet-level, not a PF client property) so
#    entra-directory has something to resolve. Shape: EntraDirectoryAssertedContextResolver's javadoc.
#    On the PF pod hosting the attester: OIDF_ENTRA_AGENT_DIRECTORY='{"<oid>": {"display_name": "...",
#    "groups": [...], "ceiling": [...]}}'

# 5. AKS workload (plain evidence, no A2A)
docker build -t $ACR_LOGIN_SERVER/aks-workload workload && docker push $ACR_LOGIN_SERVER/aks-workload
sed "s#IMAGE#$ACR_LOGIN_SERVER/aks-workload#" workload/workload.yaml | kubectl apply -f -

# 6. Azure Container Apps gateway (A2A-fronted, asserted-context-aware)
docker build -t $ACR_LOGIN_SERVER/azure-gateway agent-runtime && docker push $ACR_LOGIN_SERVER/azure-gateway
az containerapp create --name azure-gateway --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINERAPPS_ENV" --image "$ACR_LOGIN_SERVER/azure-gateway" \
  --user-assigned "$GATEWAY_IDENTITY_CLIENT_ID" --registry-server "$ACR_LOGIN_SERVER" \
  --env-vars ATTESTER_BASE_URL=http://pingfederate.pf.svc.cluster.local:9080 \
  --ingress external --target-port 8080
```

## Verify (once deployed)

```sh
# AKS path
kubectl -n demo exec deploy/gateway-agent -- \
  sh -c 'python3 -c "import app,json;print(json.dumps(app.invoke(),indent=2))"'
#   → mint_status 200, pf_status 200, sub = spiffe://<aks-td>/ns/demo/sa/gateway-agent

# Azure Container Apps gateway, over A2A — no asserted context (Track A: the gateway's own identity)
curl -s "$GATEWAY_URL/a2a" -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": "1", "method": "message/send",
  "params": {"message": {"role": "user", "messageId": "m1", "parts": []}}}'
#   → attested=true, sub = spiffe://<azure-mi-td>/azure/mi/<oid>, no asserted_context

# Same, WITH an asserted Entra Agent ID (Track B: narrowed by the directory)
curl -s "$GATEWAY_URL/a2a" -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": "2", "method": "message/send",
  "params": {"message": {"role": "user", "messageId": "m2",
    "metadata": {"copilot_agent_id": "<oid registered in OIDF_ENTRA_AGENT_DIRECTORY>"}, "parts": []}}}'
#   → attested=true, workload.attributes.asserted present, authorization_details narrowed to the
#     directory entry's ceiling (never broader than the gateway's own evidenced ceiling)
```

Negatives to demonstrate (same as GKE/AWS): over-ceiling request → 403, replayed proof → 401, wrong
audience → 401, no attestation headers → PF rejects the credential-less request. Azure-specific: an
`asserted_context` oid absent from the directory → `access_denied`; a client that opts into an
unregistered resolver id → `invalid_client` (fails closed, never silently ignored).

## Status

**Code-complete, deployment deliberately not started** — per explicit instruction, this leaf is designed
and built now (validators, SDK evidence source, the asserted-context SPI, the A2A gateway, this deploy
tree) but no `az`/Terraform command has been run against a real subscription. What *is* verified, without
any cloud dependency:

- `servlets/attestation-issuer`: 151/151 tests pass (`mvn test`), including
  `AksWorkloadIdentityValidatorTest`, `AzureManagedIdentityValidatorTest`,
  `EntraDirectoryAssertedContextResolverTest`, and `AttestationIssuanceServletTest`'s asserted-context
  cases (ceiling narrowing, unknown-oid denial, fail-closed on an unregistered resolver, and a regression
  guard proving every existing GCP/AWS/wallet client is completely unaffected).
- `client-attestation-sdk-polyglot` (Python): 75/75 tests pass, including `AzureImdsSvidSource`'s
  JSON-envelope parsing (the one place Azure's evidence format genuinely differs from GCP's) and
  `ClientAttestation.token(asserted_context=...)`'s never-cached behavior.
- `agent-runtime/gateway.py`: a standalone functional smoke test (fake attester + fake PF token endpoint,
  real HTTP against the gateway's own server) proves the agent card, Track A (no asserted context), and
  Track B (asserted Copilot-agent oid → narrowed ceiling, two distinct mints, never cached) all work
  end to end.
- `terraform validate` passes for `variables.tf`/`provider.tf`/`versions.tf`, and for `clients.tf.example`
  against the real provider schema (validated in a scratch copy with the shared
  `pingfederate_extended_properties.props` resource stubbed, since that file is deliberately not
  self-contained — see its own header comment).

- `../cross-cloud-chain/azure/test_agent_d.py`: 22/22 checks pass — the Azure chain agent (below) driven
  over real HTTP against a fake attester/AS/resource, covering both evidence paths, the asserted-context
  narrowing, refusal of an unknown oid, and the four-deep act chain.

Once an Azure subscription is opened: run `azure/bootstrap.sh` for real (it has NOT been exercised against
live Azure — treat it as a strong first draft, not battle-tested, unlike the GKE/AWS scripts which were
proven via a full teardown-and-rebuild pass), wire the two Terraform clients in, set
`OIDF_ENTRA_AGENT_DIRECTORY` on the attester, deploy the workload + gateway, and this README's Verify
section becomes real curl output instead of expected shape.

## The cross-cloud chain leg

The third-cloud leg of the interop demo is already written:
[`../cross-cloud-chain/deploy-azure-leg.sh`](../cross-cloud-chain/deploy-azure-leg.sh) inserts an Azure
agent between the existing GKE and AWS chain and the resource, taking the RFC 8693 actor chain four deep
across three clouds — and carrying the asserted Entra Agent ID narrowing mid-delegation, which is the one
thing neither of the other two clouds can demonstrate. It is code-complete and offline-tested, waiting on
the same subscription. See [that README](../cross-cloud-chain/README.md#the-azure-leg-optional-third-cloud).
