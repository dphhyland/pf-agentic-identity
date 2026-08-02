# Standing the demo back up from nothing

Everything is torn down as of 2026-08-02 — no GCP project, no EKS cluster, no AgentCore runtime, no
IAM role, no load balancers, no charges on either cloud. This is the guide to bring it all back.

## What this is, in one paragraph

A workload on GKE and a workload on EKS both authenticate to PingFederate using an identity token
their own cloud already issues them — no client secret, no provisioned credential. Each platform's
evidence goes to an attestation-issuer servlet, which turns it into a portable Client Attestation
(draft-ietf-oauth-attestation-based-client-auth). That attestation can be presented to *either* cloud's
PingFederate, because the two PFs are joined by an OpenID Federation trust chain — one PF is the
anchor, the other a leaf, and each vouches for its own attester's keys through the chain rather than a
pasted-in trust file. On top of that, four agents (two on GKE, one a real Bedrock AgentCore Runtime
agent, plus a mock resource on EKS) chain RFC 8693 token exchanges across both clouds, so a token
arriving at the resource carries `sub` = the workload that started the chain and a nested `act` claim
naming every agent that has handled it since — delegation, not impersonation, verifiable end to end.

## What you need before starting

- `gcloud`, `aws` CLI, `eksctl`, `kubectl`, `docker`, `terraform`, `mvn` (Maven 3.9+)
- A GCP billing account you can link, and an AWS account/profile with admin rights
- A python venv with a current `boto3` — `python3 -m venv /private/tmp/aws-venv && /private/tmp/aws-venv/bin/pip install -U boto3`.
  Every script that touches AWS checks this at startup and refuses to proceed with a clear message if
  it's broken; don't skip rebuilding it if a script tells you to.
- The repo's gitignored secrets, if you still have them from before: `deploy/pingfederate/overlay/`
  (the PF master key + system keys) and a saved `data.zip`. **If you don't have these, that's fine —
  see "No saved secrets?" below, it's the normal case after a project deletion anyway.**

Budget half a day, almost all of it waiting on cluster creation and Docker builds, not active work.

## No saved secrets? Read this first

If the old GCP project was deleted, its SPIFFE trust domain (`<project>.svc.id.goog`) is gone with it
— a rebuild always lands on a *new* project id, therefore a *new* trust domain, therefore every
`attestation_trust_domain`, `spiffe_id` binding, and evidence issuer in the config has to be rebuilt
too. There is no "restore the old config" path across a project change. This guide assumes exactly
that: starting genuinely from zero, generating a fresh bridge key and fresh terraform state. See
`aws-bedrock-demo/RECOVERY.md` for the full detail on *why* — it's worth reading once, not because the
steps below hide anything, but because the reasons matter when something doesn't match this guide.

## Order

```
1. GCP project + GKE cluster           gke-spiffe-demo/gcp/bootstrap.sh
2. Bridge key + attester key           gke-spiffe-demo/pf/gen-bridge-key.sh (+ manual attester key)
3. Deploy PingFederate to GKE          kubectl apply, no config baked yet
4. Terraform apply (from-zero)         recover-config.sh --apply
5. Set GKE PF as the federation anchor OIDF_FEDERATION_* env
6. Export + bake GKE PF                configArchive/export, docker build, roll
7. AWS: EKS + ECR + IAM + AgentCore    aws-bedrock-demo/aws/bootstrap.sh
8. Deploy PingFederate to EKS          kubectl apply, no config baked yet
9. Terraform apply (from-zero)         recover-config.sh --apply, same pattern
10. Set EKS PF as the federation leaf  OIDF_FEDERATION_* env, authority_hints -> the anchor
11. Export + bake EKS PF               same pattern
12. Verify the trust chain resolves    /federation/fetch, cryptographic check
13. Deploy the cross-cloud chain       cross-cloud-chain/deploy.sh
```

Steps 1–6 and 7–11 are each internally ordered but the two clouds don't depend on each other until
step 12. If you're doing this solo, GCP first is slightly easier since AWS's bootstrap can copy the
bridge/attester secrets *from* the GKE cluster rather than you generating them twice.

## 1. GCP project + cluster

```sh
cd deploy/gke-spiffe-demo/gcp
PROJECT_ID=pf-spiffe-demo-$RANDOM BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX ./bootstrap.sh
```

Creates the project, links billing, enables the container + artifact registry APIs, creates a zonal
`e2-standard-4` cluster in `us-central1-a` (the GKE free tier covers one zonal cluster's management
fee), and an Artifact Registry repo at `us-central1-docker.pkg.dev/$PROJECT_ID/demo`.

**GCP capacity is a real failure mode.** `e2-standard-4` was completely stocked out (`GCE_STOCKOUT`)
across every `us-central1` zone during the 2026-07-30 rebuild — each failed attempt took ~20 minutes to
report. If `us-central1-a` fails, don't retry the same zone serially; run the create against two or
three other zones/regions in parallel and take whichever lands first, then delete the losers:

```sh
gcloud container clusters create spiffe-demo --zone us-central1-c --project "$PROJECT_ID" \
  --machine-type e2-standard-4 --num-nodes 1 --workload-pool="$PROJECT_ID.svc.id.goog" &
gcloud container clusters create spiffe-demo --zone us-east1-b --project "$PROJECT_ID" \
  --machine-type e2-standard-4 --num-nodes 1 --workload-pool="$PROJECT_ID.svc.id.goog" &
wait
```

Whatever zone/cluster name you end up with, **note it** — it feeds every step below.

```sh
export PROJECT_ID=...       # whatever you actually got
export ZONE=...             # whatever zone actually worked
export CLUSTER=...          # whatever cluster name you used
gcloud container clusters get-credentials "$CLUSTER" --zone "$ZONE" --project "$PROJECT_ID"
export GKE_CONTEXT=$(kubectl config current-context)
export GKE_REGISTRY="us-central1-docker.pkg.dev/$PROJECT_ID/demo"
```

## 2. Bridge key + attester key

The bridge key is a single shared key: PingFederate's `ClientAttestationAuthFilter` uses its private
half to sign a `private_key_jwt` assertion on behalf of whichever client the attestation resolved to;
every attestation client carries its public half in its JWKS. **Both PFs and every client must use the
same key** — generate it once.

```sh
kubectl create namespace pf --dry-run=client -o yaml | kubectl apply -f -
deploy/gke-spiffe-demo/pf/gen-bridge-key.sh   # writes the k8s secret pf-bridge-key
```

The attester's own signing key (mints the Client Attestation itself) needs generating too — an EC
P-256 key, `kid=mock-attester-1` by convention, stored as k8s secret `pf-attester-signing` and also
referenced inline in each client's `attestation_signing_jwk` terraform value and in
`oidf-mock-attesters.json` in the PF image build context. If you don't have a script for this handy,
generate one with `openssl` or the `jose4j` library the servlet already depends on — any P-256 key
pair works, it just has to be the *same* key everywhere it's referenced.

DevOps licence secret, if you're using an eval licence:

```sh
kubectl -n pf create secret generic pf-devops-license \
  --from-literal=PING_IDENTITY_DEVOPS_USER=<email> --from-literal=PING_IDENTITY_DEVOPS_KEY=<key>
```

## 3. Deploy PingFederate to GKE — no config yet

Build the module jar and a *bare* PF image (empty `data.zip` — terraform fills it next):

```sh
cd deploy/gke-spiffe-demo/pf
SKIP_BUILD=0 ./build-module-jar.sh
cd ../../pingfederate
rm -f data.zip && touch data.zip   # or use a genuinely empty drop-in-deployer archive
docker build --platform linux/amd64 -t "$GKE_REGISTRY/pingfederate:bootstrap" .
docker push "$GKE_REGISTRY/pingfederate:bootstrap"
kubectl apply -f ../gke-spiffe-demo/pf/deployment.yaml \
  -f ../gke-spiffe-demo/pf/service.yaml
kubectl -n pf set image deploy/pingfederate pingfederate="$GKE_REGISTRY/pingfederate:bootstrap"
kubectl -n pf expose deploy/pingfederate --name=pingfederate-external --type=LoadBalancer \
  --port=80 --target-port=9080
```

Wait for the LoadBalancer IP (`kubectl -n pf get svc pingfederate-external -w`) — that IP is this PF's
public issuer for the rest of the guide. Call it `$GKE_PF_URL`.

## 4. Terraform apply (from-zero)

```sh
cd deploy/gke-spiffe-demo/pf/terraform
export TF_VAR_pf_admin_host=https://localhost:29991   # via a port-forward, see below
export TF_VAR_pf_admin_password=<the admin password baked into your build>
export PINGFEDERATE_PROVIDER_PRODUCT_VERSION=13.0      # REQUIRED or every apply fails before touching PF
export TF_VAR_bridge_public_jwks='{"keys":[...]}'      # public half of the bridge key from step 2
export TF_VAR_gcp_project_id="$PROJECT_ID"
export TF_VAR_gke_cluster_issuer="https://container.googleapis.com/v1/projects/$PROJECT_ID/locations/$ZONE/clusters/$CLUSTER"
export TF_VAR_gke_jwks_uri="$TF_VAR_gke_cluster_issuer/jwks"

kubectl -n pf port-forward svc/pingfederate 29991:9999 &

../../../aws-bedrock-demo/aws/recover-config.sh          # plan first — should show creates only
../../../aws-bedrock-demo/aws/recover-config.sh --apply  # then apply
```

`recover-config.sh` strips every `import {}` block before applying, because Terraform's `import` fails
outright against an object that doesn't exist yet — a from-zero server has nothing to import. Expect
~14 creations (the ATM, the token processor, all three access-token mappings, the token-exchange
policy, `server_settings`, and every attestation client). `PRIVATE_KEY_JWT` clients throw a benign
"Provider produced inconsistent result after apply" — the admin API call succeeded, it's a read-back
quirk; verify with `GET /oauth/clients/<id>` if you want to be sure, then move on.

## 5. Set the GKE PF as the federation anchor

```sh
kubectl -n pf set env deploy/pingfederate \
  OIDF_FEDERATION_TRUST_ANCHORS="http://$GKE_PF_URL" \
  OIDF_FEDERATION_SUBORDINATES="http://$GKE_PF_URL,http://$EKS_PF_URL" \
  OIDF_FEDERATION_TRUST_CONTROLLER_HOST="http://$GKE_PF_URL" \
  OIDF_FEDERATION_ATTESTER_JWKS='{"keys":[{...the attester public JWKS from step 2...}]}'
```

You won't have `$EKS_PF_URL` yet on a fresh rebuild — set `OIDF_FEDERATION_SUBORDINATES` to just the
GKE URL for now and update it once EKS exists (step 10 sets it for real; revisit this here too, or
you'll hit `Unknown subordinate` when EKS tries to resolve the chain).

**This step alone is not durable.** Setting env vars rolls the pod, which re-imports whatever is baked
into the image right now (nothing, from step 3) — the federation config just set will *not* be there
after the next rollout unless you re-bake. That's what step 6 is for; do it immediately, don't leave
the anchor configured-but-unbaked.

## 6. Export + bake the GKE PF

```sh
kubectl -n pf port-forward svc/pingfederate 29991:9999 &
curl -sk -u administrator:<pw> -H 'X-XSRF-Header: PingFederate' \
  -o deploy/pingfederate/data.zip https://localhost:29991/pf-admin-api/v1/configArchive/export

cd deploy/pingfederate
docker build --platform linux/amd64 -t "$GKE_REGISTRY/pingfederate:v1" .
docker push "$GKE_REGISTRY/pingfederate:v1"
kubectl -n pf set image deploy/pingfederate pingfederate="$GKE_REGISTRY/pingfederate:v1"
kubectl -n pf rollout status deploy/pingfederate
```

Verify: `curl http://$GKE_PF_URL/.well-known/client-attester` should return discovery JSON with
`pop_audience` equal to `http://$GKE_PF_URL` — not `localhost:9031` and not some other IP. If it's
wrong, `serverSettings.federationInfo.baseUrl` didn't get set before this export; go back and set it
(the terraform in step 4 manages this declaratively as `server_settings.tf` — re-run
`recover-config.sh --apply` if needed, then re-export and re-bake).

## 7. AWS: EKS + ECR + IAM + AgentCore

```sh
cd deploy/aws-bedrock-demo/aws
export AWS_PROFILE=attest-demo AWS_REGION=ap-southeast-2
export GKE_CONTEXT=<from step 1>
./bootstrap.sh
```

Checks python/boto3 first and fails loudly with remediation if it's broken — that's deliberate, this
was the single most common thing to silently break the old version of this script. Creates the EKS
cluster (IRSA on), four ECR repos, enables AWS Outbound Identity Federation (the account-level STS
issuer used by `aws-sts-web-identity` evidence — enabling it is a one-time, harmless, idempotent
call), the `agentcore-attest-demo` IAM role, and a real Bedrock AgentCore Runtime. Copies the bridge
and attester secrets *from* the GKE cluster if `GKE_CONTEXT` is set — this is the only step that
avoids generating those keys twice.

Prints `EKS_CONTEXT`, `EKS_CLUSTER_ISSUER`, `EKS_JWKS_URL`, `AWS_STS_ISSUER`, `AWS_STS_JWKS_URL`,
`ECR`, and `AGENTCORE_ARN` at the end. **Use those printed values, not hardcoded ones** —
`eksctl create cluster` mints a brand new cluster OIDC issuer every single time, and a stale copy is
the trust root for the `eks-sa-token` evidence path failing silently later.

## 8. Deploy PingFederate to EKS — no config yet

Same idea as step 3, but the AWS manifest is a single file
(`deploy/aws-bedrock-demo/pf/pingfederate.yaml`) with no LoadBalancer Service baked in — expose it
by hand:

```sh
cd deploy/aws-bedrock-demo/pf
rm -f ../../pingfederate/data.zip && touch ../../pingfederate/data.zip
docker build --platform linux/amd64 -t "$ECR/pingfederate:bootstrap" ../../pingfederate
docker push "$ECR/pingfederate:bootstrap"
kubectl apply -f pingfederate.yaml
kubectl -n pf set image deploy/pingfederate pingfederate="$ECR/pingfederate:bootstrap"
kubectl -n pf expose deploy/pingfederate --name=pingfederate-public --type=LoadBalancer \
  --port=80 --target-port=9080
```

AWS hands out a hostname, not an IP — note it as `$EKS_PF_URL`. It can take a minute or two to
resolve after the Service is created.

## 9. Terraform apply (from-zero)

Same shape as step 4, in `deploy/aws-bedrock-demo/pf/terraform`, using the `EKS_CLUSTER_ISSUER` /
`EKS_JWKS_URL` bootstrap printed in step 7 as `TF_VAR_eks_cluster_issuer` / `TF_VAR_eks_jwks_url`.

## 10. Set the EKS PF as the federation leaf

```sh
kubectl -n pf set env deploy/pingfederate \
  OIDF_FEDERATION_TRUST_ANCHORS="http://$GKE_PF_URL" \
  OIDF_FEDERATION_TRUST_CONTROLLER_HOST="http://$GKE_PF_URL" \
  OIDF_FEDERATION_ATTESTER_JWKS='{"keys":[{...same attester public JWKS...}]}'
```

Then go back to the GKE PF and update `OIDF_FEDERATION_SUBORDINATES` to include the real
`$EKS_PF_URL` now that you have it (same `kubectl -n pf set env` pattern as step 5) — **and re-bake
the GKE PF**, or the anchor's `/federation/fetch` will refuse the EKS leaf with `Unknown subordinate`.

## 11. Export + bake the EKS PF

Same shape as step 6, against the EKS admin API.

## 12. Verify the trust chain resolves

```sh
curl "http://$GKE_PF_URL/.well-known/openid-federation"        # anchor's own entity config
curl "http://$GKE_PF_URL/federation/list"                       # should list both PF URLs
curl "http://$GKE_PF_URL/federation/fetch?iss=http://$GKE_PF_URL&sub=http://$EKS_PF_URL"
```

The `fetch` call is the anchor's subordinate statement about the EKS leaf — it should carry the EKS
PF's *own* signing key (fetched live from the EKS PF's entity config), not the anchor's. If you want
the full cryptographic proof rather than eyeballing it, walk the chain with `pyjwt`: verify the EKS
leaf's self-signed entity config against the keys in the anchor's subordinate statement, then verify
the subordinate statement against the anchor's own self-published key. Both should verify clean.

## 13. Deploy the cross-cloud chain

```sh
cd deploy/cross-cloud-chain
export GKE_CONTEXT=... EKS_CONTEXT=... GKE_REGISTRY=... ECR=...
export EKS_PF_URL="http://<eks-elb-hostname>" GKE_PF_URL="http://<gke-lb-ip>"
export AGENTCORE_ARN="<from aws/bootstrap.sh output>"
./deploy.sh
```

Checks python/boto3 up front (hard-exits if broken, before any docker build — there's no partial
path forward here). Builds and pushes three images (layered on the existing demo images, not built
from scratch — a plain `pip install cryptography` for linux/amd64 under emulation timed out at seven
minutes the one time it was tried the naive way). Deploys strictly in dependency order — the resource
first, then agent C configured with the resource's real URL, then the AgentCore runtime pointed at
agent C's real IP, then agent A pointed at the AgentCore ARN — because each step needs an address the
cloud only hands out once the previous step is actually running.

**Before agent A can deploy**, create the transport-only AWS credential it uses to reach the AgentCore
control API (this is *not* an identity credential — A still authenticates to PingFederate with its own
attestation; this key only lets it call `bedrock-agentcore:InvokeAgentRuntime`):

```sh
kubectl -n demo create secret generic aws-invoke \
  --from-literal=access-key-id=<id> --from-literal=secret-access-key=<secret>
```

The script ends by actually calling the live chain and asserting on the real response — not just
trusting that each `kubectl apply` "said" it worked:

```
ok:             True
on behalf of:   spiffe://<project>.svc.id.goog/ns/demo/sa/payment-agent
actor chain:    ['demo-attest-gke-delivery', 'demo-attest-agentcore', 'demo-attest-gke-native']
decision:       True
```

If that prints, the whole thing is live: `sub` preserved across two clouds and two Authorization
Servers, `act` nested three deep, the resource verified the token against the issuing AS's real keys
and allowed the delegated call.

## When you're done

`deploy/aws-bedrock-demo/aws/teardown.sh --yes` then `PROJECT_ID=$PROJECT_ID deploy/gke-spiffe-demo/gcp/teardown.sh --yes`
(AWS first — its bootstrap needs the GKE secrets if you ever rebuild again, so tearing GCP down first
loses nothing there, but AWS-first matches how bootstrap is written). Both scripts check their own
prerequisites, refuse to run without `--yes`, and verify independently afterward — they'll tell you in
an unmissable banner if anything is left over, rather than reporting success and being wrong.

## Where the detail lives if something doesn't match this guide

- `aws-bedrock-demo/RECOVERY.md` — the full incident history: the three-place issuer trap, why
  `serverSettings` needs re-baking after every env change, the import-block rule, the trust-domain
  cascade on a project rebuild, the GCP capacity workaround. Read this when a step above fails in a
  way this guide doesn't explain.
- `gke-spiffe-demo/DEMO-STATE.md` / `aws-bedrock-demo/DEMO-STATE.md` — what was actually live last
  time, useful as a "does this match" reference, not a rebuild guide (coordinates go stale the moment
  anything is rebuilt).
- Script headers (`bootstrap.sh`, `teardown.sh`, `deploy.sh`, `recover-config.sh`) — each documents
  its own required environment and the specific failure it was hardened against, with the incident
  that motivated it.
