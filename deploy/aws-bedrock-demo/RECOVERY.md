# Rebuilding PingFederate config from zero

Read this before tearing anything down.

## The thing that will catch you out

`data.zip` (the PF config archive) is **encrypted with the master key** in
`deploy/pingfederate/overlay/pf.jwk`, and both are gitignored — deliberately, they are secrets. The
consequence people get wrong:

> A `data.zip` from one instance **will not decrypt** against a freshly generated `pf.jwk`.

So recovery is *not* "restore the archive". If you still hold the master key **and** the archive, you
can rebuild the image directly. If you have lost either, you must rebuild the config with Terraform
and export a fresh archive. That path is the subject of this document.

## Export before you tear down

Cheapest insurance. From a running PF:

```sh
kubectl -n pf port-forward pod/<pf-pod> 29992:9999 &
curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
  -o data.zip https://localhost:29992/pf-admin-api/v1/configArchive/export
```

Keep it next to the matching `pf.jwk`. Separated, neither is much use.

## From-zero rebuild

The Terraform in `deploy/gke-spiffe-demo/pf/terraform` and `deploy/aws-bedrock-demo/pf/terraform`
holds a **complete** definition of every object the demo needs. But most objects carry an
`import {}` block, because they were adopted from a running server rather than created by us.

**Terraform `import {}` fails against an object that does not exist** — it does not fall back to
creating one. So a from-zero apply aborts on the first missing object unless you strip the imports.

Verified 2026-07-28: with the import blocks removed and empty state, `terraform plan` proposes

```
Plan: 13 to add, 0 to change, 0 to destroy.
```

covering `extended_properties`, `attestJwtATM`, `subjectJwtProc`, all three access-token mappings,
the `userToAgentTE` exchange policy, and all six attestation clients. `recover-config.sh` automates
exactly that.

```sh
cd deploy/gke-spiffe-demo/pf/terraform
../../../aws-bedrock-demo/aws/recover-config.sh          # plan only
../../../aws-bedrock-demo/aws/recover-config.sh --apply  # create everything
```

Then export the archive and bake it into the image, as `DEMO-STATE.md` describes.

## The gap this exposed - now closed

`attest_cc_mapping` (`client_credentials|attestATM`) references an access-token manager called
**`attestATM`** — the Reference-token variant — which **no Terraform resource manages**. It came from
the original agentic demo's archive. On a from-zero apply the mapping will be created and then fail,
because its `access_token_manager_ref` points at something that does not exist.

**Closed 2026-07-30.** `attest-reference-atm.tf` now manages it, captured from the live server before
the teardown rehearsal. Verified both ways: the adopt path imports it, the from-zero path creates it
(14 creations). The original options, for the record:

1. Add a `pingfederate_oauth_access_token_manager` resource for `attestATM` (Reference plugin), or
2. Drop `attest_cc_mapping` from the config — nothing in the current demo issues reference tokens;
   every client is pinned to `attestJwtATM`.

Option 2 is probably right, but it removes an object from a live server, so it wants doing
deliberately rather than as part of a recovery under pressure.

## A rebuilt EKS cluster has a NEW OIDC issuer

Learned in the 2026-07-30 rebuild test. `eksctl create cluster` mints a fresh cluster OIDC issuer
every time:

```
before  https://oidc.eks.ap-southeast-2.amazonaws.com/id/9B3C4E687CA92CD350F551C7E0C69A07
after   https://oidc.eks.ap-southeast-2.amazonaws.com/id/DE6B6D49900B87B9BF65A45D4822CD7D
```

That issuer is the trust root for the `eks-sa-token` evidence path, so after any cluster rebuild the
`demo-attest-eks` client's `attestation_evidence_issuer` and `attestation_bundle_url` are stale and
the EKS workload will fail attestation. Take both values from `bootstrap.sh`'s output
(`EKS_CLUSTER_ISSUER` / `EKS_JWKS_URL`) and pass them as `TF_VAR_eks_cluster_issuer` /
`TF_VAR_eks_jwks_url` — never hardcode them.

The account STS issuer (`aws-sts-web-identity`, used by the AgentCore agent) is account-level and does
NOT change, which is why teardown leaves outbound federation enabled.

## A rebuilt load balancer breaks THREE baked settings

The sharpest finding of the rebuild test. A new EKS cluster gets a new ELB hostname, and that
hostname is the PF's public issuer — baked into `data.zip` in three independent places. Fixing one is
not enough, and the symptom of missing one is subtle:

| Setting | Drives | Symptom if stale |
|---|---|---|
| `serverSettings.federationInfo.baseUrl` | the OP issuer and `pop_audience` in discovery | attestation PoP rejected, `invalid_client` |
| `attestJwtATM` field **Issuer Claim Value** | the `iss` claim stamped into issued tokens | the resource rejects the token: `wrong issuer` |
| `subjectJwtProc` field **Issuer** | which issuer subject tokens are accepted from | token exchange fails `Invalid Issuer` |

Observed: after fixing only `baseUrl`, all three hops returned 200 and the chain still failed at the
resource with

```
invalid_token: wrong issuer 'http://<old-elb>' (this resource trusts 'http://<new-elb>')
```

Both ATM/processor values live in `adopted-issuer.tf`. `generate-config` writes them as **literals**,
so the Terraform variables do not help — grep the old hostname out of `*.tf` and replace it:

```sh
grep -rln '<old-elb-hostname>' *.tf
sed -i '' 's|<old-elb-hostname>|<new-elb-hostname>|g' *.tf
```

Also update the **anchor's** `OIDF_FEDERATION_SUBORDINATES` on the other PF, or `/federation/fetch`
correctly refuses with `Unknown subordinate` and no trust chain resolves.

**The durable fix** is to stop using raw ELB/LB hostnames as issuers: put a stable DNS name in front
of each PF so the issuer survives a rebuild. Until then, budget for the three-place update.

## Every object that can arrive via data.zip needs an import block

A resource with no `import {}` block will be **created**, and against a server built from the baked
image that fails with `Client ID is already in use` / `The plugin ID is already defined`. Found on
`demo-attest-gke-delivery` and `gkeSubjectProc` during the rebuild. Both now have import blocks;
`recover-config.sh` strips them for the genuine from-zero case. The rule: if the object is in the
archive, it needs an import block.

## serverSettings is NOT terraform-managed by default - and that bites twice

The single most confusing failure of the full rebuild. `serverSettings.federationInfo.baseUrl` was
set through the admin API, then a `kubectl set env` rolled the pod, which re-imported the baked
`data.zip` and **silently reverted the issuer to the old value**. Symptom: mint 200, then the token
endpoint rejects the PoP with `Expected one of [..., http://<old-ip>]`.

It happened again on the other PF an hour later, with `gkeSubjectProc`'s Issuer: terraform-applied,
then an env change rolled the pod and reverted it, giving `Invalid Issuer` on the second exchange hop.

**The rule: any admin-API or terraform change is provisional until you export and re-bake. Rolling
the pod for any reason - including an unrelated env var - reverts everything to the image.**

`server-settings.tf` now manages `base_url` declaratively so terraform reasserts it. Note the
provider requires a non-empty `saml_2_entity_id` even for an OAuth-only deployment; a placeholder is
used, which is harmless because nothing references it.

## A rebuilt GCP project changes the SPIFFE trust domain

`gcloud projects delete` locks the project ID for ~30 days, so a rebuild lands on a NEW project id -
and the GKE trust domain is derived from it. Everything below changes together:

| Value | Derived from |
|---|---|
| `attestation_trust_domain` | `<project>.svc.id.goog` |
| `attestation_evidence_issuer` / `attestation_bundle_url` | project **and** zone/cluster name |
| every `spiffe_id` binding | the trust domain |
| the anchor's entity id, `OIDF_FEDERATION_*` on both PFs | the new LoadBalancer IP |
| the AWS root's `gke_pf_issuer`, `gkeSubjectProc` | the new anchor IP |

Verified 2026-07-30: rebuilt into `pf-spiffe-demo-4412` (us-east1-b) and the chain came back
identical - `sub` on the new trust domain, `act` three deep, resource allowed.

**GCP capacity is a real failure mode.** `e2-standard-4` was stocked out across every us-central1
zone (`GCE_STOCKOUT`, ~20 minutes to report). Racing two regions in parallel and taking the winner is
far faster than trying zones serially. `gcloud projects undelete <id>` restores the old project
within the window, which avoids the whole trust-domain cascade if you catch it early.

## Not in Terraform at all

These are created by the bootstrap scripts or by hand, and Terraform never sees them:

| Thing | Where it comes from |
|---|---|
| PF master key + system keys | `overlay/` (gitignored). A fresh key is fine **only** with a fresh config build. |
| Bridge key (`pf-bridge-key`) | `deploy/gke-spiffe-demo/pf/gen-bridge-key.sh`. **Both** PFs and every client must carry the same key — a new one means re-applying Terraform on both sides. |
| Attester signing key | k8s secret `pf-attester-signing`; its public half must match `oidf-mock-attesters.json` and each client's `attestation_signing_jwk`. |
| DevOps licence creds | k8s secret `pf-devops-license`. Eval licences are ~7 days and re-fetched at container start. |
| EKS cluster, ECR, IAM role, AgentCore runtime, outbound federation | `aws/bootstrap.sh` |
| GCP project, cluster, registry | `../gke-spiffe-demo/gcp/bootstrap.sh` |
| Agents + resource | `../cross-cloud-chain/deploy.sh` |

## Order for a full rebuild

1. `gke-spiffe-demo/gcp/bootstrap.sh` — GCP project, cluster, registry
2. `aws-bedrock-demo/aws/bootstrap.sh` — EKS, ECR, IAM, AgentCore, outbound federation
3. Bridge + attester keys, DevOps licence secrets into both clusters
4. Deploy PF to both clusters (no baked config yet)
5. `recover-config.sh --apply` against each PF, then export and bake each archive
6. Set the federation env (`OIDF_FEDERATION_*`) on both, roll, verify the chain resolves
7. `cross-cloud-chain/deploy.sh`

Budget half a day, most of it waiting on cluster creation.
