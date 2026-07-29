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

## One gap this exposed, still open

`attest_cc_mapping` (`client_credentials|attestATM`) references an access-token manager called
**`attestATM`** — the Reference-token variant — which **no Terraform resource manages**. It came from
the original agentic demo's archive. On a from-zero apply the mapping will be created and then fail,
because its `access_token_manager_ref` points at something that does not exist.

Two ways to close it, neither done yet:

1. Add a `pingfederate_oauth_access_token_manager` resource for `attestATM` (Reference plugin), or
2. Drop `attest_cc_mapping` from the config — nothing in the current demo issues reference tokens;
   every client is pinned to `attestJwtATM`.

Option 2 is probably right, but it removes an object from a live server, so it wants doing
deliberately rather than as part of a recovery under pressure.

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
