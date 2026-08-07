# Azure demo state — placeholder, no live state yet

Unlike `../gke-spiffe-demo/DEMO-STATE.md` and `../aws-bedrock-demo/DEMO-STATE.md`, there is nothing to
record here yet: no Azure subscription has been opened, `azure/bootstrap.sh` has not been run, and no
Terraform has been applied against a real PF. This file exists now (rather than being added later) only so
the tree's shape matches its GKE/AWS siblings — every reference to "not yet deployed" elsewhere in this
leaf (`README.md`'s Status section, the header comments in `azure/bootstrap.sh` and `azure/teardown.sh`)
points back here as the single source of truth for "is this live."

When it is: replace this file with the same shape the other two use — account/subscription id, resource
group, region, cluster name, the exact `data.zip` provenance and image digest baking it, the OIDC
issuer/JWKS URLs actually returned (not the ones this leaf's docs project), and a verified end-to-end run
of each evidence path (`aks-sa-token`, `azure-mi-token`) plus the asserted-context path (an actual `oid`
resolved through `OIDF_ENTRA_AGENT_DIRECTORY`, not the smoke-test's fake attester). Follow
`../aws-bedrock-demo/DEMO-STATE.md`'s structure closely — it is the more recently proven of the two
existing leaves and records exactly the kind of "verified live, here is the ARN/hostname/response" detail
this file should carry once real.
