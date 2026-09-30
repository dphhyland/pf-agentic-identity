# Cloud evidence is pinned per type, bounded in time, held to your projects and tenants, and verified with signing keys only

## Changelog

- The six cloud evidence validators (`gke-sa-token`, `gcp-id-token`, `eks-sa-token`, `aws-sts-web-identity`,
  `aks-sa-token`, `azure-mi-token`) are now one base class, `CloudTokenValidator`, with each type adding only its own
  claims (plan item H-ATT-1, F-0059). Every check they share is in one place and applied the same way to all six.
- Each type's accepted issuers are pinned by a new setting, `OIDF_ATTESTER_<TYPE>_ISSUERS`
  (`OIDF_ATTESTER_GKE_SA_TOKEN_ISSUERS`, `OIDF_ATTESTER_GCP_ID_TOKEN_ISSUERS`, `OIDF_ATTESTER_EKS_SA_TOKEN_ISSUERS`,
  `OIDF_ATTESTER_AWS_STS_WEB_IDENTITY_ISSUERS`, `OIDF_ATTESTER_AKS_SA_TOKEN_ISSUERS`,
  `OIDF_ATTESTER_AZURE_MI_TOKEN_ISSUERS`). A client's `attestation_evidence_issuer` may now only narrow them. The
  production profile refuses a type with no pin.
- `nbf` is checked when present and `iat` is required, both with the 60 s clock skew, and a token issued to live longer
  than `OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS` (default 3600, 60 to 86400) is refused. Unset, the maximum is
  5700 s for `azure-mi-token`, whose lifetime Entra picks, and 3600 s for the other five; set, it holds all six. The
  evidence lifetime cap, `OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS`, still bounds every piece of evidence after
  that.
- Only keys whose `use` is absent or `sig` verify a cloud token, from an inline bundle or a fetched one; the key's type
  and curve must fit the token's algorithm, and its `alg`, when it has one, must be the header's. `RemoteJwksCache`
  still keeps every key of a fetched set, whatever its `use`, so a SPIRE bundle's `jwt-svid` keys keep verifying
  `spiffe-jwt` evidence; it now refuses a set of more than 64 keys and holds at most 256 URLs.
- `gcp-id-token` evidence must come from a user-managed service account of a project `OIDF_ATTESTER_GCP_PROJECTS`
  lists, and a `gcp-id-token` binding may not contain `*`. With the list set, a `gke-sa-token`'s cluster and
  `*.svc.id.goog` trust domain must name a listed project, and a `gke-sa-token` binding's `*` may only come last,
  after `spiffe://<trust-domain>/ns/`.
- `azure-mi-token` evidence must carry `tid`, equal to one of `OIDF_ATTESTER_AZURE_TENANTS` or, with no list, the
  tenant in its pinned issuer; and `oid`, one of `OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES` when that is set. An
  `aks-sa-token` that carries `tid` is held to the tenant list.
- `aws-sts-web-identity` evidence's account must be one of `OIDF_ATTESTER_AWS_ACCOUNTS` when that is set, and must
  agree with the token's `https://sts.amazonaws.com/` `aws_account` claim when present.
- A refusal keeps its error code (`invalid_svid` for the token, `invalid_client` for the client's configuration),
  no longer repeats the token's `iss`, `sub`, `kid` or `alg` (F-0365), and is counted in
  `oidf_attester_cloud_evidence_refusals_total{type, check}`, a selector value over its bound under
  `check="selectors"`.

## Before you deploy

1. **Pin each cloud evidence issuer.** What to do: for every cloud evidence type your clients use, set its
   `OIDF_ATTESTER_<TYPE>_ISSUERS` to the issuers you accept, space- or comma-separated https URLs: your GKE clusters'
   `https://container.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER`,
   `https://accounts.google.com` for `gcp-id-token`, your EKS clusters' `https://oidc.eks.REGION.amazonaws.com/id/ID`,
   your accounts' `https://ID.tokens.sts.global.api.aws`, your AKS clusters' issuer URLs as
   `az aks show --query oidcIssuerProfile.issuerUrl` prints them, and your tenants' `https://sts.windows.net/TENANT/`
   or `https://login.microsoftonline.com/TENANT/v2.0`. Why: before 0.6.0 a token's `iss` was compared only when the
   client set `attestation_evidence_issuer`, so a client without it accepted any issuer its trust bundle verified.
   How to tell: under the production profile every issuance for a client of an unpinned type is refused
   `invalid_client`, "no issuer is pinned for <type> evidence: set OIDF_ATTESTER_<TYPE>_ISSUERS", and the log has one
   WARN per type saying the same; a value that is not an https URL makes `ATTESTATION_ISSUER`'s issuance servlet
   `FAILED_CONFIG` at deploy, naming the variable. What to change: set the variable; a client's
   `attestation_evidence_issuer` may stay, but it must now be one of the pinned issuers, or the client is refused
   `invalid_client` naming the setting. Development-profile escape: with `OIDF_DEPLOYMENT_PROFILE=development`, a type
   with no pin accepts the provider's published issuer shape (above), or the client's own
   `attestation_evidence_issuer` when it has one, with one WARN per type.
2. **Cloud evidence tokens older than the maximum lifetime are refused.** What to do: check that your Kubernetes
   workloads ask for tokens that live no longer than an hour, or set `OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS`
   (60 to 86400, default 3600) to the longest you accept. On EKS, the pod identity webhook's
   `eks.amazonaws.com/token-expiration` annotation "Defaults to 86400 for expirationSeconds if not set"
   (aws/amazon-eks-pod-identity-webhook README, read 2026-09-30), so an `eks-sa-token` from a service account without
   the annotation is refused until you set it to 3600 or less, on the service account or the pod. Azure managed
   identities need nothing: Entra picks their tokens' lifetime, "a random value ranging between 60-90 minutes"
   (Microsoft identity platform access tokens, read 2026-09-30), so with the setting unset `azure-mi-token` is held to
   5700 s instead; if you set it, it applies to Azure too, and below about 5700 some Azure tokens are refused. Why: a
   token's `exp - iat` is how long it can be replayed; AWS's `GetWebIdentityToken` allows "60 seconds (1 minute) to
   3600 seconds (1 hour)" (read 2026-09-30), but a Kubernetes projected token lives as long as the pod's
   `expirationSeconds` asks. `iat` is now required, and `nbf`, when present, is honoured. How to tell: a refused token
   is `invalid_svid`, "token was issued to live longer than the 3600 s this attester accepts of eks-sa-token evidence
   (OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS)", naming its type, and `oidf_attester_cloud_evidence_refusals_total`
   counts it under `check="lifetime"`. What to change: shorten the projected volume's `expirationSeconds` (or the EKS
   annotation), or raise the setting. There is no development-profile escape beyond the setting itself, which both
   profiles read.
3. **GCP identity patterns may not wildcard across `@` or the project.** What to do: list your Google Cloud project
   IDs in `OIDF_ATTESTER_GCP_PROJECTS`, rewrite every `gcp-id-token` binding as a literal
   `spiffe://<trust-domain>/sa/<account>@<project>.iam.gserviceaccount.com`, and make every `gke-sa-token` binding
   start `spiffe://<trust-domain>/ns/` with any `*` last. Why: a Google service-account ID token's audience "can be
   freely chosen by the token requester" (Google, Token types, read 2026-09-30), so any service account in any project
   can mint one for this attester; a binding's `*` matches any suffix, and the project comes after the `@`, so a
   binding such as `spiffe://td/sa/agent-*` admitted `agent-x@someone-elses-project.iam.gserviceaccount.com`.
   How to tell: a client with such a binding is refused `invalid_client`, "a gcp-id-token binding may not use '*'",
   or "a gke-sa-token binding is not spiffe://<trust-domain>/ns/<namespace>/sa/<name>, with at most one '*', last";
   without the project list, production refuses every `gcp-id-token` client, naming `OIDF_ATTESTER_GCP_PROJECTS`;
   a token from a service agent (`...@gcp-sa-<service>.iam.gserviceaccount.com`) or the default Compute Engine
   account is refused `invalid_svid`. What to change: the bindings and the list as above; run the workload as a
   user-managed service account. Development-profile escape: under development, `gcp-id-token` without the project
   list is accepted and no project is checked; the binding grammar applies in both profiles.
4. **Azure evidence is held to your tenant.** What to do: nothing, if each `azure-mi-token` type's pinned issuer names
   your tenant; to accept several tenants, or to name them explicitly, set `OIDF_ATTESTER_AZURE_TENANTS`, and to accept
   only certain managed identities, `OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES` (their object IDs). Why: before 0.6.0
   `tid` was covered by the signature but compared with nothing, and `oid` was checked only for presence. Microsoft's
   access token claims reference says of `iss` that "The application can use the GUID portion of the claim to restrict
   the set of tenants". How to tell: a token whose `tid` is missing, or neither listed nor the tenant of its issuer, is
   refused `invalid_svid`, counted under `check="tenant"`; one whose `oid` is missing or unlisted, under
   `check="managed_identity"`. What to change: add the tenant or the object ID to the setting. `aks-sa-token` tokens
   carry no `tid`, so the pinned cluster issuer is what holds them to a tenant; one that does carry `tid` is held to
   the list when it is set. There is no development-profile escape: the tenant check applies in both profiles.

## Notes

- `spiffe-jwt` clients whose trust bundle is fetched by `attestation_bundle_url` from a SPIRE bundle endpoint are not
  affected: the SPIFFE bundle format says "The use parameter MUST be set" (to `x509-svid`, `jwt-svid` or `wit-svid`),
  so `RemoteJwksCache` keeps every key and only the cloud validators filter to `use` absent or `sig`.

- Decision, for David to confirm: the spec asked that a cloud type with no pin make `ATTESTATION_ISSUER`
  `FAILED_CONFIG` naming the setting. The attester cannot know at deploy which types its clients use - clients are
  resolved from PingFederate per request - so a production deployment that uses no cloud type would be taken down for
  settings it does not need. A type with no pin is refused per request instead (`invalid_client`, naming the setting,
  with one WARN per type); a pin that is not an https URL, and every other new setting outside its grammar, is
  `FAILED_CONFIG` at deploy.
- `xms_mirid` is not in Microsoft's access token claims reference (read 2026-09-30), so the managed-identity claim
  read is `oid`, which the reference defines as "the verified identity of the user or service principal" (U-0375).
- Unit-tested on JDK 17, 20 and the PingFederate 13.1.3 image's JDK 21.0.12 (2026-09-30); not run on the rig, since no
  cloud platform issues tokens there.
