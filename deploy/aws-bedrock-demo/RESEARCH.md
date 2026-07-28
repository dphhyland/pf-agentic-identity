# AWS Bedrock AgentCore demo — evidence research (2026-07-28)

The AWS equivalent of the GKE demo. Question: what AWS-issued token can a workload (especially a
Bedrock AgentCore agent) present as evidence, that the attester can validate against a public JWKS?

## Headline

**AWS Outbound Identity Federation (`sts:GetWebIdentityToken`, GA re:Invent 2025)** mints an AWS-signed
OIDC **JWT** for any workload — EC2, Lambda, ECS, EKS, **and Bedrock AgentCore** — with an account-specific
public JWKS. This is the true analogue of Google's SA ID token, and it means AgentCore has a JWT evidence
path after all.

## The two viable AWS evidence types (both JWT, both mirror the GKE validators)

### 1. `aws-sts-web-identity` — `sts:GetWebIdentityToken` (general AWS + AgentCore)
- Enable once per account: `aws iam enable-outbound-web-identity-federation` → returns the account issuer.
- `iss`: `https://<uuid>.tokens.sts.global.api.aws` (one per account).
- Discovery: `<iss>/.well-known/openid-configuration`; JWKS: `<iss>/.well-known/jwks.json` (GKE-shaped).
- `sub`: the IAM principal ARN, e.g. `arn:aws:iam::<account>:role/<AgentExecutionRole>`.
- `aud`: caller-specified (set to the attester); pin with the `sts:IdentityTokenAudience` IAM condition.
- alg: RS256 or ES384. Lifetime 60–3600s (default 300).
- Caller needs the `sts:GetWebIdentityToken` IAM permission. Outbound-only (cannot be used for
  AssumeRoleWithWebIdentity), which is exactly our use.
- This is the path for a **Bedrock AgentCore agent**: it runs under an IAM execution role, so it calls
  GetWebIdentityToken and presents the JWT. AgentCore's own "workload access token" is opaque and
  first-party-only, so it is NOT usable as evidence — GetWebIdentityToken is the answer.

### 2. `eks-sa-token` — EKS IRSA projected SA token (EKS workloads; fastest to build)
- Nearly line-for-line the same as `GkeTokenValidator`.
- `iss`: `https://oidc.eks.<region>.amazonaws.com/id/<CLUSTER_OIDC_ID>`.
- JWKS: `<iss>/keys` (the one divergence from GKE's `/.well-known/jwks.json`; discovery doc still at
  `<iss>/.well-known/openid-configuration`).
- `sub`: `system:serviceaccount:<ns>:<sa>` (set the projected-volume `audience` to the attester; do not
  rely on the default `sts.amazonaws.com`).
- RS256; EKS rotates the OIDC signing key every 7 days — honour `cache-control` on the JWKS.
- Note: EKS **Pod Identity** (the newer mechanism) does NOT expose a JWT — only IRSA does. Use IRSA.

## Also considered (not chosen)
- **STS `GetCallerIdentity` signed-request replay** (Vault AWS-IAM-auth pattern): a non-JWT validator that
  replays a SigV4-signed request to STS. Superseded by GetWebIdentityToken; keep only as a fallback if an
  account cannot enable outbound federation.
- **IAM Roles Anywhere**: X.509, not a JWT — a future mTLS/X.509 evidence type, out of scope now.
- **Cognito M2M**: a verifiable JWT but it is an OAuth-client identity with a client secret, not native
  workload identity. Weaker fit.
- **SPIRE on AWS (EKS/EC2, `aws_iid` node attestor)**: emits normal JWT-SVIDs — the existing `spiffe-jwt`
  validator already handles it, no new code.

## AgentCore facts that shaped this
- Components (GA): Runtime, Identity, Gateway, Memory, plus Code Interpreter / Browser / Observability.
- The agent runs under an **IAM execution role** (trust `bedrock-agentcore.amazonaws.com`); custom code can
  call AWS APIs as that role and make outbound HTTPS (PUBLIC network mode by default).
- AgentCore Identity brokers OUTBOUND creds (token vault + credential providers; 2LO/3LO; supports a
  `CustomOauth2` provider pointing at any token endpoint, and `private_key_jwt`). That is the reverse of
  our model (AgentCore getting a token FROM an AS). Our flow instead uses the execution role +
  GetWebIdentityToken to present an identity TO the attester.

Sources: docs.aws.amazon.com IAM Outbound Identity Federation, STS GetWebIdentityToken, EKS IRSA,
Bedrock AgentCore devguide (workload access token, runtime permissions, identity), Vault AWS auth.
