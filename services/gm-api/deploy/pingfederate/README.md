# PingFederate for the Grant Evaluation API

## The instance

A DevOps container, deliberately on non-standard host ports so it does not collide
with any other PingFederate you have running:

```bash
docker run -d --name gm-pingfederate \
  -p 9131:9031 -p 9199:9999 \
  -e PING_IDENTITY_ACCEPT_EULA=YES \
  -e PING_IDENTITY_DEVOPS_USER="$PING_IDENTITY_DEVOPS_USER" \
  -e PING_IDENTITY_DEVOPS_KEY="$PING_IDENTITY_DEVOPS_KEY" \
  -e SERVER_PROFILE_URL=https://github.com/pingidentity/pingidentity-server-profiles.git \
  -e SERVER_PROFILE_PATH=getting-started/pingfederate \
  pingidentity/pingfederate:13.0.3-latest
```

| | |
|---|---|
| Runtime | https://localhost:9131 |
| Admin console / API | https://localhost:9199 (`administrator` / `2FederateM0re`) |
| Issuer (`iss` in tokens) | `https://localhost:9031` |

**The issuer and the host port disagree, and that is expected.** PF's own base URL is
`:9031`; the container merely publishes it on `:9131`. So the GM API needs
`TOKEN_ISSUER=https://localhost:9031` (what PF stamps) and
`JWKS_URL=https://localhost:9131/pf/JWKS` (what it can reach). This is exactly why
those are separate settings rather than one derived from the other.

## Configuration

All of it is Terraform in `terraform/` — never the admin console, which would be
unversioned and lost when the container is recreated.

```bash
cd terraform
export TF_VAR_pf_admin_password='2FederateM0re'
export TF_VAR_gm_api_client_secret="$(openssl rand -hex 24)"
export TF_VAR_tpp_client_secret="$(openssl rand -hex 24)"
export TF_VAR_gm_service_password="$(openssl rand -hex 20)"
terraform init && terraform validate && terraform apply
```

`terraform validate` checks against the provider's real schema **without touching a
server** — always author → init → validate → plan → apply.

What it creates:

| Resource | Why |
|---|---|
| `gmJwt` access token manager | Issues JWTs carrying `agid` (the grant id) and `authorization_details`, signed by PF's centralised key so `/pf/JWKS` validates them |
| Six scopes | `accounts.read`, `payments.write`, and the four `grant_management_*` scopes from §6.7.1 |
| `acme-budgeting` client | The TPP whose grants get evaluated |
| `gm-api` client | Client credentials, for the GM API itself |
| `gmApiService` PCV | Basic credentials for the OAuth Administrative Web Service |
| Server settings | Scopes, 90-day persistent grants, and the two bindings below |

## Two things that are not obvious

**The grant management API wants Basic auth, not Bearer.**
`/pf-ws/rest/oauth/users/{user}/grants` is part of the OAuth *Administrative* Web
Service, which authenticates via `admin_web_service_pcv_ref` — a password credential
validator. A bearer token from `atm_id_for_oauth_grant_management` is rejected with
*"HTTP Basic authentication is required"*; that setting governs a different surface.
Both are configured; the GM API's grant client uses Basic.

**RAR consent currently rides as a grant attribute, and that is interim.**
PF 13 has full native RFC 9396 support, but declaring an `authorization_detail_type`
fails with `authorizationDetailProcessorRef` required, and no processor ships with the
product — so a stock PF cannot accept `authorization_details` from a client at all.
Until one is wired up, the consent is injected server-side as an extended attribute on
the persistent grant contract, which the grant client reads as a fallback (see
`decodeAuthzDetails`). **The consent is therefore a constant from `grant-mapping.tf`,
not something a user chose.**

The fix already exists and is already deployed to this PF:
[`pf-rar-paz-plugin`](../../../pf-rar-paz-plugin) registers as *"Attestation-aware RAR
to PingAuthorize"* and supports `account_information`, `payment_initiation` and
`sales_agent`. It governs each requested consent against PingAuthorize policy —
enforcing `requested ⊆ attested` — rather than hardcoding a vocabulary.

**Remaining to finish it:** configure a processor instance with a PingAuthorize
governance-engine `PDP URL` (`pf-rar-paz-plugin/integration/config-as-code/create-processor-instance.sh`),
author the matching policy (`pf-rar-paz-plugin/paz/`), then re-add
`authorization_detail_types` to the client and delete both the `persistent_grant_contract`
extended attribute and the `authorization_details` fulfilment in `grant-mapping.tf`.
The GM API needs no change — `decodeAuthzDetails` already prefers native
`authorizationDetails` over the attribute.

## Verify

```bash
# The grant management API answers (empty until someone consents)
curl -sk -u "gm-api-service:$PINGFED_ADMIN_PASS" -H 'X-XSRF-HEADER: PingFederate' \
  https://localhost:9131/pf-ws/rest/oauth/users/alice/grants
# {"items":[]}
```

## The end-to-end flow

`scripts/authcode.py` drives a full authorization code flow: alice signs in at PF's
form, approves the consent, and the code is exchanged for a token. The tokens are
incidental. The point is the **persistent grant** PF creates on the way, which is what
the Grant Evaluation API answers questions about.

`scripts/authcode.py` ships with the Go reference,
[`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api); run it from
a checkout of that repo (it drives PF at `https://localhost:9131`).

```bash
python3 scripts/authcode.py <path-to-tpp-secret>
```

The token comes back carrying `sub: alice` and `agid: <grant id>` — that `agid` is
how a client names the grant it wants evaluated, without being told it out of band.
Then:

```bash
# The demo AuthZEN PDP also lives in grant-evaluation-api; run it from there.
go run ./cmd/pdp -addr :9099 -expose-entitlements &   # PF reaches it at host.docker.internal:9099

# The API itself is the deployed servlet (gm-api.war) inside PF — nothing to run here.
# TOKEN and AGID come from authcode.py's output above; hit the servlet on PF's own port:
curl -sk -X POST "https://localhost:9131/gm-api/grants/$AGID/evaluate" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# {"decision":false,"context":{"reasons":[{"id":"subject_not_entitled",
#   "message":"You no longer have access to this account."}]}}
```

Against Alice's real grant, which consents to 111, 222 and 444:

| Request | Result | |
|---|---|---|
| `111` read_balance | **Permit** | consent ✓ holds ✓ |
| `222` read_balance | **Deny** | consent ✓ **holds ✗** — closed after consenting |
| `444` read_balance | **Permit** | consent ✓ view rights suffice |
| `444` read_transactions | **Deny** | consent ✓ **right ✗** — view-only signatory |
| `999` read_balance | **Deny** | consent ✗ — entitlement never consulted |

## Gotchas this configuration already works around

**Do not request `openid`.** There is no OpenID Connect policy configured, and asking
for that scope makes PF fail the authorization request with `server_error` and
*"No default OpenID Connect Policy found"*. The demo needs no id_token.

**The demo user password is the PF default** (`2FederateM0re`), which the container
also uses for `administrator`. Fine for a throwaway local PF, and nowhere else.
