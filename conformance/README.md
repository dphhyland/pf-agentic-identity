# Running PingFederate from this repo

This directory turns a clone of this repo into a running PingFederate 13.0.3 with every module in it,
configured to pass the [OpenID Foundation conformance suite](https://www.certification.openid.net/)'s
FAPI 2.0 and Shared Signals plans. It is the repo's own PingFederate configuration - the demo and deploy
repos consume it; nothing here depends on them.

```sh
./up.sh          # ~5 minutes the first time: author, export, build, boot
```

You need Docker, Terraform (>= 1.5), Maven, Node and **your own licence details**. The image bakes no
licence. At boot, the stock Ping image fetches an evaluation licence with your Ping DevOps credentials,
read from `~/.pingidentity/config` (or `$PING_DEVOPS_CONFIG`), a two-line `KEY=VALUE` file:

```
PING_IDENTITY_DEVOPS_USER=<your DevOps email>
PING_IDENTITY_DEVOPS_KEY=<your DevOps key>
```

Get them at https://devops.pingidentity.com/how-to/devopsRegistration/. Nothing licensed and no key
ever lands in git: everything `up.sh` generates is under `.gitignore` here.

When it finishes, PF answers on `https://localhost:9031` (self-signed) with discovery at
`/.well-known/openid-configuration`, the SSF transmitter at `/.well-known/ssf-configuration`, an HTTP
listener on 9080 and the admin console on 9999 (`administrator`, password in `.author.env`).
`docker compose down` stops it; `./up.sh` again rebuilds the image from the archive you already have;
`SKIP_AUTHOR=1 ./up.sh` skips re-authoring when only the modules changed.

## What `up.sh` does

| Step | Script | Produces |
|---|---|---|
| 1 | `gen-keys.sh` | `keys/` - key pairs for the suite's three clients (PF gets the public halves; the suite gets the private); `secrets.env` - a test-user password and two client secrets |
| 2 | `author.sh` | a **stock** PF 13.0.3 container with its admin API on `localhost:29999`, the cipher-list overlay staged |
| 3 | `apply.sh apply` | `terraform/` applied to it: OAuth server settings, a JWT access token manager and mappings, an OIDC policy, a login form and test user, the clients (below) |
| 4 | `export.sh` | `data.zip` - PF's config archive, its whole saved state; refused if it would fail the suite |
| 5 | `mvn package` + `stage-modules.sh` | the module jars, from this repo |
| 6 | `compose-context.sh` | `.context/` - `build/pingfederate/`'s image build plus that archive |
| 7 | `docker compose up --build` | the image, running, with `vars.env` and your licence details |

Steps 2-4 are how PF is configured **as code**: `terraform/` is the source, `data.zip` the built
artefact the image imports at boot. There is no volume; a change made in the console is gone at the
next start. Change the `.tf`, run `./up.sh` again.

**The clients** (`terraform/clients.tf`): two FAPI 2.0 clients (`private_key_jwt` + DPoP + PAR + PKCE),
an SSF receiver (`ssf.manage`), an SSF event operator (`conformance-ssf-emitter`, `ssf.provision` - the
provisioner scope the servlet requires for SCIM and `/ssf/events:emit`), and the introspection client
the SSF servlet validates receiver tokens with. Scopes are in `oauth-server.tf`; `ssf.manage` and
`ssf.provision` are exclusive, so no client carries either unless named there.

**Federation and attestation are present, inert and closed.** The image runs the whole module set,
and two of the modules refuse to boot without a trust anchor and a trust controller. `vars.env` names
PF itself as both and leaves `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` unset, which is the state the filters
are written to survive: they log the refusal, validate no trust chain, register nobody, and pass every
token request to PF's own client authentication. `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` does the
same for attestation-based client authentication. Its comments say why each line is there.

## A PF on a public address

The issuer PF advertises is baked into the archive (`terraform/variables.tf` `pf_base_url`), and a suite
fails its first check if the issuer in discovery is not byte-for-byte the URL it fetched discovery from.
For a PF that a hosted suite will reach, set the origin before authoring:

```sh
PF_BASE_URL=https://your.host:port ./up.sh     # substitutes it into the archive and vars.env
```

The suite opens its own TLS handshakes against the token, authorization and userinfo endpoints and fails
anything it does not like about the listener, so the listener has to be PF's own 9031, reached through
a TLS-passthrough TCP proxy and not an HTTP edge that terminates TLS. `.context/` is the build context
a deploy tool wants (`docker build .context`, or `railway up .context --path-as-root`); the deployed
service needs `.context/vars.env`'s values plus your DevOps credentials as its variables. The demo repo
`pf-oidf-modules` deploys one such PF (project `pf-conformance`) and keeps the Railway-specific pieces.

## Why it is shaped like this

**The cipher list is in two places.** `config-store/com.pingidentity.crypto.SunJCEManager.xml` takes
the CBC and static-ECDH suites out, because the suite offers them and fails a server that accepts.
It is laid over the image *and* carried in the archive; that file's header says why either alone
looks fine and is not.

**Two FAPI 2.0 rules are enforced by a filter, not by PingFederate.** 13.0.3 accepts a client
assertion addressed to its token endpoint (or the PAR endpoint, or an array) where the profile says
issuer-only, as a string; and it accepts an RS256-signed DPoP proof where the profile says PS256, ES256
or EdDSA. Neither can be configured away on 13.0 - the first has a switch in 13.1
(`Rfc7523bisCompliantAudienceVerification`), the second has none in either. This repo's
`Fapi2ProfileFilter` enforces both for the clients `OIDF_FAPI2_CLIENTS` names, which is the two FAPI
clients and deliberately not `*`: the suite's SSF client is an ordinary OAuth client that addresses its
assertion to the token endpoint, and with the rules applied to everyone the SSF plan went from 19 of
19 to 1 of 19.

**Staying on 13.0.3 is not a choice.** PingFederate 13.1 moved to `jakarta.servlet`, and the modules are
compiled against `javax.servlet`: on a 13.1.3 base image the merged `pf-runtime.war` fails to start at
all. Until the modules are migrated ([docs/pf-13_1-jakarta-migration-plan.md](../docs/pf-13_1-jakarta-migration-plan.md)),
13.0.x is the ceiling.

## What the suite says, and what it does not

Against a PF built this way, driven by a suite run locally at release-v5.3.1:

| Plan | Variant | Result |
|---|---|---|
| `openid-ssf-transmitter-test-plan` | discovery, `private_key_jwt` client credentials, poll | 19 of 19 PASSED |
| `openid-ssf-transmitter-caep-test-plan` | the same, under the CAEP Interop Profile - the plan the Foundation certifies SSF against | 13 of 13 PASSED (2026-09-23 local replica, 2026-09-24 the public rig; needs the `/ssf/events:emit` servlet from branch `conformance/caep-interop`) |
| `fapi2-security-profile-final-test-plan` | `private_key_jwt`, DPoP, `plain_fapi`, OpenID Connect | 56 modules: 49 PASSED, 4 REVIEW, 2 WARNING, 1 SKIPPED, 0 FAILED (2026-09-21) |

Expect, and do not be alarmed by, in the FAPI 2.0 plan:

- **WARNING** on discovery - PF publishes vendor metadata the suite does not know.
- **WARNING** on authorization-code reuse - PF refuses the second use, as required, but does not also
  revoke the token the first use produced, which the profile only says it should.
- **REVIEW** on four `request_uri` modules - PF answers a reused, expired or foreign `request_uri`
  with an HTTP 400 error *page*, not a redirect. The suite accepts a picture of the page and asks a
  person to look at it. One of the four is a recommendation 13.0.3 does not follow: it spends a
  `request_uri` when the authorization page is loaded rather than when the user authorizes
  (FAPI 2.0 §5.3.2.2 NOTE 3).
- **SKIPPED** on the claims-parameter module - not supported, not advertised, so not tested.

None of that is a certification. A run that counts is made on the hosted suite, by a person who is
signed in, against a PF the suite can reach. SSF **push** delivery has not been run at all: it needs a
suite PF can call back, which a suite on localhost is not (the servlet's outbound policy refuses
loopback, rightly). CIBA is not here: the suite's only CIBA plan is `fapi-ciba-id1-test-plan`, which
profiles CIBA over FAPI **1** Advanced with certificate-bound tokens, so it is a second configuration
rather than a fourth plan on this one.

## Testing it

`suite/render.sh` turns `suite/*.template.json` into the configurations a suite wants, with the
clients' private keys and the test user's password filled in. The rendered files are git-ignored.

**Against a suite you run yourself** (the suite's own `docker compose`, dev mode, no login; it is on
`https://localhost.emobix.co.uk:9643` by default), `suite/run-plan.py` creates the plan, runs every
module and prints each failure's condition and message:

```sh
suite/render.sh

suite/run-plan.py https://localhost:9643 openid-ssf-transmitter-test-plan suite/ssf-transmitter.json \
  --variant ssf_server_metadata=discovery ssf_delivery_mode=poll ssf_auth_mode=dynamic ssf_profile=default \
            server_metadata=discovery client_registration=static_client client_auth_type=private_key_jwt

suite/run-plan.py https://localhost:9643 fapi2-security-profile-final-test-plan suite/fapi2.json \
  --variant client_auth_type=private_key_jwt sender_constrain=dpop fapi_profile=plain_fapi openid=openid_connect

# the CAEP Interop plan: its last module waits for the operator, and the hook is the operator
suite/run-plan.py https://localhost:9643 openid-ssf-transmitter-caep-test-plan suite/ssf-transmitter.json \
  --variant ssf_server_metadata=discovery ssf_delivery_mode=poll ssf_auth_mode=dynamic \
            server_metadata=discovery client_registration=static_client client_auth_type=private_key_jwt \
  --on-log-marker "Please trigger these events on the transmitter now" \
  --hook "suite/trigger-caep-events.py"
```

A suite running in a container cannot reach this machine's `localhost`. Author with an origin it can
reach and that PF can advertise - `PF_BASE_URL=https://host.docker.internal:9031 ./up.sh` - so the
issuer in discovery and the address the suite dials are the same string. If 9031, 9080 or 9999 are
taken on this machine, `PF_PORT_HTTPS` / `PF_PORT_HTTP` / `PF_PORT_ADMIN` move the host side and the
default issuer follows.

`trigger-caep-events.py` takes the emitter client's secret from `secrets.env` and PF's origin from
`terraform/variables.tf` (`--base` to override). It exits non-zero if any of the three events reached
no stream. It needs the `/ssf/events:emit` servlet, which is on branch `conformance/caep-interop`
until that merges.

**Against the hosted suite**, for a run that counts: sign in at certification.openid.net, create the
plan with the same variants, and paste the rendered configuration. The redirect URIs for both suites
are already registered (`suite_base_urls`). The suite drives PF's login and consent pages itself; the
`browser` block's selectors are the ids in PF's stock `html.form.login.template.html` and
`oauth.approval.page.template.html`, and restyling those pages means changing the block.

## What is not in git, and must not be

`.author.env`, `keys/`, `secrets.env`, `data*.zip`, `overlay/`, `suite/*.json`, `.context/`,
terraform state. A config archive is a plain zip that contains `pf.jwk`, the master key that decrypts
every secret in it, beside the admin password hash. This directory ships it in plaintext into the
image, which the build warns about loudly and correctly; `export.sh` says why that is tolerable for a
PF whose key was generated minutes ago and protects three public JWKS and two generated secrets, and
for nothing whose master key protects anything real.
