# Environment as one solution — git-managed, CI-deployed

An **environment** (staging or production) is the *whole* set of services that make the demo work,
not just the UI. Historically only the demo UI was git-managed + CI-deployed; every other service
was `railway up`'d by hand from throwaway `/tmp` contexts, with its config living only in Railway's
console. That drift is what let a one-line lighthouse var change turn into an outage with no git
source of truth to revert to. This tree fixes that: **every service is defined here, config is code,
and CI deploys the environment.** (The demo UI itself, `pf-demo-ui`, stays with the demo repo,
[pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules), and its own `deploy-demo.yml`.)

## The pattern (every service follows it)

```
deploy/<service>/
  Dockerfile           # or build context — pinned by digest where it's an upstream image
  railway.json         # builder + deploy policy
  vars.staging.env      # non-secret config as code (KEY=value)
  vars.production.env
```

- **CI** — `.github/workflows/deploy-<service>.yml`, path-filtered to `deploy/<service>/**`, applies
  `vars.<env>.env` (`railway variables --set`) then `railway up`s. **Push to `main` → staging.
  Production only by explicit `workflow_dispatch` with `environment=production`** — there is no
  branch that deploys production on push. (The demo repo's `deploy-demo.yml` has its own,
  different mapping; do not read it across.) Tokens: repo secrets `RAILWAY_TOKEN_STAGING` /
  `RAILWAY_TOKEN_PROD`, one project token per environment.
- **Secrets never live in git.** Master keys, licenses, vault tokens, DB creds → Railway/GitHub
  secrets, referenced by name. `vars.*.env` holds only non-secret config.
- **Reproducible.** A fresh environment = deploy each `deploy/<service>/` context + apply its vars.
  Persistent state (the lighthouse volume — anchor key + subordinate DB; the enrolment Postgres; the
  Redis) are pre-existing Railway resources — created once per env, never rebuilt from git. PF itself
  is ephemeral (no volume): its config is the archive baked into the image.

## Service inventory & migration status

| Service | Purpose | Status |
|---|---|---|
| **`lighthouse`** | trust anchor / resolver (go-oidfed, pinned by digest) | **CI** — `deploy/lighthouse/` + `deploy-lighthouse.yml` (push → `lighthouse` in staging; dispatch → `lighthouse-prod`) |
| **`fedhost`** | serves entity configs (public JWTs) | **CI** — `deploy/fedhost/` + `deploy-fedhost.yml`; per-env content via `FEDHOST_CONTENT` (`content.{staging,production}.json`); production service is `fedhost-prod` |
| `pingfederate-runtime` | the AS (PF 13.0.3 + the reactor's modular jars merged into `pf-runtime.war`) | **build-in-CI, `workflow_dispatch`-only** — `deploy-pingfederate.yml` builds the reactor, stages `modules/` via `build/stage-modules.sh`, `railway up --no-gitignore`s. Gated on provisioning (below). Local `railway up` from `deploy/pingfederate/` is the working path today ([its README](pingfederate/README.md)) |
| `device-enrolment` | the agent platform backend (Client Attester for on-device agents) | **config only, no workflow** — `deploy/device-enrolment/` has Dockerfile + `railway.json` + `vars.<env>.env`, but no `deploy-device-enrolment.yml`; deploys by hand (`railway up`, context = repo root — the Dockerfile builds the reactor). Its `Dockerfile.demo`/`docker-compose.yml` still reference the removed `demo/phone-simulator` path — see [docs/DEMOS.md](../docs/DEMOS.md) |
| `Redis` | challenge/replay store (`OIDF_REDIS_URL`) | managed DB — a Railway resource, no deploy dir |
| `openbao` | secrets vault (`OIDF_OPENBAO_URL`, transit signing) | dormant, deferred (has secrets); a Railway resource, no deploy dir |

## PingFederate — to go live (the one part that needs you)

`deploy-pingfederate.yml` extracts the licensed `pf-protocolengine` jar, the PF SDK jar and the stock
`pf-runtime.war` from the `pingidentity/pingfederate` image the deploy already builds FROM (public
pull; no deploy key, no jar host — the module source lives in this repo), builds the reactor, stages
the modular jars (`build/stage-modules.sh` → `modules/`, seven today), and lets the Dockerfile
assemble `pf-runtime.war`. Nothing licensed is baked: the runtime is DevOps-licensed at boot
(`PING_IDENTITY_DEVOPS_*` service vars). What's yours to provision before the first dispatch:

- **Repo Actions secrets:** `PF_JWK` (the `pf.jwk` master key),
  `PF_SYSTEM_KEYS` (`pingfederate-system-keys.xml`), `RAILWAY_TOKEN_STAGING` / `RAILWAY_TOKEN_PROD`.
  These four are the only secrets any workflow here reads.
- **The per-env config archive — currently a hard stop.** A PF `configArchive` is a plain zip that
  **contains `pf.jwk` itself**, along with `pingfederate-system-keys.xml`, both keystores, the admin
  password hash and master-key-reversible client secrets. PF obfuscates individual *values* with the
  master key and then ships the key in the same archive, so the old reading here — "encrypted with
  `pf.jwk`, therefore safe to version" — was wrong. `data.staging.zip` was committed on that premise
  and reached the public remote; that key is treated as compromised and is being rotated.
  Everything matching `data*.zip` is now git-ignored, `build.yml` fails if such a file is ever
  tracked, and the deploy workflow refuses to run rather than deploy from a committed archive. The
  replacement — an `age`-encrypted archive in git, decrypted at boot from a sealed Railway variable,
  so the key sits in neither git nor an image layer — lands with the rotation.
- **Confirm two image paths** on the first run (marked `CONFIRM` in the workflow): where
  `pf-protocolengine*.jar` and the stock `pf-runtime.war` live inside the PF image.
- **Note:** unlike lighthouse/fedhost, this workflow does not apply `vars.<env>.env` — the
  `pingfederate-runtime` service vars (`OIDF_FEDERATION_TRUST_ANCHORS`,
  `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`, `OIDF_SSF_ISSUER`, EULA) have to be on the service
  already; the files are the record of what should be there, not yet the mechanism.
- **Not yet set: the SSF receiver's instance-registry wiring.** `servlets/ssf` can turn inbound CAEP
  signals into agent-instance registry changes (`InstanceRegistryReceiverHandler`), but it's gated
  behind `OIDF_SSF_RECEIVERINSTANCEREGISTRY=true` **and** `OIDF_SSF_STOREDIALECT=ldm` on
  `pingfederate-runtime` — neither is set on staging yet, so today the handler is built but not
  installed. `libs/device-instance/device-instance-0.1.0.jar` also needs to be in `modules/` (added
  to `stage-modules.sh`); the next `deploy-pingfederate.yml` dispatch picks it up automatically.

## Known cleanups (tracked here so they aren't lost)
- **Service-name skew:** staging is `lighthouse`, production is `lighthouse-prod` (the CLI couldn't add
  a same-named service to a second env); fedhost has the same `fedhost` / `fedhost-prod` split. The CI
  carries per-env names; unify by renaming so both envs use one service name.
- **Image pinning:** the lighthouse is pinned by digest on purpose — an unpinned `:latest` is what
  drifted and broke staging. Bump the digest deliberately, in git, not by re-pulling.
- **Stale header comment** in `deploy-fedhost.yml` still describes the old `sd-jwt-rar-paz`→staging /
  `main`→production mapping; the triggers themselves are correct (push to `main` → staging job,
  dispatch → production job).
