# Environment as one solution — git-managed, CI-deployed

An **environment** (staging or production) is the *whole* set of services that make the demo work,
not just the UI. Historically only `pf-demo-ui` was git-managed + CI-deployed; every other service
was `railway up`'d by hand from throwaway `/tmp` contexts, with its config living only in Railway's
console. That drift is what let a one-line lighthouse var change turn into an outage with no git
source of truth to revert to. This tree fixes that: **every service is defined here, config is code,
and CI deploys the environment per branch.**

## The pattern (every service follows it)

```
deploy/<service>/
  Dockerfile           # or build context — pinned by digest where it's an upstream image
  railway.json         # builder + deploy policy
  vars.staging.env      # non-secret config as code (KEY=value)
  vars.production.env
```

- **CI** — `.github/workflows/deploy-<service>.yml`, path-filtered to `deploy/<service>/**`, applies
  `vars.<env>.env` then `railway up`s. Branch→env: `sd-jwt-rar-paz`→staging, `main`→production
  (same mapping as `deploy-demo.yml`). Tokens: repo secrets `RAILWAY_TOKEN_STAGING` / `_PROD`.
- **Secrets never live in git.** Master keys, licenses, vault tokens, DB creds → Railway/GitHub
  secrets, referenced by name. `vars.*.env` holds only non-secret config.
- **Reproducible.** A fresh environment = deploy each `deploy/<service>/` context + apply its vars.
  Persistent state (volumes: the lighthouse anchor key, PF's store) are pre-existing Railway
  resources — created once per env, never rebuilt from git.

## Service inventory & migration status

| Service | Purpose | Status |
|---|---|---|
| `pf-demo-ui` | demo UI | ✅ CI (`deploy-demo.yml`) — pre-existing |
| **`lighthouse`** | trust anchor / resolver (go-oidfed) | ✅ **migrated** — `deploy/lighthouse/` + `deploy-lighthouse.yml` |
| `fedhost` | serves entity configs (public JWTs) | ⏳ next — no secrets, straightforward |
| `pingfederate-runtime` | the AS (PF 13 + module) | ⏳ hard — has secrets (`pf.jwk`, license) + big wars; `deploy/pingfederate/` has the Dockerfile, needs the artifacts + secret handling |
| `Redis` | challenge/replay store | managed DB — provisioned, `OIDF_REDIS_URL` referenced |
| `openbao` | secrets vault | dormant, deferred (has secrets) |
| `agent-workload` | SPIFFE demo workload | `harness/agent-workload/` (SDK vendored, gitignored) |

## Known cleanups (tracked here so they aren't lost)
- **Service-name skew:** staging is `lighthouse`, production is `lighthouse-prod` (the CLI couldn't add
  a same-named service to a second env). The CI carries per-env names; unify by renaming so both envs
  use one service name.
- **Image pinning:** the lighthouse is pinned by digest on purpose — an unpinned `:latest` is what
  drifted and broke staging. Bump the digest deliberately, in git, not by re-pulling.
