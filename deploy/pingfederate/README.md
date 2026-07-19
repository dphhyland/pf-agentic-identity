# OIDF PingFederate — isolated deploy context

The **own** deploy context for `pingfederate-runtime` (Railway project `e02a8e2f`) — PF 13.0.3 + the
`pf-oidf-modules` attestation/federation module **only**. It replaces building from the *shared*
`idp-paz-authzen-adapter/demo/pingfederate/`, so no agentic `urn:agent:*` clients or RFC 8693
token-exchange plane ride along.

- **[`Dockerfile`](Dockerfile)** — the minus-RAR image: drops the RAR→PingAuthorize plugin, the RAR
  consent page, and the PingAuthorize-TLS workaround; **merges `pf-oidf-modules.jar` + jose4j into
  `pf-runtime.war`** (root context, single classloader) with the SSF logout filter registered in its
  `web.xml`, keeps the mock-attester + master-key overlay, and bakes this repo's **own** `data.zip`.
  Because the module is at root, its endpoints have **no `/oidf` prefix** (e.g. the challenge endpoint is
  `/federation/attestation-challenge`, `/.well-known/ssf-configuration` is at root) — repoint any `/oidf/*`
  consumers (demo UI `PF_BASE`) accordingly.
- **[`terraform/`](terraform/)** — the config-as-code source (the federation issuance criterion) + the
  Phase-2 runbook that produces the OIDF-only `data.zip`.

## Stage the build context, then deploy

The Dockerfile `COPY`s these — place them here first (git-ignored; `.railwayignore` still uploads them):

| Artifact | Source |
|---|---|
| `pf-oidf-modules.jar` | `mvn -q package` in this repo (merged into `pf-runtime.war` at build) |
| `jose4j-0.9.6.jar` | module runtime dep (merged into `pf-runtime.war`) |
| `oidf-mock-attesters.json` | DEV attester trust (issuer → public JWK) |
| `overlay/` | **secret** — master key from `idp-paz-authzen-adapter/demo/pingfederate/` (git-ignored) |
| `data.zip` | `terraform/` Phase-2 export (OIDF-only configArchive) |

> **Licensing is DevOps-fetched — no `pingfederate.lic` is baked or staged.** The image sets
> `PING_IDENTITY_ACCEPT_EULA=YES`; the base image's boot hook pulls a fresh evaluation license when
> `PING_IDENTITY_DEVOPS_USER` + `PING_IDENTITY_DEVOPS_KEY` are present as **Railway service vars**
> (already set on `pingfederate-runtime`) / **GitHub Actions secrets** (applied by the deploy workflow).
> Non-secret licensing config lives in `vars.<env>.env`. Trade-off: DevOps eval licenses are short-lived
> (~7 days) and re-fetched only at container start.

```sh
# from repo root, after staging the artifacts above and running terraform Phase 2:
( cd deploy/pingfederate && railway up --detach -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -s pingfederate-runtime -e staging )
```

Then verify: the demo ⚡ flow still issues a token (enrol → resolve → 200), and the admin console
(`https://hayabusa.proxy.rlwy.net:39267/pingfederate/app`) shows only OIDF clients — no `urn:agent:*`.

> Until you cut over, `pingfederate-runtime` keeps building from the shared context. This context becomes
> authoritative the first time you `railway up` from here (Step 6 of `terraform/README.md`).
