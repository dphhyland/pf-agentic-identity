# The PingFederate image build

PF 13.0.3 plus this repo's modules, assembled into a runnable image. This is the **capability made
runnable** - it belongs here, beside the code it packages, and it deploys nowhere by itself.

Three repos consume it, and only one of them deploys to Railway:

| Consumer | What it does with this | Where it runs |
|---|---|---|
| [`pf-oidf-modules`](https://github.com/dphhyland/pf-oidf-modules) | composes a deploy context from this + its own `railway.json`/vars/archive | Railway project `e02a8e2f` |
| [`idp-agentic-demo`](https://github.com/dphhyland/idp-agentic-demo) | builds its own agentic-banking PF; consumes the module jars | Railway project `ac9af096` |
| [`pf-agentic-identity-domain-authority`](https://github.com/dphhyland/pf-agentic-identity-domain-authority) | builds this context and pushes the image to **ECR** for the EKS/GKE rigs | AWS / GCP |

That third one is why the image build is not a Railway artefact and does not live in a deploy repo.

## What is here, and what you must supply

Tracked:

| Path | Purpose |
|---|---|
| `Dockerfile` | stock `pingidentity/pingfederate:13.0.3` + the staged modules, merged into `pf-runtime.war` at the **root** context (single classloader), with the SSF logout filter registered in its `web.xml` |
| `stage-modules.sh` | copies the reactor's eight module jars into `modules/` and writes `MANIFEST` |
| `assemble-pf-runtime-war.sh` | merges `modules/` into the stock war; also used inside the image build |
| `overlay/config-store/` | plain ForceImport config - not secret |

You supply, per deployment (all git-ignored - see `.gitignore`):

| Path | What it is |
|---|---|
| `modules/` | output of `stage-modules.sh`; do not hand-populate it |
| `data.zip.age` | the PF configArchive for **your** environment, **age-encrypted**. A configArchive is a plain zip that *contains* `pf.jwk` - the master key that decrypts every secret in it, next to the system keys, both keystores and the admin password hash. Encrypted, it is safe in git and safe in an image layer. |
| `data.zip` | the same thing **unencrypted**. Transitional only - see below. |
| `overlay/pf.jwk`, `overlay/pingfederate-system-keys.xml` | needed **only** on the plaintext path. The encrypted path takes them from inside the archive. |
| `oidf-mock-attesters.json` | DEV attester trust (issuer → public JWK). Demo trust, not capability - which is why it is supplied rather than baked here, so no consumer inherits another's attesters. |

## Building

```sh
mvn -q -DskipTests package          # from the repo root
build/pingfederate/stage-modules.sh # -> build/pingfederate/modules/ + MANIFEST
# stage your data.zip, overlay/ and oidf-mock-attesters.json into build/pingfederate/, then:
docker build -t pf-oidf build/pingfederate
```

From another repo, point the script at a sibling checkout:

```sh
PF_AGENTIC_IDENTITY_HOME=../pf-agentic-identity ../pf-agentic-identity/build/pingfederate/stage-modules.sh
```

`STAGE_DEST` redirects where the jars land, if you are composing a context elsewhere.

## The encrypted archive

`pf-entrypoint.sh` decrypts `data.zip.age` at boot, using an identity supplied as a runtime variable,
then extracts `pf.jwk` and the system keys **from inside the archive** and hands over to the base
image's own `bootstrap.sh`. So the master key is in neither git nor an image layer - it exists only in
the running container.

```sh
# once per environment, by whoever owns the deployment:
age-keygen -o identity.txt          # keep the identity in a password manager + a sealed Railway var
age -r "$(grep -o 'age1[a-z0-9]*' identity.txt)" -o data.zip.age data.zip
shred -u data.zip                   # the plaintext has no further use

# then, on the service:
PF_ARCHIVE_AGE_KEY=<the identity>   # or PF_ARCHIVE_AGE_KEY_FILE=<a mounted path>
```

**Only one secret.** `pf.jwk` is deliberately *not* supplied separately: it comes out of the archive
after decryption, so the running key is by construction the one the archive was encrypted under.
Supplying them separately is how an archive and a key drift apart, and a PF whose key does not match
its archive fails in a way that reads like data corruption.

**Verified**, not assumed: alpine 3.23.4 in the base image has the community repo enabled and installs
`age` 1.2.1 (no static-binary fallback needed); the entrypoint fails closed with a missing identity and
with a wrong one; and a `docker save` layer scan of an image built this way finds **no** key material,
against a plaintext-built control that finds four files. That control matters — an earlier version of
the same scan reported "clean" for both images and was simply broken.

**The layer trap.** Staging the key and deleting it in a later `RUN` does *not* remove it: the earlier
layer still carries it and `docker save` yields it. The plaintext path demonstrably does this. Only
never putting it in a layer works.

> **Transitional.** A plaintext `data.zip` still builds and boots, with a loud warning, so the build is
> not broken between now and the master-key rotation. Once every environment ships `data.zip.age`, drop
> that branch from `pf-entrypoint.sh` and the `overlay/` key handling from the Dockerfile.

## The MANIFEST guard

`stage-modules.sh` writes `modules/MANIFEST` naming exactly the jars it staged, and
`assemble-pf-runtime-war.sh` refuses to build unless the directory matches it: a missing jar, an extra
hand-added one, or no MANIFEST at all each fail the build. Hand-copying jars into `modules/` is how
modules have gone missing before, and a war that is missing one does not fail at build - it 500s at
first use, in production. The guard turns that into a build failure.

> **Licensing is DevOps-fetched - no `pingfederate.lic` is baked or staged.** The image sets
> `PING_IDENTITY_ACCEPT_EULA=YES`; the base image's boot hook pulls a fresh evaluation license when
> `PING_IDENTITY_DEVOPS_USER` + `PING_IDENTITY_DEVOPS_KEY` are present in the environment. Eval
> licenses are short-lived (~7 days) and re-fetched only at container start.

Because the modules sit at the **root** context, their endpoints have no `/oidf` prefix - the challenge
endpoint is `/federation/attestation-challenge`, and `/.well-known/ssf-configuration` is at root.
Repoint any `/oidf/*` consumers accordingly.
