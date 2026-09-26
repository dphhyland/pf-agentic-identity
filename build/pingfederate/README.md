# The PingFederate image build

PF 13.1.3 plus this repo's modules, assembled into a runnable image. This is the **capability made
runnable** - it belongs here, beside the code it packages. To run it on this machine, configured,
use [`../conformance/up.sh`](../../conformance/README.md); this page is about the image itself.

This directory builds an image; it deploys nothing. [`conformance/`](../../conformance/README.md) is the
one consumer in this repo: it authors the PF configuration as Terraform, exports the archive, composes
the build context and runs the image with `docker compose`. A deployment elsewhere composes its own
context from this directory plus its own archive and variables, and keeps whatever its platform needs in
its own repo.

## The PingFederate version

`build/pf-version.env` is the one place the PingFederate version is written down: the image tag and its
digest, the SDK version the reactor compiles against, and the product version the Terraform provider is
told. `tools/pf-version-check.py` checks that the other places which name the version agree with it -
the Dockerfile's `FROM` line among them, which has to stay a literal. Moving to another PingFederate
release starts with that file, and the modules move with it: build them against the new SDK and stage
them again. `assemble-pf-runtime-war.sh` refuses jars built for the other servlet namespace, and
`tools/pf-linkcheck.py` finds a PingFederate member the new release no longer has - both before
anything boots.

## Two profiles

An image is built for one of two **staging profiles**, and says which in a label.

| Profile | Module jars | For |
|---|---|---|
| `production` (the default) | eight: `oidf.jar`, `attestation-issuer`, `ssf`, `oidf-jose`, `client-attestation`, `openid-federation`, `agent-registry`, `device-instance` | every deployment |
| `conformance` | those and a ninth, `pf.plugins.ciba-sim.jar`, plus `/opt/ciba-sim`, the directory the simulator keeps its decisions in (`0700`, owned by PingFederate's user) | the conformance rig, for the suite's FAPI-CIBA plan |

The CIBA simulator is an approval oracle keyed by nothing but an `auth_req_id`
([plugins/ciba-sim](../../plugins/ciba-sim/README.md)), so it is never staged into a production image, and
even in a conformance one it runs only under `OIDF_DEPLOYMENT_PROFILE=development`. The profile is chosen
twice, and the two must agree: `stage-modules.sh --profile <p>` writes it into `MANIFEST`, and
`docker build --build-arg STAGING_PROFILE=<p>` hands it to the assembler, which refuses a `modules/` staged
for the other one. A third value is refused by both. The image records it as the label
`io.github.dphhyland.pf-agentic-identity.staging-profile`:

```sh
docker inspect --format '{{index .Config.Labels "io.github.dphhyland.pf-agentic-identity.staging-profile"}}' <image>
```

Verified 2026-09-27 on 13.1.3: a production build has the eight jars in `server/default/deploy` and in the
war's `WEB-INF/lib`, no `pf.plugins.ciba-sim.jar` and no `/opt/ciba-sim`; a conformance build has nine and
the directory as `drwx------ ping`; a production `modules/` built with `STAGING_PROFILE=conformance` fails
at the assembler, and `STAGING_PROFILE=staging` fails at the first `RUN`. The conformance image booted
through `conformance/up.sh`: the token endpoint answered, a bare `POST /ciba-sim/decision` was a 400 and
not a 404 (every check in the simulator's gate passed on the running PF), a recorded decision appeared in
`/opt/ciba-sim` as a `0600` file, and the PingFederate JVM had `Umask: 0077` and the profile in its
environment.

## What is here, and what you must supply

Tracked:

| Path | Purpose |
|---|---|
| `Dockerfile` | stock `pingidentity/pingfederate:13.1.3` + the staged modules, merged into `pf-runtime.war` at the **root** context (single classloader), with seven filters registered over PF's own endpoints in its `web.xml` - the list, and the order they must run in, is in `assemble-pf-runtime-war.sh`. `--build-arg STAGING_PROFILE=production\|conformance` (default `production`) |
| `stage-modules.sh` | copies the reactor's module jars into `modules/` - eight for `--profile production` (the default), nine for `--profile conformance` - and writes the v2 `MANIFEST` |
| `assemble-pf-runtime-war.sh` | merges `modules/` into the stock war after checking it against `MANIFEST` and the profile; also used inside the image build |
| `pf-entrypoint.sh` | the boot shim: checks, decrypts and places the archive, drops the identity from the environment, hands over to the base image |
| `test-entrypoint.sh` | exercises the entrypoint's decisions with PingFederate stubbed out; `--image <image>` runs it inside a built image |
| `overlay/config-store/` | plain ForceImport config - not secret |

You supply, per deployment (all git-ignored - see `.gitignore`):

| Path | What it is |
|---|---|
| `modules/` | output of `stage-modules.sh`; do not hand-populate it |
| `data.zip.age` | the PF configArchive for **your** environment, **age-encrypted**. A configArchive is a plain zip that *contains* `pf.jwk` - the master key that decrypts every secret in it, next to the system keys, both keystores and the admin password hash. Encrypted, it is safe in git and safe in an image layer. |
| `data.zip` | the same thing **unencrypted**. Transitional, and refused at boot unless `OIDF_DEPLOYMENT_PROFILE=development` - see below. |
| `overlay/pf.jwk`, `overlay/pingfederate-system-keys.xml` | staged **only** on the plaintext path, and redundant since the entrypoint takes both keys from inside the archive on either path. Phase 3 (plan item R-I3) removes the plaintext path and them with it. |
| `oidf-mock-attesters.json` | DEV attester trust (issuer → public JWK). Demo trust, not capability - which is why it is supplied rather than baked here, so no consumer inherits another's attesters. |

## Consuming a release, rather than copying jars

Tagging `v<version>` publishes a checksummed set of these artifacts as a GitHub Release — the module
set, `oidf.war`, the plugin jars, `SHA256SUMS`, and a `PROVENANCE.txt` naming the commit that built
them. Maven artifacts also go to GitHub Packages under `com.pingidentity.ps.oidf`, though that requires
authentication even for public reads, so the release assets are the auth-free path.

**Pull a release and record what you pulled.** The alternative — copying jars out of a sibling checkout
— is how a consumer came to be running module code from before the 2026-08-15 split-package unwind,
with none of the security work in it, and nothing anywhere recording that it was behind.

```sh
gh release download v<version> -R dphhyland/pf-agentic-identity -D vendor/
( cd vendor && sha256sum -c SHA256SUMS )      # verify before use
grep -E '^(commit|tag):' vendor/PROVENANCE.txt >> VENDORED.txt   # record it
```

For PingFederate 13.1.3 that is v0.3.0 or later. Every v0.1.x release is a `javax.servlet` build for
13.0.x, and moving from one means moving PingFederate in the same change.

`modules/` is **eight separate jars** in a production stage, which is what a release is, and nine in a
conformance stage (v0.3.0's release set was the nine of the one-profile script). If you are copying a
single `pf-oidf-modules.jar`, you are on the pre-unwind artifact shape that this build no longer produces.

## Building

```sh
mvn -q -DskipTests package                              # from the repo root
build/pingfederate/stage-modules.sh                     # -> modules/ + MANIFEST; --profile conformance for a rig
# stage your data.zip.age, overlay/ and oidf-mock-attesters.json into build/pingfederate/, then:
docker build -t pf-oidf build/pingfederate              # --build-arg STAGING_PROFILE=conformance for a rig
```

From another repo, point the script at a sibling checkout:

```sh
PF_AGENTIC_IDENTITY_HOME=../pf-agentic-identity ../pf-agentic-identity/build/pingfederate/stage-modules.sh
```

`STAGE_DEST` redirects where the jars land, if you are composing a context elsewhere.

## The MANIFEST guard

`stage-modules.sh` writes `modules/MANIFEST`, version 2:

```
MANIFEST/2 profile=production built=2026-09-27T09:28:26Z commit=a440bc5f88d1
[servlets]
ca43ec7a6863eba7e8c1f0cd5a4c59135a2f9796ea9c513c0043ef83593c61fa  oidf.jar
729ab2b32f47280a274c3bf29e464724caa4471c1d064d7ec5ec4e4c93b64d51  attestation-issuer-0.4.0-SNAPSHOT.jar
...
[libs]
...
```

One header line - the format, the profile, when it was staged and from which commit (`-dirty` when tracked
files had uncommitted changes; `unknown` outside a git checkout); a `[section]` per module group
(`servlets`, `libs`, and `plugins` in a conformance stage); and one `<sha256>  <file>` line per jar, in
`sha256sum`'s own format, so the directory can be checked by hand:

```sh
grep -E '^[0-9a-f]{64}  ' modules/MANIFEST | ( cd modules && sha256sum -c )
```

`assemble-pf-runtime-war.sh` refuses to build unless the header is a v2 header whose profile is the one it
was told (its fifth argument, `production` when omitted), every named jar is present with the digest it was
staged with, and no other jar is in the directory. A v1 `MANIFEST` - bare filenames, no header - is refused
too: it came from an older `stage-modules.sh`, and the jars beside it from some other tree. Hand-copying
jars into `modules/` is how modules have gone missing before, and a war that is missing one does not fail
at build - it 500s at first use, in production. The guard turns that into a build failure, and the digests
catch the jar that was rebuilt or swapped after staging, which a list of names could not.

Verified 2026-09-27 against the 13.1.3 stock war: both profiles assemble; a profile mismatch either way, a
v1 file, a jar with one byte appended, a stray jar, a missing jar and a third profile value are each
refused, and no output war is left behind.

**Reading a MANIFEST elsewhere.** Anything that counted the module set by counting lines - the release
workflow builds `PROVENANCE.txt` that way - counts the header and the sections as well from this version.
Count the digest lines instead: `grep -cE '^[0-9a-f]{64}  ' MANIFEST`.

> **Licensing is DevOps-fetched - no `pingfederate.lic` is baked or staged.** The image sets
> `PING_IDENTITY_ACCEPT_EULA=YES`; the base image's boot hook pulls a fresh evaluation license when
> `PING_IDENTITY_DEVOPS_USER` + `PING_IDENTITY_DEVOPS_KEY` are present in the environment. Eval
> licenses are short-lived (~7 days) and re-fetched only at container start.

## The archive at boot

`pf-entrypoint.sh` runs before the base image's own `bootstrap.sh`, and does these things in this order:

1. `umask 077`, before anything is written - the decrypted archive, the keys, and every file the base
   image's hooks go on to copy are readable by PingFederate's user alone.
2. Chooses the archive: `PF_ARCHIVE_FILE` if set, else `data.zip.age` in the drop-in directory, else
   `data.zip` there. Encrypted and plain are told apart by content (an age file starts with
   `age-encryption.org/v1`), not by name.
3. If `PF_ARCHIVE_SHA256` is set, checks the archive against it - before it is decrypted or imported.
4. Decrypts an encrypted archive with the identity from `PF_ARCHIVE_AGE_KEY_FILE`, or, only when that is
   unset, from `PF_ARCHIVE_AGE_KEY`. The inline identity reaches `age` on a pipe, never a temporary file
   or an argument; the file is the operator's, read and left alone.
5. Refuses a plaintext archive unless `OIDF_DEPLOYMENT_PROFILE=development`. Production is the default
   when the variable is unset, and what any other value counts as.
6. Extracts `pf.jwk` and `pingfederate-system-keys.xml` from inside the archive, on either path.
7. Removes `PF_ARCHIVE_AGE_KEY` and `PF_ARCHIVE_AGE_KEY_FILE` from the environment and hands over. Nothing
   downstream - the base image's hooks, PingFederate, a shell in the container - sees the identity.

| Variable | Default | What it does | When it's wrong |
|---|---|---|---|
| `PF_ARCHIVE_FILE` | `data.zip.age`, else `data.zip`, in the drop-in directory | The archive to boot from - a mounted secret, usually. It wins over an archive baked into the image, which is left where it is | Not a file: `FATAL: PF_ARCHIVE_FILE=... is not a file`, no boot |
| `PF_ARCHIVE_AGE_KEY_FILE` | unset | Path to the age identity, as a mounted secret file. **Preferred**: it is never in the container's metadata | Set but missing: `FATAL: ... does not exist` - no fall-through to the inline key. Wrong identity: `FATAL: could not decrypt the config archive`, and no plaintext is left behind |
| `PF_ARCHIVE_AGE_KEY` | unset | The identity itself, read only when `_FILE` is unset. Gone from the process environment before PingFederate starts, but still in `docker inspect` - the reason to prefer the file | Wrong: as above. Neither set for an encrypted archive: `FATAL: ... neither PF_ARCHIVE_AGE_KEY_FILE nor PF_ARCHIVE_AGE_KEY is set` |
| `PF_ARCHIVE_SHA256` | unset (no check) | The archive's SHA-256 in hex, any case, of the file as shipped - the ciphertext for an encrypted archive | Mismatch: `FATAL: ... does not match PF_ARCHIVE_SHA256`, before anything is decrypted. Not 64 hex digits: `FATAL: PF_ARCHIVE_SHA256 is not a hex SHA-256` |
| `OIDF_DEPLOYMENT_PROFILE` | unset, which is `production` | `development` lets a plaintext archive boot, with a warning. Read from the environment directly here and by plugins/ciba-sim until plan item PR-1 (Phase 2) centralises the profile | Unset, `production` or anything else with a plaintext archive: `FATAL: a plaintext archive (...) is refused when OIDF_DEPLOYMENT_PROFILE is production` |
| `PF_DATA_DIR`, `PF_BOOTSTRAP` | `/opt/in/instance/server/default/data`, `/opt/bootstrap.sh` | Where the archive and keys go, and what to hand over to. `test-entrypoint.sh` points both at a scratch directory and a stub | - |

Once per environment, by whoever owns the deployment:

```sh
age-keygen -o identity.txt          # keep the identity in a password manager + a sealed service secret
age -r "$(grep -o 'age1[a-z0-9]*' identity.txt)" -o data.zip.age data.zip
sha256sum data.zip.age              # -> PF_ARCHIVE_SHA256, if you want the boot to check it
shred -u data.zip                   # the plaintext has no further use

# then, on the service: mount identity.txt as a secret file and set
PF_ARCHIVE_AGE_KEY_FILE=/run/secrets/pf-archive-identity   # or PF_ARCHIVE_AGE_KEY=<the identity>, second best
```

**Only one secret.** `pf.jwk` is deliberately *not* supplied separately: it comes out of the archive
after decryption, so the running key is by construction the one the archive was encrypted under.
Supplying them separately is how an archive and a key drift apart, and a PF whose key does not match
its archive fails in a way that reads like data corruption. From this version the plaintext path takes
its keys from the archive as well; the `overlay/` keys it used to rely on are the same files.

### Where the plaintext lives

Earlier versions of this page and of the script said the archive was decrypted "into a tmpfs-backed
path". It never was; nothing mounted one. What happens, read from the 13.1.3 base image's scripts on
2026-09-27: the entrypoint writes `data.zip` to the drop-in directory under `PF_DATA_DIR` and the two key
files beside it, on the container's writable layer; the base image's `entrypoint.sh` then copies everything
under `/opt/in` to `/opt/staging` (`apply_local_server_profile`) and hook `07-apply-server-profile.sh` copies
that into `/opt/out/instance`, both with a plain `cp` of every file. So for the life of the container the
plaintext archive and `pf.jwk` exist in three places on that layer, each `0600` because of the umask - seen
on the rig 2026-09-27, where the drop-in deployer had also renamed its copy under `/opt/out` to
`data.zip.<date>` after importing it, and left it there. What the entrypoint guarantees is narrower, and
holds: none of them is in an image layer, and the identity that unlocked them is in none of those places
either.

To keep them off the node's disk as well, mount a tmpfs over `/opt/out`, the runtime instance the
bootstrap builds there from `/opt/server` (519 MB on 13.1.3) and where PingFederate also writes its logs -
so size it:

```sh
docker run ... --tmpfs /opt/out:rw,exec,size=2g,uid=9031,gid=0,mode=0770 ...
```

`exec` is not optional: Docker mounts a tmpfs `noexec` unless told otherwise, and the runtime's `run.sh`
then fails with `Permission denied` before PingFederate starts (seen 2026-09-27: exit 126, after the
licence had been fetched). With it, the boot described under "Verified" below came up with `/opt/out` a
2 GB tmpfs, 569 MB used. With `PF_ARCHIVE_FILE` pointing at a mounted secret, the drop-in copy under
`/opt/in` can go on a tmpfs too (`--tmpfs /opt/in/instance/server/default/data/drop-in-deployer`), leaving
the extracted keys under `PF_DATA_DIR` and the `/opt/staging` copy on the writable layer: `/opt/staging`
holds the hooks and cannot be a mount, and `PF_DATA_DIR` holds the image's `config-store/` overlay. Plan
item R-I3 (Phase 3) revisits the layout.

**Verified.** 2026-08-21 on the 13.0.3 base image: the entrypoint failed closed with a missing identity and
with a wrong one, and a `docker save` layer scan of an image built this way found **no** key material,
against a plaintext-built control that found four files - a control that matters, because an earlier
version of the same scan reported "clean" for both images and was simply broken. 2026-09-27 on 13.1.3:
the base image is alpine 3.24.1 with `age` 1.3.1, and `test-entrypoint.sh --image` ran its 38 checks inside
an image built from this Dockerfile, as the `ping` user - every refusal above, the file-over-variable
preference, `umask 077` reaching the process the entrypoint hands over to, both identity variables absent
from its environment, and the inline identity found nowhere on disk. The same day, on a real boot: the
rig's image started from an age-encrypted archive named by `PF_ARCHIVE_FILE` on a read-only mount, the
identity from `PF_ARCHIVE_AGE_KEY_FILE`, `PF_ARCHIVE_SHA256` set, under `OIDF_DEPLOYMENT_PROFILE=production`,
first on the writable layer and then with `/opt/out` on the tmpfs above. Both times the entrypoint logged
the integrity match, the decrypt and both extractions; PingFederate answered on the token endpoint; the
JVM's `/proc/<pid>/environ` held `PF_ARCHIVE_FILE` and `PF_ARCHIVE_SHA256` and neither identity variable,
and the identity's text was nowhere in it; `Umask: 0077`; both mounted files were untouched; and the
simulator's endpoint, jar present, answered 404.

**The layer trap.** Staging the key and deleting it in a later `RUN` does *not* remove it: the earlier
layer still carries it and `docker save` yields it. The plaintext path demonstrably does this. Only
never putting it in a layer works.

> **Transitional.** A plaintext `data.zip` still builds, and boots under `OIDF_DEPLOYMENT_PROFILE=development`
> with a loud warning, so the rig is not broken between now and the master-key rotation. Phase 3 (R-I3)
> drops that branch from `pf-entrypoint.sh` and the `overlay/` key handling from the Dockerfile.

## Testing the entrypoint

```sh
build/pingfederate/test-entrypoint.sh                        # here: needs age, age-keygen, zip, unzip
build/pingfederate/test-entrypoint.sh --image <built image>  # the same inside the image, which has them
```

Each case boots the entrypoint from a fresh data directory under `env -i`, with the base image's
`bootstrap.sh` replaced by a stub that records its environment, umask, working directory and arguments,
and asserts on what was written, what was refused and what PingFederate would have seen. It becomes a CI
step in Phase 2 (plan item R-CI6). Every script in this directory is shellcheck-clean (0.11.0, 2026-09-27).

Because the modules sit at the **root** context, their endpoints have no `/oidf` prefix - the challenge
endpoint is `/federation/attestation-challenge`, and `/.well-known/ssf-configuration` is at root.
Repoint any `/oidf/*` consumers accordingly.
