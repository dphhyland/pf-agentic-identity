#!/bin/sh
#
# Boot shim: check the PF config archive, decrypt it, put it where the drop-in deployer looks, then hand
# over to the base image's bootstrap with the decryption key gone from the environment.
#
# WHY THIS EXISTS. A PF configArchive is a plain zip that CONTAINS pf.jwk - the master key that
# decrypts every secret inside it - along with the system keys, both keystores and the admin password
# hash. Baking one into an image layer publishes the key to anyone who can pull the image, exactly as
# committing one publishes it to anyone who can clone the repo. This project has done both.
#
# Note a layer trap this also closes: staging the key and deleting it in a later RUN does NOT remove it
# from the image - the earlier layer still carries it, and `docker save` yields it. The only version
# that holds is never putting it in a layer at all.
#
# So the archive ships encrypted with age, and is decrypted here, at boot, using an identity supplied
# as a mounted secret file or a sealed runtime variable that is never in git and never in a layer.
#
# WHERE THE PLAINTEXT GOES. Into the drop-in directory under PF_DATA_DIR, on the container's writable
# layer - not a tmpfs, unless one is mounted there (README.md: "Where the plaintext lives"). The base
# image's bootstrap then copies PF_DATA_DIR, like everything under /opt/in, into /opt/staging and
# /opt/out/instance, so the plaintext archive and the keys exist in three places for the life of the
# container. What this script guarantees is narrower and holds: none of them is in an image layer.
#
# THE ONE SECRET. pf.jwk is NOT supplied separately. It is extracted from the archive, which keeps the
# invariant that matters: the running key is by construction the key the archive was encrypted under.
# Supplying them separately is how an archive and a key drift apart, and a PF whose key does not match
# its archive fails in a way that reads like data corruption.
#
# Env:
#   PF_ARCHIVE_FILE          the archive to boot from: age-encrypted (preferred; binary or `age -a` armored)
#                            or a plain configArchive, told apart by content. Default: data.zip.age in the
#                            drop-in directory, else data.zip there. A mounted secret is the usual reason
#                            to set it.
#   PF_ARCHIVE_AGE_KEY_FILE  a path to the age identity (a mounted secret file). Preferred.
#   PF_ARCHIVE_AGE_KEY       the identity itself (AGE-SECRET-KEY-1...). Read only when _FILE is unset.
#                            Both are removed from the environment before PingFederate starts.
#   PF_ARCHIVE_SHA256        optional: the archive's SHA-256, hex. Checked before the archive is decrypted
#                            or imported; a mismatch stops the boot.
#   OIDF_DEPLOYMENT_PROFILE  development lets a plaintext archive boot; production - the default when
#                            unset, and what any other value counts as - refuses it. The Java modules read
#                            it through libs/platform's DeploymentProfile; DeploymentProfileShellTest holds
#                            is_development to that rule (they differ only on padding, F-0161).
#   PF_DATA_DIR              where the archive and keys go (default /opt/in/instance/server/default/data).
#   PF_BOOTSTRAP             the base image's bootstrap (default /opt/bootstrap.sh); test-entrypoint.sh
#                            points it at a stub.
#
set -eu
# Before anything is written: the decrypted archive, the keys and every file the base image's bootstrap
# goes on to copy or create are readable by this user alone.
umask 077

DATA_DIR="${PF_DATA_DIR:-/opt/in/instance/server/default/data}"
DROP_IN="$DATA_DIR/drop-in-deployer"
ENCRYPTED="$DROP_IN/data.zip.age"
ARCHIVE="$DROP_IN/data.zip"
BOOTSTRAP="${PF_BOOTSTRAP:-/opt/bootstrap.sh}"
PROFILE="${OIDF_DEPLOYMENT_PROFILE:-production}"

log() { echo "pf-entrypoint: $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# sha256sum is busybox and GNU; shasum is macOS, where test-entrypoint.sh may run.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
# An age file starts with its version line, or with the PEM header of the armor `age -a` writes (the C2SP
# age spec: RFC 7468 encoding, label "AGE ENCRYPTED FILE"; both seen from age 1.3.1 on 2026-09-27, which
# decrypts either without being told which). Nothing else is decrypted. The bytes stay in a pipe rather
# than a shell variable: a zip has NULs in its first 34.
is_age() { head -c 34 "$1" | head -n 1 | grep -qsE '^(age-encryption\.org/v1|-----BEGIN AGE ENCRYPTED FILE-----)$'; }
is_development() { [ "$(printf '%s' "$PROFILE" | tr '[:upper:]' '[:lower:]')" = development ]; }

# --- which archive ---
if [ -n "${PF_ARCHIVE_FILE:-}" ]; then
    [ -f "$PF_ARCHIVE_FILE" ] || die "PF_ARCHIVE_FILE=$PF_ARCHIVE_FILE is not a file"
    SOURCE="$PF_ARCHIVE_FILE"
elif [ -f "$ENCRYPTED" ]; then
    SOURCE="$ENCRYPTED"
elif [ -f "$ARCHIVE" ]; then
    SOURCE="$ARCHIVE"
else
    SOURCE=""
fi

# --- integrity, before the archive is decrypted or imported ---
if [ -n "$SOURCE" ] && [ -n "${PF_ARCHIVE_SHA256:-}" ]; then
    want="$(printf '%s' "$PF_ARCHIVE_SHA256" | tr 'A-F' 'a-f')"
    case "$want" in
        *[!0-9a-f]* | "") die "PF_ARCHIVE_SHA256 is not a hex SHA-256" ;;
    esac
    [ "${#want}" -eq 64 ] || die "PF_ARCHIVE_SHA256 is not a hex SHA-256 (64 digits; got ${#want})"
    have="$(sha256_of "$SOURCE")"
    [ "$have" = "$want" ] || die "$SOURCE does not match PF_ARCHIVE_SHA256: its sha256 is $have"
    log "archive integrity: $SOURCE matches PF_ARCHIVE_SHA256"
fi

if [ -z "$SOURCE" ]; then
    log "no config archive present; PF will boot with whatever configuration is already in $DATA_DIR"

elif is_age "$SOURCE"; then
    command -v age >/dev/null 2>&1 || die "$SOURCE is age-encrypted but 'age' is not installed in this image"
    mkdir -p "$DROP_IN"
    rm -f "$ARCHIVE"
    log "decrypting $SOURCE"
    # Fail closed and loudly on a missing identity: booting without it would either start PF with no
    # config at all or fall through to a stale plaintext archive, and both look like a working deploy.
    # The inline identity goes to age on a pipe - never a temp file, never an argument - and _FILE is
    # the operator's file: read, not deleted.
    if [ -n "${PF_ARCHIVE_AGE_KEY_FILE:-}" ]; then
        [ -f "$PF_ARCHIVE_AGE_KEY_FILE" ] || die "PF_ARCHIVE_AGE_KEY_FILE=$PF_ARCHIVE_AGE_KEY_FILE does not exist"
        age --decrypt --identity "$PF_ARCHIVE_AGE_KEY_FILE" --output "$ARCHIVE" "$SOURCE" \
            || die "could not decrypt the config archive - wrong identity in PF_ARCHIVE_AGE_KEY_FILE, or the file is not age-encrypted"
    elif [ -n "${PF_ARCHIVE_AGE_KEY:-}" ]; then
        printf '%s\n' "$PF_ARCHIVE_AGE_KEY" | age --decrypt --identity - --output "$ARCHIVE" "$SOURCE" \
            || die "could not decrypt the config archive - wrong identity in PF_ARCHIVE_AGE_KEY, or the file is not age-encrypted"
    else
        die "$SOURCE is age-encrypted but neither PF_ARCHIVE_AGE_KEY_FILE nor PF_ARCHIVE_AGE_KEY is set"
    fi
    # The ciphertext has served its purpose; only the copy the image carries is ours to remove.
    [ "$SOURCE" != "$ENCRYPTED" ] || rm -f "$ENCRYPTED"
    log "config archive ready"

else
    # A plaintext archive: the master key is in it, and if it came baked into the image it is in a layer
    # too. That is the thing this script exists to replace, so production refuses it - and production is
    # what an unset profile means. A rig says so explicitly.
    is_development || die "a plaintext archive ($SOURCE) is refused when OIDF_DEPLOYMENT_PROFILE is production (it is '$PROFILE', and unset means production). Ship data.zip.age - see build/pingfederate/README.md - or set OIDF_DEPLOYMENT_PROFILE=development on a rig"
    if [ "$SOURCE" != "$ARCHIVE" ]; then
        mkdir -p "$DROP_IN"
        cp "$SOURCE" "$ARCHIVE"
    fi
    log "WARNING: booting from a PLAINTEXT archive ($SOURCE) because OIDF_DEPLOYMENT_PROFILE=$PROFILE."
    log "WARNING: The archive - and the master key inside it - are on disk in the clear, and if the archive"
    log "WARNING: was baked into the image they are in an image layer too. Ship data.zip.age instead."
fi

if [ -n "$SOURCE" ]; then
    # The key travels INSIDE the archive; take it from there rather than from a second variable, on the
    # plaintext path as well - the overlay/ keys the Dockerfile still stages for that path are the same
    # files, lifted out of the same archive.
    for member in pf.jwk pingfederate-system-keys.xml; do
        if unzip -o -q -j "$ARCHIVE" "$member" -d "$DATA_DIR" 2>/dev/null; then
            chmod 600 "$DATA_DIR/$member"
            log "extracted $member from the archive"
        else
            die "$member is not in the archive - it is not a PF configArchive, or it was stripped"
        fi
    done
    chmod 600 "$ARCHIVE"
fi

# Nothing that runs from here - the base image's hooks, PingFederate, a shell in the container - sees the
# identity. It stays in the container's metadata (docker inspect) when passed inline, which is the reason
# to prefer the file.
unset PF_ARCHIVE_AGE_KEY PF_ARCHIVE_AGE_KEY_FILE

cd "$(dirname "$BOOTSTRAP")"
exec "$BOOTSTRAP" "$@"
