#!/bin/sh
#
# Boot shim: decrypt the PF config archive, then hand over to the base image's bootstrap.
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
# So the archive ships encrypted with age, and is decrypted here, at boot, into a tmpfs-backed path -
# using an identity supplied as a sealed runtime variable that is never in git and never in a layer.
#
# THE ONE SECRET. pf.jwk is NOT supplied separately. It is extracted from the archive after decryption,
# which keeps the invariant that matters: the running key is by construction the key the archive was
# encrypted under. Supplying them separately is how an archive and a key drift apart, and a PF whose
# key does not match its archive fails in a way that reads like data corruption.
#
# Env:
#   PF_ARCHIVE_AGE_KEY   the age identity (AGE-SECRET-KEY-1...). Required when data.zip.age is present.
#   PF_ARCHIVE_AGE_KEY_FILE  alternatively, a path to it (a mounted secret file).
#
set -eu

DATA_DIR="${PF_DATA_DIR:-/opt/in/instance/server/default/data}"
DROP_IN="$DATA_DIR/drop-in-deployer"
ENCRYPTED="$DROP_IN/data.zip.age"
ARCHIVE="$DROP_IN/data.zip"

log() { echo "pf-entrypoint: $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

if [ -f "$ENCRYPTED" ]; then
    command -v age >/dev/null 2>&1 || die "data.zip.age is present but 'age' is not installed in this image"

    # Resolve the identity. Fail closed and loudly: booting without it would either start PF with no
    # config at all or fall through to a stale plaintext archive, and both look like a working deploy.
    identity_file=""
    cleanup() { [ -n "$identity_file" ] && [ -f "$identity_file" ] && rm -f "$identity_file" || true; }
    trap cleanup EXIT HUP INT TERM

    if [ -n "${PF_ARCHIVE_AGE_KEY_FILE:-}" ]; then
        [ -f "$PF_ARCHIVE_AGE_KEY_FILE" ] || die "PF_ARCHIVE_AGE_KEY_FILE=$PF_ARCHIVE_AGE_KEY_FILE does not exist"
        identity_file="$PF_ARCHIVE_AGE_KEY_FILE"
    elif [ -n "${PF_ARCHIVE_AGE_KEY:-}" ]; then
        identity_file="$(mktemp)"
        chmod 600 "$identity_file"
        printf '%s\n' "$PF_ARCHIVE_AGE_KEY" > "$identity_file"
    else
        die "data.zip.age is present but neither PF_ARCHIVE_AGE_KEY nor PF_ARCHIVE_AGE_KEY_FILE is set"
    fi

    log "decrypting $ENCRYPTED"
    age --decrypt --identity "$identity_file" --output "$ARCHIVE" "$ENCRYPTED" \
        || die "could not decrypt the config archive - wrong identity, or the file is not age-encrypted"
    cleanup; trap - EXIT HUP INT TERM

    # The key travels INSIDE the archive; take it from there rather than from a second variable.
    for member in pf.jwk pingfederate-system-keys.xml; do
        if unzip -o -q -j "$ARCHIVE" "$member" -d "$DATA_DIR" 2>/dev/null; then
            chmod 600 "$DATA_DIR/$member" 2>/dev/null || true
            log "extracted $member from the archive"
        else
            die "$member is not in the archive - it is not a PF configArchive, or it was stripped"
        fi
    done

    # The ciphertext has served its purpose; the plaintext archive stays for the drop-in-deployer.
    rm -f "$ENCRYPTED"
    log "config archive ready"

elif [ -f "$ARCHIVE" ]; then
    # TRANSITIONAL. This is the pre-rotation path: a plaintext archive baked into the image, with
    # pf.jwk sitting beside it in a layer. It still works so the build is not broken between now and
    # the rotation, but it is the thing this script exists to replace. Remove this branch once every
    # environment ships data.zip.age.
    log "WARNING: booting from a PLAINTEXT data.zip. The archive - and the master key inside it - are"
    log "WARNING: in an image layer. Ship data.zip.age instead; see build/pingfederate/README.md."
else
    log "no config archive present; PF will boot with whatever configuration is already in $DATA_DIR"
fi

cd /opt
exec ./bootstrap.sh "$@"
