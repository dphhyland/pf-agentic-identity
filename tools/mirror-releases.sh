#!/usr/bin/env bash
# Mirror the releases published before the split onto ID-Partners/pf-agentic-identity, once, by hand: the
# public repository's first commits and releases. Run from a checkout of the private repository with your own
# gh credentials (gh auth status), never in CI and never with PUBLIC_REPO_TOKEN.
#
#   tools/mirror-releases.sh [--dry-run] [--only <tag>] [--work <dir>]
#
# One row per tag, in order, in TABLE below: the tag, whether the public tree is docs alone (v0.3.0-v0.5.0: no
# image/ or demo/, those releases cannot stage an image), docs only, or full (v0.6.0: image/ and demo/ exported
# from the tag, though they build from source - the tag's assets carry no war assembler), and the assets of the
# original release the mirror leaves out (v0.3.0's pf.plugins.ciba-sim.jar, the simulator that ran on
# OIDF_CIBA_SIM_ENABLED alone, F-0120). For each tag: the internal release's assets are downloaded and checked
# against its SHA256SUMS (--ignore-missing only for an omitted asset); tools/export-public.py exports the tag's
# tree; it is committed "Release <v> (mirrored)" with the author and committer dates set to the internal
# release's publishedAt, and tagged. --dry-run stops there, printing each tree and body. Otherwise main and the
# tag are pushed, the release is created with the assets minus omissions (--latest on the last row only), and
# every asset is downloaded again with no credentials and checked. The public repository must be empty or hold
# exactly a prefix of this sequence, so the script can be re-run after a failure and never overwrites a commit it
# did not make. Nothing is force-pushed.
set -euo pipefail

SOURCE_REPO=dphhyland/pf-agentic-identity
PUBLIC_REPO=ID-Partners/pf-agentic-identity
# tag  mode(docs-alone|docs-only|full)  omitted assets (comma-separated, or -)
TABLE=(
  "v0.3.0 docs-alone pf.plugins.ciba-sim.jar"
  "v0.4.0 docs-alone -"
  "v0.5.0 docs-alone -"
  "v0.6.0 full -"
)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=false ONLY="" WORK=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown argument $1" >&2; exit 2 ;;
  esac
done
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/mirror-releases.XXXXXX")}"
mkdir -p "$WORK"
die() { echo "ERROR: $*" >&2; exit 1; }
command -v gh > /dev/null || die "gh is needed"
gh auth status > /dev/null 2>&1 || die "gh is not signed in; the mirror runs with your own credentials"
[ -z "${GH_TOKEN:-}" ] || die "GH_TOKEN is set: the mirror runs with your own gh login, not a token in the environment"
echo "work directory: $WORK"

# The public clone: empty, or exactly a prefix of the sequence.
CLONE="$WORK/public"
if [ ! -d "$CLONE/.git" ]; then
  if ! git clone --quiet "https://github.com/$PUBLIC_REPO.git" "$CLONE" 2> "$WORK/clone.err"; then
    if [ "$DRY_RUN" = true ]; then
      echo "note: $PUBLIC_REPO could not be cloned ($(tr '\n' ' ' < "$WORK/clone.err")); the dry run works in an empty local repository"
      git init --quiet -b main "$CLONE"
    else
      die "cannot clone $PUBLIC_REPO: $(cat "$WORK/clone.err")"
    fi
  fi
fi
if git -C "$CLONE" rev-parse --verify -q HEAD > /dev/null; then
  git -C "$CLONE" checkout --quiet main 2>/dev/null || git -C "$CLONE" checkout --quiet -b main
  mapfile -t have < <(git -C "$CLONE" log --reverse --format=%s main)
  expected=()
  for row in "${TABLE[@]}"; do read -r tag _ _ <<< "$row"; expected+=("Release ${tag#v} (mirrored)"); done
  for i in "${!have[@]}"; do
    [ "${have[$i]}" = "${expected[$i]:-}" ] || die "$PUBLIC_REPO main's commit $((i + 1)) is '${have[$i]}', not '${expected[$i]:-<nothing>}': not a prefix of the mirror sequence; nothing is touched"
  done
  done_rows=${#have[@]}
  echo "$PUBLIC_REPO already holds $done_rows mirrored release(s)"
else
  git -C "$CLONE" checkout --quiet -b main 2>/dev/null || true
  done_rows=0
  echo "$PUBLIC_REPO is empty: the first mirrored commit is its root"
fi

LAST_TAG=""
for row in "${TABLE[@]}"; do read -r LAST_TAG _ _ <<< "$row"; done

i=0
for row in "${TABLE[@]}"; do
  read -r TAG MODE OMIT <<< "$row"
  i=$((i + 1))
  VERSION="${TAG#v}"
  if [ $i -le "$done_rows" ]; then echo "== $TAG: already mirrored"; continue; fi
  if [ -n "$ONLY" ] && [ "$ONLY" != "$TAG" ]; then echo "== $TAG: skipped (--only $ONLY)"; continue; fi
  echo "== $TAG ($MODE, omitting ${OMIT})"
  git -C "$ROOT" rev-parse --verify -q "refs/tags/$TAG" > /dev/null || die "$TAG is not a tag in $ROOT (git fetch --tags)"

  # 1. The internal release's assets, verified.
  ASSETS="$WORK/assets/$VERSION"
  rm -rf "$ASSETS"; mkdir -p "$ASSETS"
  gh release download "$TAG" --repo "$SOURCE_REPO" --dir "$ASSETS"
  published="$(gh release view "$TAG" --repo "$SOURCE_REPO" --json publishedAt --jq .publishedAt)"
  omit_args=()
  if [ "$OMIT" != - ]; then
    IFS=, read -r -a omitted <<< "$OMIT"
    for a in "${omitted[@]}"; do
      [ -f "$ASSETS/$a" ] || die "$TAG has no asset $a to omit"
      rm -f "$ASSETS/$a"
      omit_args+=(--omit "$a=not mirrored: the $VERSION CIBA simulator runs on \`OIDF_CIBA_SIM_ENABLED\` alone (F-0120); verify with \`sha256sum -c --ignore-missing\`")
    done
    ( cd "$ASSETS" && sha256sum -c --ignore-missing --quiet SHA256SUMS )
  else
    ( cd "$ASSETS" && sha256sum -c --strict --quiet SHA256SUMS )
  fi
  echo "   assets verified: $(find "$ASSETS" -type f | wc -l | tr -d ' ') files, published $published"

  # 2. The tag's public tree.
  TREE="$WORK/tree/$VERSION"
  rm -rf "$TREE"
  case "$MODE" in
    docs-alone) python3 "$ROOT/tools/export-public.py" --source-ref "$TAG" --version "$VERSION" --docs-alone "$TREE" ;;
    docs-only)  python3 "$ROOT/tools/export-public.py" --source-ref "$TAG" --version "$VERSION" --docs-only "$TREE" ;;
    full)       python3 "$ROOT/tools/export-public.py" --source-ref "$TAG" --version "$VERSION" "$TREE" ;;
    *) die "unknown mode $MODE for $TAG" ;;
  esac
  BODY="$WORK/body-$VERSION.md"
  python3 "$ROOT/tools/public-release-body.py" "$VERSION" --tree "$TREE" --source-ref "$TAG" --sums "$ASSETS/SHA256SUMS" \
    --mirrored --date "$(date -u +%Y-%m-%d)" ${omit_args[@]+"${omit_args[@]}"} -o "$BODY"

  # 3. The commit and the tag, dated as the original release was.
  ( cd "$CLONE" && find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} + )
  cp -R "$TREE"/. "$CLONE"/
  git -C "$CLONE" add -A
  GIT_AUTHOR_DATE="$published" GIT_COMMITTER_DATE="$published" \
    git -C "$CLONE" -c user.name="pf-agentic-identity release" -c user.email="release@pf-agentic-identity.invalid" \
    commit --quiet -m "Release $VERSION (mirrored)"
  GIT_COMMITTER_DATE="$published" git -C "$CLONE" -c user.name="pf-agentic-identity release" \
    -c user.email="release@pf-agentic-identity.invalid" tag -a "$TAG" -m "pf-agentic-identity $VERSION (mirrored)"
  echo "   committed $(git -C "$CLONE" rev-parse --short HEAD) and tagged $TAG"
  if [ "$DRY_RUN" = true ]; then
    echo "   --- tree"; ( cd "$TREE" && find . -type f | sort | sed 's/^/   /' )
    echo "   --- body ($BODY)"; sed 's/^/   | /' "$BODY"
    continue
  fi

  # 4. Push, release, and the anonymous check.
  git -C "$CLONE" push --quiet "https://github.com/$PUBLIC_REPO.git" main "refs/tags/$TAG"
  latest=(); [ "$TAG" = "$LAST_TAG" ] && latest=(--latest)
  if ! gh release view "$TAG" --repo "$PUBLIC_REPO" > /dev/null 2>&1; then
    gh release create "$TAG" "$ASSETS"/* --repo "$PUBLIC_REPO" --verify-tag --title "pf-agentic-identity $VERSION" \
      --notes-file "$BODY" ${latest[@]+"${latest[@]}"}
  else
    echo "   release $TAG already exists on $PUBLIC_REPO: left as it is"
  fi
  ANON="$WORK/anon/$VERSION"; rm -rf "$ANON"; mkdir -p "$ANON"
  base="https://github.com/$PUBLIC_REPO/releases/download/$TAG"
  deadline=$((SECONDS + 300))
  until curl -fsSL -o "$ANON/SHA256SUMS" "$base/SHA256SUMS" 2>/dev/null && cmp -s "$ANON/SHA256SUMS" "$ASSETS/SHA256SUMS"; do
    [ $SECONDS -lt $deadline ] || die "$base/SHA256SUMS is not the release's after five minutes"
    sleep 15
  done
  while read -r _ name; do
    [ "$name" = SHA256SUMS ] && continue
    [ -f "$ASSETS/$name" ] || continue      # an omitted asset
    until curl -fsSL -o "$ANON/$name" "$base/$name" 2>/dev/null; do
      [ $SECONDS -lt $deadline ] || die "$base/$name could not be downloaded after five minutes"
      sleep 15
    done
  done < "$ANON/SHA256SUMS"
  ( cd "$ANON" && sha256sum -c --ignore-missing --quiet SHA256SUMS )
  for f in "$ASSETS"/*; do [ -f "$ANON/$(basename "$f")" ] || die "$(basename "$f") was not uploaded to $TAG on $PUBLIC_REPO"; done
  echo "   $TAG on $PUBLIC_REPO: every mirrored asset verifies anonymously"
done
echo "done"
