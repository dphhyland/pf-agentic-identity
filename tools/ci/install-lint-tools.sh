#!/usr/bin/env bash
# The linters build.yml's lint job runs, and the image job's scanner and SBOM generator, at the versions and
# checksums written here, into one directory:
#
#   tools/ci/install-lint-tools.sh DIR [TOOL...]    actionlint, shellcheck, zizmor, gitleaks, grype and syft,
#                                                   or the ones named
#   PATH="DIR:$PATH"
#
# Each is a release archive from the project's own GitHub releases, checked against the sha256 recorded here
# before it is unpacked, so a build runs the binary that was reviewed and not whatever a URL serves today.
# actionlint's, gitleaks', grype's and syft's sums are the ones in their release's checksums file (grype's and
# syft's compared with the archives as downloaded on 2026-09-28); shellcheck and zizmor publish none, so theirs
# are of the archives as downloaded on 2026-09-27. grype fetches its vulnerability database when it runs: the
# binary is pinned here, the data it matches against is the day's. Linux x86_64 (the ubuntu runners) and macOS
# arm64 are recorded; another platform stops here. To move a tool: change its version and every checksum for
# it (Dependabot does not see these), run the lint job's steps by hand, and commit both.
set -euo pipefail

ACTIONLINT_VERSION=1.7.12
SHELLCHECK_VERSION=0.11.0
ZIZMOR_VERSION=1.30.1
GITLEAKS_VERSION=8.30.1
GRYPE_VERSION=0.119.0
SYFT_VERSION=1.52.0

[[ $# -ge 1 ]] || { echo "usage: $0 DIR [actionlint|shellcheck|zizmor|gitleaks|grype|syft ...]" >&2; exit 2; }
DIR="$1"; shift
TOOLS=("$@"); [[ ${#TOOLS[@]} -gt 0 ]] || TOOLS=(actionlint shellcheck zizmor gitleaks grype syft)

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) OS=linux ;;
  Darwin/arm64) OS=darwin ;;
  *) echo "ERROR: no checksum recorded for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

# sha256, URL and the binary's path inside the archive, per tool and platform.
release() {
  case "$1/$2" in
    actionlint/linux)  echo "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz actionlint" ;;
    actionlint/darwin) echo "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_darwin_arm64.tar.gz actionlint" ;;
    shellcheck/linux)  echo "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz shellcheck-v${SHELLCHECK_VERSION}/shellcheck" ;;
    shellcheck/darwin) echo "56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79 https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.darwin.aarch64.tar.xz shellcheck-v${SHELLCHECK_VERSION}/shellcheck" ;;
    zizmor/linux)      echo "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-x86_64-unknown-linux-gnu.tar.gz zizmor" ;;
    zizmor/darwin)     echo "e28d22b087f9ebb8d99da6e740d348c930f559961c7c3f12badda54f882195a2 https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-aarch64-apple-darwin.tar.gz zizmor" ;;
    gitleaks/linux)    echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz gitleaks" ;;
    gitleaks/darwin)   echo "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz gitleaks" ;;
    grype/linux)       echo "3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz grype" ;;
    grype/darwin)      echo "500c9b2b6c089d21481815f57a553fabbd441ec7d1e79d95e3aaf40c3bfc7e36 https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_darwin_arm64.tar.gz grype" ;;
    syft/linux)        echo "caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz syft" ;;
    syft/darwin)       echo "014d561b6d13059124155f74a6c5a9a99501f5e209313638dd884f39eb418ee6 https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_darwin_arm64.tar.gz syft" ;;
    *) echo "ERROR: unknown tool '$1' (actionlint, shellcheck, zizmor, gitleaks, grype or syft)" >&2; return 1 ;;
  esac
}

version_of() {
  case "$1" in
    actionlint) echo "$ACTIONLINT_VERSION" ;;
    shellcheck) echo "$SHELLCHECK_VERSION" ;;
    zizmor) echo "$ZIZMOR_VERSION" ;;
    gitleaks) echo "$GITLEAKS_VERSION" ;;
    grype) echo "$GRYPE_VERSION" ;;
    syft) echo "$SYFT_VERSION" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

mkdir -p "$DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
for tool in "${TOOLS[@]}"; do
  spec="$(release "$tool" "$OS")"
  read -r sum url member <<<"$spec"
  version="$(version_of "$tool")"
  stamp="$DIR/.$tool-$version"
  if [[ -x "$DIR/$tool" && -f "$stamp" ]]; then
    echo "kept      $tool $version"
    continue
  fi
  archive="$WORK/${url##*/}"
  curl -fsSL --retry 3 -o "$archive" "$url"
  got="$(sha256_of "$archive")"
  if [[ "$got" != "$sum" ]]; then
    echo "ERROR: $tool $version: $url has sha256 $got, not the recorded $sum" >&2
    exit 1
  fi
  mkdir -p "$WORK/$tool"
  tar -xf "$archive" -C "$WORK/$tool" "$member"
  cp "$WORK/$tool/$member" "$DIR/$tool"
  chmod 0755 "$DIR/$tool"
  rm -f "$DIR/.$tool-"*
  touch "$stamp"
  echo "installed $tool $version"
done
