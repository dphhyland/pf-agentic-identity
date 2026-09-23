#!/usr/bin/env bash
# Render suite/*.template.json into suite/*.json - the configurations you paste into, or post to, a
# conformance suite. The rendered files carry the clients' PRIVATE keys and the test user's password,
# so they are git-ignored; the templates carry neither and are not.
#
#   PF_BASE_URL   defaults to terraform's pf_base_url default
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; RIG="$(dirname "$HERE")"
BASE="${PF_BASE_URL:-$(sed -n 's/^  default *= *"\(https:[^"]*\)"$/\1/p' "$RIG/terraform/variables.tf" | head -1)}"
[[ -n "$BASE" ]] || { echo "ERROR: could not determine PF_BASE_URL" >&2; exit 1; }
umask 177
PF_BASE_URL="$BASE" RIG="$RIG" python3 - "$HERE"/*.template.json <<'PY'
import json, os, re, sys
rig, base = os.environ["RIG"], os.environ["PF_BASE_URL"]
secrets = dict(l.strip().split("=", 1) for l in open(f"{rig}/secrets.env") if "=" in l and not l.startswith("#"))
def fill(node):
    if isinstance(node, dict): return {k: fill(v) for k, v in node.items()}
    if isinstance(node, list): return [fill(v) for v in node]
    if isinstance(node, str):
        m = re.fullmatch(r"\{\{JWKS:([a-z0-9-]+)\}\}", node)
        if m: return json.load(open(f"{rig}/keys/{m.group(1)}.private.jwks.json"))
        return node.replace("{{PF_BASE_URL}}", base).replace("{{TEST_USER_PASSWORD}}", secrets["TF_VAR_test_user_password"])
    return node
for template in sys.argv[1:]:
    out = template.replace(".template.json", ".json")
    json.dump(fill(json.load(open(template))), open(out, "w"), indent=2)
    print("rendered", os.path.basename(out))
PY
