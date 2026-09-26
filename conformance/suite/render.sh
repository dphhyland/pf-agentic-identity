#!/usr/bin/env bash
# Render suite/*.template.json into suite/*.json - the configurations you paste into, or post to, a
# conformance suite. The rendered files carry the clients' PRIVATE keys and the test user's password,
# so they are git-ignored; the templates carry neither and are not.
#
#   PF_BASE_URL   defaults to terraform's pf_base_url default
#   PF_LOCAL_URL  where this machine reaches PF (default https://localhost:${PF_PORT_HTTPS:-9031}), for a
#                 template that needs something only the running PF knows: {{PF_FEDERATION_JWKS}}, the
#                 jwks of its entity configuration
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; RIG="$(dirname "$HERE")"
BASE="${PF_BASE_URL:-$(sed -n 's/^  default *= *"\(https:[^"]*\)"$/\1/p' "$RIG/terraform/variables.tf" | head -1)}"
[[ -n "$BASE" ]] || { echo "ERROR: could not determine PF_BASE_URL" >&2; exit 1; }
umask 177
PF_BASE_URL="$BASE" PF_LOCAL_URL="${PF_LOCAL_URL:-https://localhost:${PF_PORT_HTTPS:-9031}}" RIG="$RIG" python3 - "$HERE"/*.template.json <<'PY'
import base64, json, os, re, ssl, sys, urllib.request
rig, base = os.environ["RIG"], os.environ["PF_BASE_URL"]
federation_jwks = None
def pf_federation_jwks():
    # The rig's PF is its own Trust Anchor, and the suite is told its keys: read them from the entity
    # configuration it serves. Fine for a rig; a real deployment pins them from somewhere it trusts.
    global federation_jwks
    if federation_jwks is None:
        insecure = ssl.create_default_context()
        insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE
        url = os.environ["PF_LOCAL_URL"] + "/.well-known/openid-federation"
        jwt = urllib.request.urlopen(url, context=insecure, timeout=15).read().decode()
        payload = jwt.split(".")[1]
        federation_jwks = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jwks"]
    return federation_jwks
secrets = dict(l.strip().split("=", 1) for l in open(f"{rig}/secrets.env") if "=" in l and not l.startswith("#"))
def fill(node):
    if isinstance(node, dict): return {k: fill(v) for k, v in node.items()}
    if isinstance(node, list): return [fill(v) for v in node]
    if isinstance(node, str):
        m = re.fullmatch(r"\{\{JWKS:([a-z0-9-]+)\}\}", node)
        if m: return json.load(open(f"{rig}/keys/{m.group(1)}.private.jwks.json"))
        if node == "{{PF_FEDERATION_JWKS}}": return pf_federation_jwks()
        m = re.fullmatch(r"\{\{PEM:([a-z0-9.-]+)\}\}", node)
        if m: return open(f"{rig}/keys/{m.group(1)}").read()  # PEM text, armour and all; the suite strips it
        return node.replace("{{PF_BASE_URL}}", base).replace("{{TEST_USER_PASSWORD}}", secrets["TF_VAR_test_user_password"])
    return node
for template in sys.argv[1:]:
    out = template.replace(".template.json", ".json")
    try:
        rendered = fill(json.load(open(template)))
    except OSError as e:
        # Only a template that needs the running PF gets here; the others render without it.
        print("skipped ", os.path.basename(template), "- PF is not answering at", os.environ["PF_LOCAL_URL"], f"({e})")
        continue
    json.dump(rendered, open(out, "w"), indent=2)
    print("rendered", os.path.basename(out))
PY
