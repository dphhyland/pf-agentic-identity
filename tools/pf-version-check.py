#!/usr/bin/env python3
"""Every place this repo names a PingFederate agrees with build/pf-version.env.

  tools/pf-version-check.py            # exit 1 with each disagreement listed
  tools/pf-version-check.py --root DIR

The env file is the one place the version is written down; this is what makes that true. Before it,
the same version was a literal in eight files, and they drifted: author.sh started a 13.0.3 while
the rig built FROM 13.1.3, and the release workflow carried its own copy of the jar-install steps.

What is checked, and against which key:
  build/pf-version.env                   the keys are all present and agree with each other
                                         (the image tag starts with PF_VERSION, the SDK version is
                                         PF_VERSION.0, the Terraform version is its major.minor, the
                                         digest is a sha256)
  bom/pom.xml                            <version.pingfederate>            = PF_SDK_MAVEN_VERSION
  services/gm-api/servlet/pom.xml        <pingfederate.version>            = PF_VERSION
  build/pingfederate/Dockerfile          FROM                              = PF_IMAGE@PF_IMAGE_DIGEST
                                         (a literal, so Dependabot can bump it; pf-version-sync.py
                                         then rewrites the env file from it)
  .github/actions/pf-provided-jars       sources the env file; no image or version literal of its own
  .github/workflows/*.yml                append the env file to $GITHUB_ENV; no image literal
  conformance/author.sh                  sources the env file; no image literal
  conformance/apply.sh                   exports TF_VAR_pf_product_version from PF_TERRAFORM_PRODUCT_VERSION
  conformance/terraform/provider.tf      product_version = var.pf_product_version
  conformance/terraform/variables.tf     pf_product_version's default      = PF_TERRAFORM_PRODUCT_VERSION
  every other file                       any pingidentity/pingfederate:<tag> reference matches PF_IMAGE,
                                         and its digest when it carries one. Markdown is exempt (prose
                                         may name a version that used to be), and so are showcase/,
                                         which is rendered from the Markdown, and tools/tests/, whose
                                         fixtures name other versions on purpose.

Exit status: 0 when everything agrees, 1 with a list otherwise, 2 when the env file cannot be read.
"""
import argparse
import os
import re
import sys

ENV_FILE = "build/pf-version.env"
KEYS = ("PF_VERSION", "PF_SDK_MAVEN_VERSION", "PF_IMAGE", "PF_IMAGE_DIGEST", "PF_TERRAFORM_PRODUCT_VERSION")
IMAGE_REF_RE = re.compile(r"pingidentity/pingfederate:([0-9][A-Za-z0-9._-]*[A-Za-z0-9])(@sha256:[0-9a-f]{64})?")
SWEEP_SKIP_DIRS = {".git", "node_modules", "target", ".claude", "showcase", ".terraform", "__pycache__"}
SWEEP_SKIP_PATHS = {os.path.join("tools", "tests")}


def read_env(path):
    """KEY=VALUE lines; comments and blanks ignored. No quoting, no expansion - bash, $GITHUB_ENV and
    this file must all read the same value."""
    values = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"{path}:{n}: not KEY=VALUE: {line}")
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    return values


def _read(root, rel):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def _xml_text(data, element):
    m = re.search(r"<%s>\s*([^<\s]+)\s*</%s>" % (re.escape(element), re.escape(element)), data or "")
    return m.group(1) if m else None


def check_env(env, problems):
    for k in KEYS:
        if not env.get(k):
            problems.append(f"{ENV_FILE}: {k} is missing")
    if any(not env.get(k) for k in KEYS):
        return False
    v = env["PF_VERSION"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v):
        problems.append(f"{ENV_FILE}: PF_VERSION {v!r} is not major.minor.patch")
    if env["PF_SDK_MAVEN_VERSION"] != v + ".0":
        problems.append(f"{ENV_FILE}: PF_SDK_MAVEN_VERSION {env['PF_SDK_MAVEN_VERSION']} is not PF_VERSION.0 ({v}.0)")
    tag = env["PF_IMAGE"].split(":", 1)[1] if ":" in env["PF_IMAGE"] else ""
    if not env["PF_IMAGE"].startswith("pingidentity/pingfederate:") or not tag.startswith(v + "-") and tag != v:
        problems.append(f"{ENV_FILE}: PF_IMAGE {env['PF_IMAGE']} is not a pingidentity/pingfederate tag for {v}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", env["PF_IMAGE_DIGEST"]):
        problems.append(f"{ENV_FILE}: PF_IMAGE_DIGEST {env['PF_IMAGE_DIGEST']!r} is not sha256:<64 hex>")
    if env["PF_TERRAFORM_PRODUCT_VERSION"] != ".".join(v.split(".")[:2]):
        problems.append(f"{ENV_FILE}: PF_TERRAFORM_PRODUCT_VERSION {env['PF_TERRAFORM_PRODUCT_VERSION']} is not PF_VERSION's major.minor")
    return True


def check_files(root, env, problems):
    image_ref = f"{env['PF_IMAGE']}@{env['PF_IMAGE_DIGEST']}"

    bom = _read(root, "bom/pom.xml")
    got = _xml_text(bom, "version.pingfederate")
    if got != env["PF_SDK_MAVEN_VERSION"]:
        problems.append(f"bom/pom.xml: <version.pingfederate> is {got}, PF_SDK_MAVEN_VERSION is {env['PF_SDK_MAVEN_VERSION']}")

    gm = _read(root, "services/gm-api/servlet/pom.xml")
    got = _xml_text(gm, "pingfederate.version")
    if got != env["PF_VERSION"]:
        problems.append(f"services/gm-api/servlet/pom.xml: <pingfederate.version> is {got}, PF_VERSION is {env['PF_VERSION']}")

    df = _read(root, "build/pingfederate/Dockerfile")
    froms = re.findall(r"^FROM\s+(\S+)", df or "", re.M)
    if not froms:
        problems.append("build/pingfederate/Dockerfile: no FROM line")
    for f in froms:
        if f != image_ref:
            problems.append(f"build/pingfederate/Dockerfile: FROM {f} is not {image_ref}")

    action = _read(root, ".github/actions/pf-provided-jars/action.yml")
    if action is None:
        problems.append(".github/actions/pf-provided-jars/action.yml: missing")
    else:
        if ENV_FILE not in action:
            problems.append(f".github/actions/pf-provided-jars/action.yml: does not read {ENV_FILE}")
        for lit in re.findall(r"\b1[0-9]\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\b", action):
            problems.append(f".github/actions/pf-provided-jars/action.yml: carries the version literal {lit}; read it from {ENV_FILE}")

    wf_dir = os.path.join(root, ".github/workflows")
    for name in sorted(os.listdir(wf_dir)) if os.path.isdir(wf_dir) else []:
        if not name.endswith((".yml", ".yaml")):
            continue
        wf = _read(root, f".github/workflows/{name}")
        if not re.search(r"pf-version\.env.*>>\s*\"?\$GITHUB_ENV", wf):
            problems.append(f".github/workflows/{name}: does not append {ENV_FILE} to $GITHUB_ENV")

    author = _read(root, "conformance/author.sh")
    if author is None or "pf-version.env" not in author:
        problems.append(f"conformance/author.sh: does not source {ENV_FILE}")

    apply_sh = _read(root, "conformance/apply.sh")
    if apply_sh is None or not re.search(r"TF_VAR_pf_product_version=\"?\$\{?PF_TERRAFORM_PRODUCT_VERSION", apply_sh):
        problems.append("conformance/apply.sh: does not export TF_VAR_pf_product_version from PF_TERRAFORM_PRODUCT_VERSION")

    provider = _read(root, "conformance/terraform/provider.tf")
    if provider is None or not re.search(r"product_version\s*=\s*var\.pf_product_version", provider):
        problems.append("conformance/terraform/provider.tf: product_version is not var.pf_product_version")

    variables = _read(root, "conformance/terraform/variables.tf")
    m = re.search(r'variable\s+"pf_product_version"\s*\{.*?default\s*=\s*"([^"]*)"', variables or "", re.S)
    if not m:
        problems.append("conformance/terraform/variables.tf: no pf_product_version variable with a default")
    elif m.group(1) != env["PF_TERRAFORM_PRODUCT_VERSION"]:
        problems.append(f"conformance/terraform/variables.tf: pf_product_version defaults to {m.group(1)}, PF_TERRAFORM_PRODUCT_VERSION is {env['PF_TERRAFORM_PRODUCT_VERSION']}")


def sweep(root, env, problems):
    """Every pingidentity/pingfederate:<tag> outside Markdown and the rendered showcase."""
    want_tag = env["PF_IMAGE"].split(":", 1)[1]
    want_digest = "@" + env["PF_IMAGE_DIGEST"]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SWEEP_SKIP_DIRS
                             and os.path.relpath(os.path.join(dirpath, d), root) not in SWEEP_SKIP_PATHS)
        for fn in sorted(filenames):
            if fn.endswith(".md"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            if b"pingidentity/pingfederate:" not in raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            rel = os.path.relpath(p, root)
            for n, line in enumerate(text.splitlines(), 1):
                for m in IMAGE_REF_RE.finditer(line):
                    tag, digest = m.group(1), m.group(2)
                    if tag != want_tag:
                        problems.append(f"{rel}:{n}: pingidentity/pingfederate:{tag} is not the {want_tag} in {ENV_FILE}")
                    elif digest and digest != want_digest:
                        problems.append(f"{rel}:{n}: digest {digest[1:]} is not PF_IMAGE_DIGEST")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the repo root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    env_path = os.path.join(root, ENV_FILE)
    try:
        env = read_env(env_path)
    except (OSError, ValueError) as e:
        print(f"error: cannot read {ENV_FILE}: {e}", file=sys.stderr)
        return 2
    problems = []
    if check_env(env, problems):
        check_files(root, env, problems)
        sweep(root, env, problems)
    if problems:
        print(f"error: {len(problems)} disagreement(s) with {ENV_FILE}:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"ok: PingFederate {env['PF_VERSION']} ({env['PF_IMAGE']}@{env['PF_IMAGE_DIGEST'][:19]}...) everywhere it is named")
    return 0


if __name__ == "__main__":
    sys.exit(main())
