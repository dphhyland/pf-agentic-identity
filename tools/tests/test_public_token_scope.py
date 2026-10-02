"""PUBLIC_REPO_TOKEN, the token that can push to ID-Partners/pf-agentic-identity, stays where it belongs: only in
release.yml's public-preflight and publish-public jobs, in a workflow no pull request starts. Plain-text parsing
of the workflows, as the other tool tests do (no YAML library on the runner); fixtures that break each rule
fail."""
import os
import re
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
TOKEN = "PUBLIC_REPO_TOKEN"
PUBLIC_JOBS = ("public-preflight", "publish-public")


def jobs(text):
    """{job id: its lines}, read from the two-space-indented keys under the top-level `jobs:`."""
    out, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            in_jobs = line.rstrip() == "jobs:"
            current = None
            continue
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$", line)
        if m:
            current = m.group(1)
            out[current] = []
        elif current is not None:
            out[current].append(line)
    return out


def triggers(text):
    """The keys directly under the top-level `on:` (or `"on":`), and push's own keys."""
    keys, push_keys, in_on, in_push = [], [], False, False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            in_on = re.match(r"^['\"]?on['\"]?:\s*$", line) is not None
            in_push = False
            continue
        if not in_on or not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^  ([A-Za-z_]+):", line)
        if m:
            keys.append(m.group(1))
            in_push = m.group(1) == "push"
            continue
        m = re.match(r"^    ([A-Za-z_-]+):", line)
        if m and in_push:
            push_keys.append(m.group(1))
    return keys, push_keys


def run_blocks(lines):
    """Each `run:` value of a job, inline or as a block scalar."""
    blocks, i = [], 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if m:
            indent = len(m.group(1))
            value = m.group(2)
            body = [] if value.strip() in ("|", ">", "|-", ">-", "") else [value]
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            blocks.append("\n".join(body))
            continue
        i += 1
    return blocks


def problems(files):
    """Every rule broken by {workflow file name: text}."""
    out = []
    for name, text in sorted(files.items()):
        if re.search(r"^\s*['\"]?pull_request_target['\"]?\s*:", text, re.M) or re.search(r"\bpull_request_target\b", text.split("jobs:")[0]):
            out.append(f"{name}: has a pull_request_target trigger")
        # A job can be handed every secret without naming one: toJSON(secrets) (or the secrets context passed
        # whole anywhere else), and a reusable-workflow call with `secrets: inherit`.
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        expressions = re.findall(r"\$\{\{(.*?)\}\}", code, re.S)
        if any(re.search(r"\bsecrets\b(?!\s*\.\s*[A-Za-z_])", e) for e in expressions):
            out.append(f"{name}: uses the secrets context whole (toJSON(secrets) or the like), which would hand out {TOKEN}")
        if re.search(r"^\s*secrets:\s*['\"]?inherit\b", code, re.M):
            out.append(f"{name}: passes secrets: inherit, which would hand out {TOKEN}")
        if TOKEN not in text:
            continue
        if name != "release.yml":
            out.append(f"{name}: names {TOKEN}, which only release.yml's public jobs may hold")
            continue
    release = files.get("release.yml")
    if release is None:
        return out + ["release.yml: missing"]
    keys, push_keys = triggers(release)
    if sorted(keys) != ["push", "workflow_dispatch"]:
        out.append(f"release.yml: triggers are {keys}, not push (tags) and workflow_dispatch only")
    if push_keys != ["tags"]:
        out.append(f"release.yml: push is filtered by {push_keys}, not tags alone")
    found = jobs(release)
    outside = release
    for job in PUBLIC_JOBS:
        if job in found:
            outside = outside.replace("\n".join(found[job]), "")
    if TOKEN in "\n".join(l for l in outside.splitlines() if not l.lstrip().startswith("#")):
        out.append(f"release.yml: names {TOKEN} outside {' and '.join(PUBLIC_JOBS)}")
    for job in PUBLIC_JOBS:
        lines = found.get(job, [])
        if any(re.match(r"^\s*persist-credentials:\s*['\"]?true", l) for l in lines):
            out.append(f"release.yml: {job} sets persist-credentials: true")
        for block in run_blocks(lines):
            # Any expression in a run: that reaches an input or the event, also through a function such as
            # format('{0}', inputs.version), is spliced into the script before it runs.
            if any(re.search(r"\b(inputs|github\.event)\b", e) for e in re.findall(r"\$\{\{(.*?)\}\}", block, re.S)):
                out.append(f"release.yml: {job} expands an input or github.event inside run: (pass it through env:)")
    return out


def read_workflows():
    files = {}
    for name in os.listdir(WORKFLOWS):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
                files[name] = f.read()
    return files


RELEASE = """name: Release
on:
  push:
    tags: ['v*']
  workflow_dispatch:
    inputs:
      version:
        required: false
permissions: {}
jobs:
  public-preflight:
    runs-on: ubuntu-latest
    steps:
      - name: check
        env:
          PUBLIC_REPO_TOKEN: ${{ secrets.PUBLIC_REPO_TOKEN }}
          INPUT_VERSION: ${{ inputs.version }}
        run: |
          echo "$INPUT_VERSION"
  release:
    needs: public-preflight
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  publish-public:
    needs: [public-preflight, release]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
      - env:
          GH_TOKEN: ${{ secrets.PUBLIC_REPO_TOKEN }}
        run: gh release view
"""


class RealWorkflows(unittest.TestCase):
    def test_the_repository_passes(self):
        self.assertEqual(problems(read_workflows()), [])


class Fixtures(unittest.TestCase):
    def test_fixture_passes(self):
        self.assertEqual(problems({"release.yml": RELEASE}), [])

    def test_token_in_another_workflow(self):
        bad = {"release.yml": RELEASE, "build.yml": "on: push\njobs:\n  a:\n    env:\n      T: ${{ secrets.PUBLIC_REPO_TOKEN }}\n"}
        self.assertTrue(any("build.yml" in p for p in problems(bad)))

    def test_token_in_the_release_job(self):
        bad = RELEASE.replace("      - run: echo build", "      - env:\n          T: ${{ secrets.PUBLIC_REPO_TOKEN }}\n        run: echo build")
        self.assertTrue(any("outside" in p for p in problems({"release.yml": bad})))

    def test_pull_request_trigger(self):
        bad = RELEASE.replace("  workflow_dispatch:\n", "  pull_request:\n  workflow_dispatch:\n", 1)
        self.assertTrue(any("triggers" in p for p in problems({"release.yml": bad})))

    def test_push_to_branches(self):
        bad = RELEASE.replace("    tags: ['v*']\n", "    tags: ['v*']\n    branches: [main]\n")
        self.assertTrue(any("push is filtered" in p for p in problems({"release.yml": bad})))

    def test_pull_request_target_anywhere(self):
        bad = {"release.yml": RELEASE, "x.yml": "on:\n  pull_request_target:\njobs: {}\n"}
        self.assertTrue(any("x.yml: has a pull_request_target" in p for p in problems(bad)))

    def test_persist_credentials(self):
        bad = RELEASE.replace("persist-credentials: false", "persist-credentials: true")
        self.assertTrue(any("persist-credentials" in p for p in problems({"release.yml": bad})))

    def test_input_expanded_in_run(self):
        bad = RELEASE.replace('echo "$INPUT_VERSION"', 'echo "${{ inputs.version }}"')
        self.assertTrue(any("expands an input" in p for p in problems({"release.yml": bad})))
        bad = RELEASE.replace("run: gh release view", "run: gh release view ${{ github.event.inputs.version }}")
        self.assertTrue(any("expands an input" in p for p in problems({"release.yml": bad})))

    def test_input_through_a_function_in_run(self):
        bad = RELEASE.replace('echo "$INPUT_VERSION"', "echo \"${{ format('{0}', inputs.version) }}\"")
        self.assertTrue(any("expands an input" in p for p in problems({"release.yml": bad})))

    def test_every_secret_at_once(self):
        bad = {"release.yml": RELEASE, "build.yml": "on: push\njobs:\n  a:\n    env:\n      ALL: ${{ toJSON(secrets) }}\n"}
        self.assertTrue(any("build.yml: uses the secrets context whole" in p for p in problems(bad)))
        bad = RELEASE.replace("      - run: echo build", "      - env:\n          ALL: ${{ toJson( secrets ) }}\n        run: echo build")
        self.assertTrue(any("secrets context whole" in p for p in problems({"release.yml": bad})))
        bad = RELEASE.replace("      - run: echo build", "      - env:\n          T: ${{ secrets['PUBLIC_REPO_TOKEN'] }}\n        run: echo build")
        self.assertTrue(any("secrets context whole" in p for p in problems({"release.yml": bad})))

    def test_secrets_inherit(self):
        bad = {"release.yml": RELEASE, "x.yml": "on: push\njobs:\n  a:\n    uses: ./.github/workflows/y.yml\n    secrets: inherit\n"}
        self.assertTrue(any("x.yml: passes secrets: inherit" in p for p in problems(bad)))


if __name__ == "__main__":
    unittest.main()
