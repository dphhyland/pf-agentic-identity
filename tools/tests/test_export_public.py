"""tools/export-public.py on fixture repositories made here: the tree is deterministic and built from tracked
files only, every guard fails on its fixture and names the file, the link transform and the URL table do what
docs/development/public-export.md says, a tag tolerates what HEAD refuses, and the overlay's sections follow
what is exported. The keys below are assembled at run time and sign nothing."""
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

ep = load("export-public.py")

INTERNAL = "https://github.com/" + "dphhyland/pf-agentic-identity"
PUBLIC = "https://github.com/ID-Partners/pf-agentic-identity"

MANIFEST = """# fixture
root LICENSE
docs docs/guide/**
docs docs/releases/*.md
docs docs/assets/**
docs svc/docs/*.md -> docs/svc/
image build/img/Dockerfile -> image/
image build/img/run.sh -> image/
image build/img/stage-from-release.sh -> image/ optional
image build/pf-version.env -> image/pf-version.env
internal rig/skip.sh
demo rig/** -> demo/
internal docs/findings/**
internal svc/**
internal build/**
refuse showcase/**
refuse **/src/**
refuse **/*.java
refuse **/pom.xml
refuse .github/**
"""

DENY = """# fixture deny list
/(Users|home)/[a-z][a-z0-9._-]*/ # a home directory
railway\\.internal # private network
\\.up\\.railway\\.app # a Railway host
"""

OVERLAY = """# Public {{VERSION}}

Tag {{TAG}} on PingFederate {{PF_VERSION}}.
<!-- if:demo -->
DEMO
<!-- if:staging -->
STAGING
<!-- end:staging -->
<!-- unless:staging -->
FROM-SOURCE
<!-- end:staging -->
<!-- end:demo -->
See [the guide](docs/guide/a.md).
"""

BASE = {
    "LICENSE": "Apache\n",
    "docs/guide/a.md": "# A\n\nSee [b](b.md#part) and [the finding](../findings/F-1.yaml).\n",
    "docs/guide/b.md": "# B\n",
    "docs/findings/F-1.yaml": "id: F-1\n",
    "docs/releases/0.1.0.md": "# 0.1.0\n",
    "docs/assets/flow.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
    "svc/docs/api.md": "# API\n\nBack to [the guide](../../docs/guide/a.md#top) and [code](../Main.txt).\n",
    "svc/Main.txt": "internal\n",
    "build/img/Dockerfile": "FROM scratch\n",
    "build/img/run.sh": "#!/bin/sh\necho run\n",
    "build/pf-version.env": "PF_VERSION=13.1.3\n",
    "rig/up.sh": "#!/bin/sh\necho up\n",
    "rig/README.md": "# Rig\n\nThe image is [here](../build/img/Dockerfile).\n",
    "rig/skip.sh": "#!/bin/sh\n",
}


def git(root, *args):
    subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                   check=True, capture_output=True)


def repo(files=None, extra=None, manifest=MANIFEST, overlay=OVERLAY, tag=None, after_tag=None, untracked=None):
    root = tempfile.mkdtemp()
    content = dict(BASE if files is None else files)
    content.update(extra or {})
    content["tools/public-export/manifest.txt"] = manifest
    content["tools/public-export/deny.txt"] = DENY
    if overlay is not None:
        content["tools/public-export/overlay/README.md"] = overlay
    write(root, content)
    for rel in content:
        if rel.endswith(".sh"):
            os.chmod(os.path.join(root, rel), 0o755)
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "fixture")
    if tag:
        git(root, "tag", tag)
    if after_tag:
        write(root, after_tag)
        git(root, "add", "-A")
        git(root, "commit", "-qm", "after the tag")
    if untracked:
        write(root, untracked)
    return root


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(text if isinstance(text, bytes) else text.encode("utf-8"))


def run(root, *argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = ep.main(["--root", root, *argv])
    return code, out.getvalue(), err.getvalue()


def export(root, *argv):
    """(code, outdir, stdout, stderr) of an export into a fresh directory."""
    out = os.path.join(tempfile.mkdtemp(), "public")
    code, stdout, stderr = run(root, *argv, out)
    return code, out, stdout, stderr


def read(out, rel):
    with open(os.path.join(out, rel), encoding="utf-8") as f:
        return f.read()


def listing(out):
    found = []
    for dirpath, dirnames, filenames in os.walk(out):
        for name in filenames:
            found.append(os.path.relpath(os.path.join(dirpath, name), out))
    return sorted(found)


class Tree(unittest.TestCase):

    def test_two_runs_give_the_same_tree(self):
        root = repo()
        first = ep.tree_digest(ep.build(root))
        self.assertEqual(first, ep.tree_digest(ep.build(root)))
        code1, out1, _, err1 = export(root)
        code2, out2, _, _ = export(root)
        self.assertEqual((code1, code2), (0, 0), err1)
        self.assertEqual(listing(out1), listing(out2))
        for rel in listing(out1):
            with open(os.path.join(out1, rel), "rb") as a, open(os.path.join(out2, rel), "rb") as b:
                self.assertEqual(a.read(), b.read(), rel)
            self.assertEqual(os.stat(os.path.join(out1, rel)).st_mode, os.stat(os.path.join(out2, rel)).st_mode)
        self.assertEqual(oct(os.stat(os.path.join(out1, "image/run.sh")).st_mode & 0o777), "0o755")
        self.assertEqual(oct(os.stat(os.path.join(out1, "LICENSE")).st_mode & 0o777), "0o644")

    def test_the_layout_follows_the_manifest(self):
        code, out, stdout, err = export(repo())
        self.assertEqual(code, 0, err)
        self.assertEqual(listing(out), [
            "LICENSE", "README.md", "demo/README.md", "demo/up.sh", "docs/assets/flow.svg", "docs/guide/a.md", "docs/guide/b.md",
            "docs/releases/0.1.0.md", "docs/svc/api.md", "image/Dockerfile", "image/pf-version.env", "image/run.sh"])
        self.assertIn("not present: build/img/stage-from-release.sh (optional, not present)", stdout)

    def test_only_tracked_files_are_read(self):
        root = repo(untracked={"docs/guide/secret-notes.md": "# not tracked\n"})
        code, out, _, err = export(root)
        self.assertEqual(code, 0, err)
        self.assertNotIn("docs/guide/secret-notes.md", listing(out))

    def test_an_untracked_overlay_file_is_not_exported(self):
        root = repo(untracked={"tools/public-export/overlay/NOTES.md": "# not tracked\n"})
        code, out, _, err = export(root)
        self.assertEqual(code, 0, err)
        self.assertNotIn("NOTES.md", listing(out))
        self.assertIn("README.md", listing(out))

    def test_the_working_tree_content_of_a_tracked_file_is_what_goes_out(self):
        root = repo()
        write(root, {"docs/guide/b.md": "# B, edited\n"})
        code, out, _, err = export(root)
        self.assertEqual(read(out, "docs/guide/b.md"), "# B, edited\n")

    def test_check_writes_nothing_and_an_outdir_must_be_empty(self):
        root = repo()
        code, stdout, err = run(root, "--check")
        self.assertEqual(code, 0, err)
        self.assertIn("ok: every guard passed", stdout)
        self.assertEqual(run(root)[0], 2)
        self.assertEqual(run(root, "--check", os.path.join(root, "x"))[0], 2)
        busy = tempfile.mkdtemp()
        write(busy, {"there.txt": "x"})
        self.assertEqual(run(root, busy)[0], 2)
        self.assertEqual(run(root, "--check", "--version", "seven")[0], 2)


class Guards(unittest.TestCase):

    def failed(self, root, *argv):
        code, stdout, err = run(root, "--check", *argv)
        self.assertEqual(code, 1, stdout + err)
        return err

    def test_source_code_and_build_files(self):
        err = self.failed(repo(extra={"docs/guide/Main.java": "class Main {}\n"}))
        self.assertIn("error: [no-source] docs/guide/Main.java: source code is never exported", err)
        err = self.failed(repo(extra={"rig/pom.xml": "<project/>\n"}))
        self.assertIn("error: [no-source] rig/pom.xml: a Maven build file is never exported", err)
        err = self.failed(repo(extra={"docs/guide/src/x.md": "# x\n"}))
        self.assertIn("error: [no-source] docs/guide/src/x.md: a src/ directory is never exported", err)
        self.assertIn("nothing was written", err)

    def test_a_manifest_rule_that_reaches_a_refused_path_is_a_manifest_error(self):
        root = repo(extra={"showcase/index.html": "<html></html>\n"}, manifest=MANIFEST.replace(
            "root LICENSE\n", "root LICENSE\ndocs showcase/index.html\n"))
        code, stdout, err = run(root, "--check")
        self.assertEqual(code, 2)
        self.assertIn("docs showcase/index.html - its source matches the refuse rule `showcase/**`", err)

    def test_a_refuse_rule_holds_against_a_broader_rule_above_it(self):
        # docs/guide/private/ is in no NO_SOURCE pattern: only the refuse rule keeps it out
        root = repo(extra={"docs/guide/private/plan.md": "# plan\n"},
                    manifest=MANIFEST + "refuse docs/guide/private/**\n")
        err = self.failed(root)
        self.assertIn("error: [no-source] docs/guide/private/plan.md: matches the refuse rule "
                      "`docs/guide/private/**`", err)
        self.assertIn("docs docs/guide/** matches it first", err)

    def test_a_committed_symbolic_link(self):
        root = repo()
        os.symlink("b.md", os.path.join(root, "docs/guide/link.md"))
        git(root, "add", "-A")
        git(root, "commit", "-qm", "a link")
        err = self.failed(root)
        self.assertIn("error: [no-source] docs/guide/link.md: a symbolic link", err)

    def test_a_tracked_file_turned_into_a_symbolic_link_is_refused(self):
        root = repo()
        outside = os.path.join(tempfile.mkdtemp(), "elsewhere.md")
        write(os.path.dirname(outside), {"elsewhere.md": "# not the repository's\n"})
        os.remove(os.path.join(root, "docs/guide/b.md"))
        os.symlink(outside, os.path.join(root, "docs/guide/b.md"))
        code, stdout, err = run(root, "--check")
        self.assertEqual(code, 2, stdout + err)
        self.assertIn("docs/guide/b.md: the working tree has a symbolic link where the index has a regular file", err)

    def test_an_html_link_that_would_be_de_linked(self):
        err = self.failed(repo(extra={"docs/guide/c.md": '<a href="../findings/F-1.yaml">F-1</a>\n'}))
        self.assertIn("error: [links] docs/guide/c.md:1: ../findings/F-1.yaml in an HTML href or src would be "
                      "de-linked", err)

    def test_a_mixed_case_internal_url_or_slug(self):
        err = self.failed(repo(extra={"build/img/Dockerfile": 'LABEL source="https://github.com/DPHHYLAND/'
                                      'pf-agentic-identity"\nREPO=Dphhyland/Pf-Agentic-Identity\n'}))
        self.assertIn("error: [urls] build/img/Dockerfile:1: https://github.com/DPHHYLAND/pf-agentic-identity", err)
        self.assertIn("error: [urls] build/img/Dockerfile:2: dphhyland/pf-agentic-identity outside a URL", err)

    def test_a_dead_relative_link_and_an_unclassified_one(self):
        err = self.failed(repo(extra={"docs/guide/c.md": "[gone](gone.md) [odd](../../other/x.md)\n",
                                      "other/x.md": "x\n"}))
        self.assertIn("error: [links] docs/guide/c.md:1: gone.md -> docs/guide/gone.md, which does not exist", err)
        self.assertIn("error: [links] docs/guide/c.md:1: ../../other/x.md -> other/x.md, which the manifest "
                      "does not classify", err)

    def test_an_internal_url_in_a_dockerfile(self):
        err = self.failed(repo(extra={"build/img/Dockerfile": f'LABEL source="{INTERNAL}"\n'}))
        self.assertIn(f"error: [urls] build/img/Dockerfile:1: {INTERNAL} is not in the rewrite table", err)

    def test_a_bare_slug_outside_a_gh_flag(self):
        err = self.failed(repo(extra={"rig/up.sh": "#!/bin/sh\nREPO=dphhyland/" + "pf-agentic-identity\n"}))
        self.assertIn("error: [urls] rig/up.sh:2: dphhyland/pf-agentic-identity outside a URL", err)

    def test_the_deny_list(self):
        err = self.failed(repo(extra={"rig/up.sh": "#!/bin/sh\ncd /Users/someone/src/x\n",
                                      "docs/guide/b.md": "Open https://demo-1234.up.railway.app now.\n"}))
        self.assertIn("error: [deny] demo/up.sh:2 (from rig/up.sh): matches `/(Users|home)/", err)
        self.assertIn("error: [deny] docs/guide/b.md:1: matches `\\.up\\.railway\\.app` - a Railway host", err)

    def test_the_deny_list_leaves_a_scim_path_alone(self):
        root = repo(extra={"docs/guide/b.md": "GET /Users/{id} and POST /Users\n"})
        self.assertEqual(run(root, "--check")[0], 0)

    def test_the_deny_list_covers_the_overlay(self):
        err = self.failed(repo(overlay=OVERLAY + "Ask at railway.internal\n"))
        self.assertIn("error: [deny] README.md:", err)

    def test_a_private_jwk(self):
        b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg"
        key = "{" + '"kty": "EC", "crv": "P-256", "x": "' + b64 + '", "d' + '": "' + b64 + '"}'
        err = self.failed(repo(extra={"rig/key.json": key + "\n"}))
        self.assertIn("error: [secrets] demo/key.json:1 (from rig/key.json): private JWK", err)

    def test_binaries(self):
        big = b"\x89PNG\r\n\x1a\n" + b"\0" * (5 * 1024 * 1024)
        err = self.failed(repo(extra={"docs/assets/big.png": big, "docs/assets/tool.bin": b"\0\1\2"}))
        self.assertIn("error: [binaries] docs/assets/big.png: 5242888 bytes, over the 5242880 byte limit", err)
        self.assertIn("error: [binaries] docs/assets/tool.bin: a binary file; only .png", err)
        self.assertEqual(run(repo(extra={"docs/assets/logo.png": b"\x89PNG\r\n\x1a\n\0\0"}), "--check")[0], 0)


class Links(unittest.TestCase):

    def doc(self, text, path="docs/guide/c.md", **kw):
        code, out, stdout, err = export(repo(extra={path: text}), **kw)
        self.assertEqual(code, 0, err)
        return read(out, ep.Rule("docs", "svc/docs/*.md", "docs/svc/", False, 0).public_path(path)
                    if path.startswith("svc/docs/") else path), stdout

    def test_an_exported_target_moves_with_its_anchor_and_an_internal_one_keeps_its_text(self):
        text, stdout = self.doc("x\n", path="svc/docs/c.md")
        code, out, stdout, err = export(repo())
        self.assertEqual(read(out, "docs/svc/api.md"),
                         "# API\n\nBack to [the guide](../guide/a.md#top) and code.\n")
        self.assertEqual(read(out, "docs/guide/a.md"), "# A\n\nSee [b](b.md#part) and the finding.\n")
        self.assertEqual(read(out, "demo/README.md"), "# Rig\n\nThe image is [here](../image/Dockerfile).\n")
        self.assertIn("docs/svc/api.md: 1 rewritten, 1 de-linked (internal), 0 de-linked (private)", stdout)

    def test_a_directory_link_follows_the_directory(self):
        text, _ = self.doc("[rig](../../rig/) and [svc docs](../../svc/docs)\n")
        self.assertEqual(text, "[rig](../../demo/) and [svc docs](../svc)\n")

    def test_reference_style_links(self):
        text, _ = self.doc("[One][a], [two][gone] and [gone][].\n\n[a]: b.md#x\n[gone]: ../findings/F-1.yaml\n"
                           "[Release]: " + INTERNAL + "/releases/tag/v0.5.0\n")
        self.assertEqual(text, "[One][a], two and gone.\n\n[a]: b.md#x\n[Release]: " + PUBLIC
                         + "/releases/tag/v0.5.0\n")

    def test_an_html_href_or_src_to_an_exported_file_is_rewritten(self):
        text, _ = self.doc('<a href="../../rig/README.md#x">rig</a> <img src="../../docs/assets/flow.svg"/>\n',
                           path="svc/docs/c.md")
        self.assertEqual(text, '<a href="../../demo/README.md#x">rig</a> <img src="../assets/flow.svg"/>\n')

    def test_fenced_code_and_inline_code_are_untouched(self):
        body = "```md\n[f](../findings/F-1.yaml)\n```\n`[g](../findings/F-1.yaml)`\n~~~\n[h](nowhere.md)\n~~~\n"
        text, _ = self.doc(body)
        self.assertEqual(text, body)

    def test_a_link_text_across_lines_and_an_image(self):
        text, _ = self.doc("[the\nfinding](../findings/F-1.yaml) ![logo](../findings/F-1.yaml)\n")
        self.assertEqual(text, "the\nfinding logo\n")

    def test_the_url_table(self):
        rows = [
            (f"[r]({INTERNAL}/releases/tag/v0.5.0)", f"[r]({PUBLIC}/releases/tag/v0.5.0)"),
            (f"[r]({INTERNAL}/releases/tag/v0.3.0#notes)", f"[r]({PUBLIC}/releases/tag/v0.3.0#notes)"),
            (f"[r]({INTERNAL}/releases/tag/v0.1.5)", "r"),
            (f"[d]({INTERNAL}/releases/download/v0.6.0/SHA256SUMS)", f"[d]({PUBLIC}/releases/download/v0.6.0/SHA256SUMS)"),
            (f"[d]({INTERNAL}/releases/download/v0.2.9/x.jar)", "d"),
            (f"[all]({INTERNAL}/releases)", f"[all]({PUBLIC}/releases)"),
            (f"[run 1]({INTERNAL}/actions/runs/1)", "run 1"),
            (f"[c]({INTERNAL}/compare/v0.5.0...main)", "c"),
            (f"[b]({INTERNAL}/blob/main/x.md)", "b"),
            (f"[t]({INTERNAL}/tree/main/docs)", "t"),
            (f"[p]({INTERNAL}/pull/7)", "p"),
            (f"[i]({INTERNAL}/issues/9)", "i"),
            (f"see {INTERNAL}/releases/tag/v0.4.0.", f"see {PUBLIC}/releases/tag/v0.4.0."),
            (f"see <{INTERNAL}/actions/runs/2>.", "see the internal repository."),
            ("gh release download v0.6.0 --repo dphhyland/" + "pf-agentic-identity -p x",
             "gh release download v0.6.0 --repo ID-Partners/pf-agentic-identity -p x"),
            ("gh release download v0.6.0 -R dphhyland/" + "pf-agentic-identity",
             "gh release download v0.6.0 -R ID-Partners/pf-agentic-identity"),
            ("[sidecar](https://github.com/dphhyland/grant-evaluation-api/tree/main)", "sidecar"),
            ("bare https://github.com/dphhyland/idp-agentic-demo.", "bare idp-agentic-demo."),
            ("[public](https://github.com/dphhyland/pf-oidf-modules/blob/main/x.tf)",
             "[public](https://github.com/dphhyland/pf-oidf-modules/blob/main/x.tf)"),
            ("[R](https://github.com/DPHHYLAND/PF-Agentic-Identity/releases/tag/v0.6.0)",
             f"[R]({PUBLIC}/releases/tag/v0.6.0)"),
            ("[P](https://github.com/Dphhyland/pf-agentic-identity/pull/3)", "P"),
            ("gh release list -R DPHHYLAND/pf-agentic-identity", "gh release list -R ID-Partners/pf-agentic-identity"),
            ("[S](https://github.com/DPHHYLAND/Grant-Evaluation-API)", "S"),
        ]
        text, stdout = self.doc("".join(src + "\n" for src, _ in rows))
        self.assertEqual(text.split("\n")[:-1], [want for _, want in rows])
        self.assertIn("docs/guide/c.md: 9 rewritten, 10 de-linked (internal), 3 de-linked (private)", stdout)

    def test_the_url_table_applies_inside_fenced_code_and_outside_markdown(self):
        text, _ = self.doc("```sh\ngh release download v0.6.0 -R dphhyland/" + "pf-agentic-identity\n```\n")
        self.assertIn("-R ID-Partners/pf-agentic-identity", text)
        code, out, _, err = export(repo(extra={"rig/up.sh": f"#!/bin/sh\ncurl -O {INTERNAL}/releases/download/v0.6.0/x\n"}))
        self.assertEqual(read(out, "demo/up.sh"), f"#!/bin/sh\ncurl -O {PUBLIC}/releases/download/v0.6.0/x\n")


class SourceRef(unittest.TestCase):

    def test_a_tag_tolerates_a_missing_path_and_replaces_what_head_refuses(self):
        tagged = dict(BASE)
        del tagged["build/img/run.sh"]
        tagged["build/img/Dockerfile"] = f'LABEL source="{INTERNAL}"\n'
        tagged["docs/guide/b.md"] = ("[gone](gone.md) and https://demo-1234.up.railway.app/x and "
                                     + "dphhyland/" + "pf-agentic-identity\n")
        root = repo(files=tagged, tag="v0.5.0", after_tag={"build/img/run.sh": "#!/bin/sh\n",
                                                           "build/img/Dockerfile": "FROM scratch\n",
                                                           "docs/guide/b.md": "# B\n"})
        self.assertEqual(run(root, "--check")[0], 0)
        code, out, stdout, err = export(root, "--source-ref", "v0.5.0")
        self.assertEqual(code, 0, err)
        self.assertIn("public tree from v0.5.0:", stdout)
        self.assertIn("not present: build/img/run.sh", stdout)
        self.assertEqual(read(out, "image/Dockerfile"), 'LABEL source="the internal repository"\n')
        self.assertEqual(read(out, "docs/guide/b.md"),
                         "gone and https://<redacted>/x and the internal repository\n")
        self.assertIn(f"listed: image/Dockerfile:1: {INTERNAL} -> the internal repository", stdout)
        self.assertIn("listed: docs/guide/b.md:1: gone.md -> link dropped (no such file at v0.5.0)", stdout)
        self.assertIn("-> <redacted>", stdout)
        self.assertEqual(read(out, "image/release.env"),
                         "PFAI_RELEASE=0.5.0\nPFAI_RELEASE_REPO=ID-Partners/pf-agentic-identity\n")
        self.assertIn("# Public 0.5.0", read(out, "README.md"))

    def test_head_refuses_a_missing_path(self):
        root = repo(manifest=MANIFEST.replace("root LICENSE\n", "root LICENSE\nroot NOTICE\n"))
        code, stdout, err = run(root, "--check")
        self.assertEqual(code, 2)
        self.assertIn("root NOTICE matches no tracked file", err)

    def test_a_manifest_error_is_exit_2(self):
        for bad in ("wrong LICENSE\n", "docs a -> \n", "internal a -> b\n", "docs ../x\n", "docs a b c\n"):
            root = repo(manifest=bad + MANIFEST)
            self.assertEqual(run(root, "--check")[0], 2, bad)


class Overlay(unittest.TestCase):

    def test_with_staging(self):
        code, out, _, err = export(repo(extra={"build/img/stage-from-release.sh": "#!/bin/sh\n"}), "--version", "0.7.0")
        self.assertEqual(code, 0, err)
        self.assertEqual(read(out, "README.md"),
                         "# Public 0.7.0\n\nTag v0.7.0 on PingFederate 13.1.3.\nDEMO\nSTAGING\n"
                         "See [the guide](docs/guide/a.md).\n")
        self.assertEqual(read(out, "image/release.env"),
                         "PFAI_RELEASE=0.7.0\nPFAI_RELEASE_REPO=ID-Partners/pf-agentic-identity\n")

    def test_demo_without_staging_and_no_version(self):
        code, out, _, err = export(repo())
        self.assertEqual(read(out, "README.md"),
                         "# Public <version>\n\nTag v<version> on PingFederate 13.1.3.\nDEMO\nFROM-SOURCE\n"
                         "See [the guide](docs/guide/a.md).\n")
        self.assertNotIn("image/release.env", listing(out))

    DOCS = ["LICENSE", "README.md", "docs/assets/flow.svg", "docs/guide/a.md", "docs/guide/b.md",
            "docs/releases/0.1.0.md", "docs/svc/api.md"]

    def test_docs_only_keeps_the_public_image_and_demo_in_view(self):
        code, out, _, err = export(repo(extra={"build/img/stage-from-release.sh": "#!/bin/sh\n"},
                                        overlay=OVERLAY + "[demo](demo/README.md)\n"),
                                   "--docs-only", "--version", "0.7.0")
        self.assertEqual(code, 0, err)
        self.assertEqual(listing(out), self.DOCS)
        self.assertEqual(read(out, "README.md"),
                         "# Public 0.7.0\n\nTag v0.7.0 on PingFederate 13.1.3.\nDEMO\nSTAGING\n"
                         "See [the guide](docs/guide/a.md).\n[demo](demo/README.md)\n")

    def test_docs_alone_leaves_the_image_and_demo_out(self):
        code, out, stdout, err = export(repo(extra={"build/img/stage-from-release.sh": "#!/bin/sh\n"}),
                                        "--docs-alone", "--version", "0.7.0")
        self.assertEqual(code, 0, err)
        self.assertIn("(docs alone)", stdout)
        self.assertEqual(listing(out), self.DOCS)
        self.assertEqual(read(out, "README.md"),
                         "# Public 0.7.0\n\nTag v0.7.0 on PingFederate 13.1.3.\nSee [the guide](docs/guide/a.md).\n")

    def test_a_docs_only_link_into_the_demo_follows_it_and_a_docs_alone_one_keeps_its_text(self):
        root = repo(extra={"docs/guide/c.md": "[rig](../../rig/README.md) and [dir](../../rig/)\n"})
        code, out, _, err = export(root, "--docs-only")
        self.assertEqual(read(out, "docs/guide/c.md"), "[rig](../../demo/README.md) and [dir](../../demo/)\n")
        code, out, _, err = export(root, "--docs-alone")
        self.assertEqual(read(out, "docs/guide/c.md"), "rig and dir\n")

    def test_an_overlay_link_must_resolve_in_the_public_tree(self):
        code, stdout, err = run(repo(overlay=OVERLAY + "[x](demo/missing.md)\n"), "--check")
        self.assertEqual(code, 1)
        self.assertIn("error: [links] tools/public-export/overlay/README.md:", err)

    def test_an_unknown_condition_or_placeholder(self):
        self.assertEqual(run(repo(overlay="<!-- if:moon -->x<!-- end:moon -->\n"), "--check")[0], 2)
        self.assertEqual(run(repo(overlay="{{NOPE}}\n"), "--check")[0], 2)

    def test_an_overlay_file_cannot_shadow_an_exported_one(self):
        root = repo(extra={"tools/public-export/overlay/LICENSE": "other\n"})
        self.assertEqual(run(root, "--check")[0], 2)


class Repository(unittest.TestCase):
    """The real manifest against the real repository: what the lint job runs."""

    def test_head_passes(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ep.main(["--check"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertTrue(os.path.isfile(os.path.join(root, "tools/public-export/manifest.txt")))


if __name__ == "__main__":
    unittest.main()
