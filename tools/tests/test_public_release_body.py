"""tools/public-release-body.py on fixture pages: with and without "Before you deploy", bold titles wrapped
over lines, GitHub's length limit, and the mirrored and omitted-asset text."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

body = load("public-release-body.py")

PF = {"PF_VERSION": "13.1.3", "PF_IMAGE": "pingidentity/pingfederate:13.1.3", "PF_IMAGE_DIGEST": "sha256:" + "a" * 64}

PAGE = """# 9.9.0 (2026-10-01) - a release

9.9.0 does a thing. See [the guide](../operator/upgrading/a-to-b.md#first) and [the page](#notes),
[a site](https://example.org/x) and `[not](a link)`.

## Before you deploy

1. **Follow the upgrade guide, which puts these items in the order
   to do them.** Text that continues.
2. **Set `OIDF_X`.** (P1) More.

   A second paragraph of the item.
3. **Another thing** with text after the title.

## Package P1: a package

Notes that never reach the body.
"""

NO_DEPLOY = """# 9.9.0 - a release

Intro.

## Package P1: a package

Notes.
"""

SUMS = "".join(f"{c * 64}  {n}\n" for c, n in (("a", "SHA256SUMS-is-not-listed-in-itself"), ("b", "PROVENANCE.txt"),
                                                  ("c", "pf.plugins.ciba-sim.jar"), ("d", "demo-only-ciba-sim.jar")))


class SplitAndTitles(unittest.TestCase):
    def test_opening_drops_title_and_stops_at_first_section(self):
        opening, section = body.split_page(PAGE)
        self.assertTrue(opening.startswith("9.9.0 does a thing."))
        self.assertNotIn("Notes that never", opening)
        self.assertIsNotNone(section)

    def test_bold_titles_joined_across_lines(self):
        _, section = body.split_page(PAGE)
        self.assertEqual(body.bold_titles(section), [
            "Follow the upgrade guide, which puts these items in the order to do them.",
            "Set `OIDF_X`.",
            "Another thing",
        ])

    def test_no_before_you_deploy(self):
        _, section = body.split_page(NO_DEPLOY)
        self.assertIsNone(section)
        text = body.body("9.9.0", NO_DEPLOY, PF)
        self.assertIn('has no "Before you deploy" section', text)

    def test_item_without_bold_title_fails(self):
        with self.assertRaises(body.BodyError):
            body.bold_titles(["1. Plain text, no title."])

    def test_unclosed_bold_title_fails(self):
        with self.assertRaises(body.BodyError):
            body.bold_titles(["1. **Never closed."])


class Body(unittest.TestCase):
    def test_links_made_absolute_at_the_tag(self):
        text = body.body("9.9.0", PAGE, PF)
        base = "https://github.com/ID-Partners/pf-agentic-identity/blob/v9.9.0/"
        self.assertIn(f"[the guide]({base}docs/operator/upgrading/a-to-b.md#first)", text)
        self.assertIn(f"[the page]({base}docs/releases/9.9.0.md#notes)", text)
        self.assertIn("[a site](https://example.org/x)", text)
        self.assertIn("`[not](a link)`", text)
        self.assertIn(f"[Before you deploy]({base}docs/releases/9.9.0.md#before-you-deploy)", text)
        self.assertIn("lists 3 items", text)
        self.assertIn("- Set `OIDF_X`.", text)

    def test_link_out_of_the_repository_fails(self):
        with self.assertRaises(body.BodyError):
            body.absolute_links("[x](../../../outside.md)", "9.9.0")

    def test_verify_and_pf_line(self):
        text = body.body("9.9.0", PAGE, PF)
        self.assertIn("releases/download/v9.9.0/SHA256SUMS", text)
        self.assertIn("sha256sum -c", text)
        self.assertIn("grep -E '^(commit|tag):' PROVENANCE.txt", text)
        self.assertIn("PingFederate 13.1.3 (`pingidentity/pingfederate:13.1.3@sha256:", text)
        self.assertNotIn("## Mirrored", text)

    def test_simulator_warning_only_when_listed(self):
        self.assertIn("is not a deployable", body.body("9.9.0", PAGE, PF, sums=["demo-only-ciba-sim.jar"]))
        self.assertNotIn("is not a deployable", body.body("9.9.0", PAGE, PF, sums=["oidf.war"]))

    def test_pf_line_follows_pf_version(self):
        self.assertIn("for the PingFederate 13.1.x line.", body.body("9.9.0", PAGE, PF))
        self.assertIn("for the PingFederate 14.0.x line.", body.body("9.9.0", PAGE, dict(PF, PF_VERSION="14.0.2")))

    def test_opening_is_unwrapped(self):
        text = body.unwrap("one\ntwo\n\n- item\n  more\n- next\n\n```\na\nb\n```\n# h\nafter")
        self.assertEqual(text, "one two\n\n- item more\n- next\n\n```\na\nb\n```\n# h\nafter")

    def test_image_from_source_line(self):
        self.assertIn("From v0.7.0 the image and the demo run", body.body("9.9.0", PAGE, PF, image_from_source=True))

    def test_mirrored_and_omitted(self):
        omits = body.parse_omits(["pf.plugins.ciba-sim.jar"], ["pf.plugins.ciba-sim.jar"])
        text = body.body("0.3.0", PAGE, PF, mirrored=True, date="2026-10-02", omits=omits)
        self.assertIn("Mirrored on 2026-10-02 from the original release; every mirrored asset is byte for byte the "
                      "original and `SHA256SUMS` is unchanged.", text)
        whole = body.body("0.4.0", PAGE, PF, mirrored=True, date="2026-10-02")
        self.assertIn("; every asset is byte for byte the original and", whole)
        self.assertIn("`run:` line of its `PROVENANCE.txt`", text)
        self.assertIn("- `pf.plugins.ciba-sim.jar` is not mirrored: the 0.3.0 CIBA simulator runs on "
                      "`OIDF_CIBA_SIM_ENABLED` alone; verify with `sha256sum -c --ignore-missing`.", text)

    def test_omit_needs_a_reason_and_a_listed_asset(self):
        with self.assertRaises(body.BodyError):
            body.parse_omits(["other.jar"], None)
        self.assertEqual(body.parse_omits(["other.jar=why"], None), [("other.jar", "why")])
        with self.assertRaises(body.BodyError):
            body.parse_omits(["pf.plugins.ciba-sim.jar"], ["oidf.war"])

    def test_length_limit(self):
        long_page = "# 9.9.0\n\n" + ("word " * 30000) + "\n"
        with self.assertRaises(body.BodyError) as e:
            body.body("9.9.0", long_page, PF)
        self.assertIn("125000", str(e.exception))
        just_under = "# 9.9.0\n\n" + ("x" * 100) + "\n"
        self.assertLess(len(body.body("9.9.0", just_under, PF)), body.BODY_LIMIT)


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        os.makedirs(os.path.join(d, "tree", "docs", "releases"))
        with open(os.path.join(d, "tree", "docs", "releases", "9.9.0.md"), "w") as f:
            f.write(PAGE)
        os.makedirs(os.path.join(d, "root", "build"))
        with open(os.path.join(d, "root", "build", "pf-version.env"), "w") as f:
            f.write("# a comment\nPF_VERSION=13.1.3\nPF_IMAGE=img\nPF_IMAGE_DIGEST=sha256:00\n")
        with open(os.path.join(d, "SHA256SUMS"), "w") as f:
            f.write(SUMS)

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = body.main(list(args) + ["--root", os.path.join(self.tmp.name, "root")])
        return code, out.getvalue(), err.getvalue()

    def test_writes_the_body(self):
        d = self.tmp.name
        out = os.path.join(d, "body.md")
        code, _, err = self.run_main("v9.9.0", "--tree", os.path.join(d, "tree"), "--sums", os.path.join(d, "SHA256SUMS"),
                                     "--mirrored", "--date", "2026-10-02", "--omit", "pf.plugins.ciba-sim.jar", "-o", out)
        self.assertEqual(code, 0, err)
        with open(out) as f:
            text = f.read()
        self.assertIn("Mirrored on 2026-10-02", text)
        self.assertIn("is not a deployable", text)
        self.assertIn("PingFederate 13.1.3 (`img@sha256:00`)", text)

    def test_missing_page_fails(self):
        code, _, err = self.run_main("9.9.1", "--tree", os.path.join(self.tmp.name, "tree"))
        self.assertEqual(code, 1)
        self.assertIn("release page", err)

    def test_usage_errors(self):
        tree = os.path.join(self.tmp.name, "tree")
        self.assertEqual(self.run_main("9.9", "--tree", tree)[0], 2)
        self.assertEqual(self.run_main("9.9.0", "--tree", tree, "--omit", "x.jar=y")[0], 2)
        self.assertEqual(self.run_main("9.9.0", "--tree", tree, "--mirrored", "--date", "1 Oct")[0], 2)

    def test_bad_sums_line_fails(self):
        d = self.tmp.name
        with open(os.path.join(d, "bad"), "w") as f:
            f.write("not a checksum\n")
        self.assertEqual(self.run_main("9.9.0", "--tree", os.path.join(d, "tree"), "--sums", os.path.join(d, "bad"))[0], 1)

    def test_stdout(self):
        code, out, _ = self.run_main("9.9.0", "--tree", os.path.join(self.tmp.name, "tree"))
        self.assertEqual(code, 0)
        self.assertIn("## Verify and consume", out)


if __name__ == "__main__":
    unittest.main()
