"""tools/doc-lint.py on documents written for it: each rule, what it leaves alone, the link check and the
baseline's ratchet."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

dl = load("doc-lint.py")


def hits(text, path="doc.md"):
    return [(h.line, h.col, h.rule, h.message) for h in dl.check_text(path, text)]


def rules(text):
    return [h.rule for h in dl.check_text("doc.md", text)]


class EmDash(unittest.TestCase):

    def test_an_em_dash_in_prose_is_a_hit_with_its_line_and_column(self):
        self.assertEqual(hits("first line\nsecond — line\n")[0][:3], (2, 8, "em-dash"))

    def test_code_and_quotations_are_left_alone(self):
        self.assertEqual(rules("in `code — span`\n"), [])
        self.assertEqual(rules("```\na — b\n```\n"), [])
        self.assertEqual(rules('the spec says "Final — text"\n'), [])
        self.assertEqual(rules("<!-- a — note -->\n"), [])
        self.assertEqual(rules("“curly — quotes”\n"), [])

    def test_a_fence_with_a_tilde_closes_only_on_a_tilde(self):
        self.assertEqual(rules("~~~\n```\na — b\n~~~\nc — d\n"), ["em-dash"])


class EnDash(unittest.TestCase):

    def test_used_as_a_dash(self):
        self.assertEqual(rules("one – two\n"), ["en-dash"])
        self.assertEqual(rules("word–word\n"), ["en-dash"])

    def test_a_range_of_numbers_is_not(self):
        self.assertEqual(rules("2026–2027, V1–99, §6.1–6.3\n"), [])


class Spelling(unittest.TestCase):

    def test_the_list_and_its_message(self):
        found = hits("the artifact and its Behavior\n")
        self.assertEqual([(h[2], h[3]) for h in found], [
            ("spelling", "'artifact': the repo writes artefact"),
            ("spelling", "'Behavior': the repo writes behaviour"),
        ])

    def test_identifiers_code_urls_links_and_quotations_are_left_alone(self):
        for text in [
            "`artifactId` and `upload-artifact`\n",
            "the artifact_name, the artifact2, artifactId, file.artifact and a/artifact\n",
            "see https://example.org/artifact/color and [x](../artifact/behavior.md) (the link is checked apart)\n",
            "[home]: docs/artifact.md\n",
            'the "Artifact" column heading\n',
            "an authorization server, authorization_details, the Authorization header\n",
        ]:
            self.assertEqual([r for r in rules(text) if r == "spelling"], [], text)

    def test_a_hyphenated_prose_word_is_still_prose(self):
        self.assertEqual(rules("release-artifact\n"), ["spelling"])


class Scaffolding(unittest.TestCase):

    def test_the_phrases(self):
        text = "Let's dive in.\nIn conclusion, delving deeper.\nI hope this helps!\n"
        self.assertEqual(rules(text), ["scaffolding", "scaffolding", "scaffolding", "scaffolding"])
        self.assertEqual(rules("the delta and the shelves\n"), [])

    def test_a_quoted_phrase_is_a_quotation(self):
        self.assertEqual(rules('the guide refuses "let\'s dive in" and `delve`\n'), [])


class Links(unittest.TestCase):

    def test_relative_links_must_resolve(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "docs", "sub"))
            open(os.path.join(d, "docs", "there.md"), "w").close()
            open(os.path.join(d, "docs", "with space.md"), "w").close()
            path = os.path.join(d, "docs", "sub", "doc.md")
            text = ("[ok](../there.md) [frag](../there.md#part) [dir](../sub) [dir2](../sub/) [enc](../with%20space.md)\n"
                    "[abs](https://example.org/x.md) [anchor](#here) [mail](mailto:x@example.org) <../there.md>\n"
                    "[titled](../there.md \"a title\") ![img](../missing.png) [gone](../gone.md#part)\n"
                    "[ref]: ../also-gone.md\n")
            found = dl.check_text(path, text)
            self.assertEqual([(h.line, h.rule, h.message.split(" ")[0]) for h in found],
                             [(3, "link", "../missing.png"), (3, "link", "../gone.md#part"), (4, "link", "../also-gone.md")])

    def test_a_link_inside_code_is_not_checked(self):
        self.assertEqual(rules("`[x](nowhere.md)`\n"), [])


def tree(files):
    root = tempfile.mkdtemp()
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return root


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = dl.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Baseline(unittest.TestCase):

    def test_no_baseline_means_nothing_is_allowed(self):
        root = tree({"a.md": "x — y\n", "b.md": "clean\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 1)
        self.assertIn("a.md: 1 em-dash hit, baseline 0:", err)
        self.assertIn("a.md:1:3: em dash", err)
        self.assertIn("error: 1 hit above the baseline in 2 documents", err)

    def test_within_the_baseline_passes_and_below_it_is_noted(self):
        root = tree({"a.md": "x — y\n", "docs/development/doc-lint-baseline.txt": "# header\na.md em-dash 2\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 0, err)
        self.assertIn("ok: 1 documents, 1 hit all within the baseline (1 entries)", out)
        self.assertIn("note: a.md em-dash: 1 of 2 allowed; --update-baseline can lower it", out)

    def test_above_the_baseline_fails_and_names_every_hit(self):
        root = tree({"a.md": "x — y — z\n", "docs/development/doc-lint-baseline.txt": "a.md em-dash 1\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 1)
        self.assertIn("a.md: 2 em-dash hits, baseline 1:", err)
        self.assertEqual(err.count("em dash (U+2014)"), 2)

    def test_update_writes_counts_and_warns_when_one_went_up(self):
        root = tree({"a.md": "x — y\nan artifact\n", "b.md": "clean\n",
                     "docs/development/doc-lint-baseline.txt": "a.md em-dash 0\n"})
        code, out, err = run(["--root", root, "--no-git", "--update-baseline", "--today", "2026-09-27"])
        self.assertEqual(code, 0, err)
        self.assertIn("warning: a.md em-dash went up, 0 -> 1", out)
        with open(os.path.join(root, "docs/development/doc-lint-baseline.txt"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Written 2026-09-27.", text)
        self.assertTrue(text.endswith("a.md em-dash 1\na.md spelling 1\n"), text)
        self.assertEqual(run(["--root", root, "--no-git"])[0], 0)

    def test_a_malformed_baseline_line_is_an_error(self):
        root = tree({"a.md": "clean\n", "docs/development/doc-lint-baseline.txt": "a.md dashes lots\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, "error: " + os.path.join(root, "docs/development/doc-lint-baseline.txt") + ":1: expected `file rule count`, got 'a.md dashes lots'")

    def test_explicit_files_and_the_claude_directory(self):
        root = tree({"a.md": "clean\n", "b.md": "x — y\n", "plugins/p/.claude/skills/s/SKILL.md": "x — y\n"})
        self.assertEqual(run(["--root", root, "--no-git", os.path.join(root, "a.md")])[0], 0)
        self.assertEqual(run(["--root", root, "--no-git", os.path.join(root, "b.md")])[0], 1)
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 1)
        self.assertNotIn("SKILL.md", err)
        self.assertIn("in 2 documents", err)

    def test_a_generated_page_is_the_generators_business(self):
        root = tree({"a.md": "clean\n", "docs/coverage-dashboard.md": "x — y — z\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 0)
        self.assertIn("ok: 1 documents", out)
        self.assertEqual(run(["--root", root, "--no-git", os.path.join(root, "docs/coverage-dashboard.md")])[0], 1)

    def test_the_public_overlay_is_not_link_checked_but_keeps_the_other_rules(self):
        overlay = "tools/public-export/overlay/README.md"
        root = tree({overlay: "[image](image/README.md)\n", "a.md": "[image](image/README.md)\n"})
        code, out, err = run(["--root", root, "--no-git", os.path.join(root, overlay)])
        self.assertEqual(code, 0, err)
        self.assertEqual(run(["--root", root, "--no-git", os.path.join(root, "a.md")])[0], 1)
        root = tree({overlay: "[image](image/README.md) and an artifact\n"})
        code, out, err = run(["--root", root, "--no-git"])
        self.assertEqual(code, 1)
        self.assertIn("1 spelling hit", err)
        self.assertNotIn("link", err)


if __name__ == "__main__":
    unittest.main()
