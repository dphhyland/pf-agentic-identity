"""tools/release-notes.py on fixture trees: a release page shaped like docs/releases/0.4.0.md, a changelog
shaped like CHANGELOG.md, and fragments well formed and not."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

rn = load("release-notes.py")

PAGE = """# 9.9.0 - a release

Intro.

## Before you deploy

1. **First thing.** Text
   that continues.
2. **Second thing.** See [the guide](../operator/README.md).

## What changes for readers

- Something.

## Package OLD: an earlier package

Its notes.

## Findings closed in 9.9.0

The register.

## What we verified

Later.
"""

CHANGELOG = """# Changelog

Intro.

## [Unreleased] - 9.9.0-SNAPSHOT

What it is for.

- **Existing** - a bullet.

## [9.8.0] - 2026-01-01

Older.
"""

GOOD = """# The thing (A1)

## Changelog

- Plan item A1: the thing. Closes [F-0001](../../findings/F-0001.yaml).

## Before you deploy

1. **Do this first.** Because. See **Then do that**.
2. **Then do that.** Link to [the lib](../../../libs/x/README.md#usage), and
   [a site](https://example.com/a), and [an anchor](#here).
   - a nested point
   - another

## Notes

What changed, with [the finding](../../findings/F-0002.yaml).

Residual risk: none.
"""

NO_ITEMS = """# B2 - quiet change

## Changelog

- Plan item B2: nothing a consumer does.

## Before you deploy

None.

## Notes

Only internal.
"""


class Tree:
    def __init__(self, fragments, page=PAGE, changelog=CHANGELOG):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "docs", "releases", "unreleased"))
        self.write("docs/releases/9.9.0.md", page)
        self.write("CHANGELOG.md", changelog)
        self.write("docs/releases/unreleased/README.md", "# not a fragment\n")
        for name, text in fragments.items():
            self.write(f"docs/releases/unreleased/{name}", text)

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8") as f:
            return f.read()

    def exists(self, rel):
        return os.path.exists(os.path.join(self.root, rel))

    def run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rn.main(["--root", self.root, *argv])
        return code, out.getvalue(), err.getvalue()

    def close(self):
        self.tmp.cleanup()


class CheckTest(unittest.TestCase):
    def check(self, text, name="A1.md"):
        tree = Tree({name: text})
        self.addCleanup(tree.close)
        return tree.run("check")

    def test_a_well_formed_fragment_passes(self):
        code, out, _ = self.check(GOOD)
        self.assertEqual(0, code)
        self.assertIn("1 fragments well formed", out)

    def test_none_is_allowed_for_nothing_to_do(self):
        self.assertEqual(0, self.check(NO_ITEMS, "B2.md")[0])

    def test_the_readme_is_not_a_fragment(self):
        tree = Tree({})
        self.addCleanup(tree.close)
        code, out, _ = tree.run("check")
        self.assertEqual(0, code)
        self.assertIn("0 fragments", out)

    def test_a_missing_heading_is_refused(self):
        code, _, err = self.check(GOOD.replace("## Notes\n", ""))
        self.assertEqual(1, code)
        self.assertIn("the headings must be exactly", err)

    def test_headings_out_of_order_are_refused(self):
        text = GOOD.replace("## Changelog", "## TEMP").replace("## Notes", "## Changelog").replace("## TEMP", "## Notes")
        self.assertIn("in that order", self.check(text)[2])

    def test_an_extra_heading_is_refused(self):
        self.assertEqual(1, self.check(GOOD + "\n## Also\n\nMore.\n")[0])

    def test_no_title_is_refused(self):
        self.assertIn("the first line must be the title", self.check(GOOD.replace("# The thing (A1)\n", ""))[2])

    def test_a_second_title_is_refused(self):
        self.assertIn("a second title", self.check(GOOD + "\n# Another\n")[2])

    def test_an_item_without_a_bold_title_is_refused(self):
        _, _, err = self.check(GOOD.replace("2. **Then do that.** Link", "2. Then do that. Link"))
        self.assertIn("item 2 does not open with a bold title", err)

    def test_a_bold_title_may_wrap(self):
        text = GOOD.replace("1. **Do this first.** Because.", "1. **Do this\n   first.** Because.")
        self.assertEqual(0, self.check(text)[0])

    def test_numbering_must_run_from_one(self):
        self.assertIn("item numbered 3, expected 2", self.check(GOOD.replace("2. **Then", "3. **Then"))[2])
        self.assertIn("item numbered 2, expected 1", self.check(GOOD.replace("1. **Do", "2. **Do"))[2])

    def test_a_paragraph_between_items_is_refused(self):
        text = GOOD.replace("2. **Then", "A loose paragraph.\n\n2. **Then")
        self.assertIn("not a numbered item", self.check(text)[2])

    def test_a_bulleted_before_you_deploy_is_refused(self):
        text = GOOD.replace("1. **Do this first.**", "- **Do this first.**").replace("2. **Then do", "- **Then do")
        self.assertEqual(1, self.check(text)[0])

    def test_an_empty_before_you_deploy_is_refused(self):
        self.assertIn("is empty", self.check(NO_ITEMS.replace("None.\n", ""), "B2.md")[2])

    def test_a_reference_by_number_is_refused_anywhere(self):
        for ref in ("see item 2", "items 1 and 2", "Item 17's text", "(item 3)"):
            with self.subTest(ref=ref):
                code, _, err = self.check(GOOD.replace("Residual risk: none.", ref))
                self.assertEqual(1, code)
                self.assertIn("refers to an item by its number", err)

    def test_a_plan_item_id_is_not_a_number(self):
        self.assertEqual(0, self.check(GOOD.replace("Residual risk: none.", "plan item S4d and item S-9"))[0])

    def test_a_bulleted_changelog_is_required(self):
        self.assertIn("bulleted list", self.check(GOOD.replace("- Plan item A1", "Plan item A1"))[2])

    def test_a_lower_case_file_name_is_refused(self):
        self.assertIn("the file name must be the package id", self.check(GOOD, "a1.md")[2])

    def test_a_fence_hides_its_contents(self):
        text = GOOD.replace("Residual risk: none.", "```sh\n## not a heading\nitem 3\n```")
        self.assertEqual(0, self.check(text)[0])

    def test_every_malformed_fragment_is_reported(self):
        tree = Tree({"A1.md": GOOD.replace("## Notes\n", ""), "B2.md": NO_ITEMS.replace("## Changelog\n", "")})
        self.addCleanup(tree.close)
        code, _, err = tree.run("check")
        self.assertEqual(1, code)
        self.assertIn("2 of 2 fragments malformed", err)


class AssembleTest(unittest.TestCase):
    def setUp(self):
        self.tree = Tree({"A1.md": GOOD, "B2.md": NO_ITEMS})
        self.addCleanup(self.tree.close)

    def test_items_are_appended_and_numbered_on_without_renumbering_the_page(self):
        code, out, _ = self.tree.run("assemble", "9.9.0")
        self.assertEqual(0, code, out)
        page = self.tree.read("docs/releases/9.9.0.md")
        self.assertIn("1. **First thing.** Text\n   that continues.\n2. **Second thing.**", page)
        self.assertIn("\n3. **Do this first.** (A1) Because. See **Then do that**.\n4. **Then do that.** (A1)", page)
        self.assertLess(page.index("4. **Then do that.** (A1)"), page.index("## What changes for readers"))
        self.assertIn("2. **Second thing.** See [the guide](../operator/README.md).\n3. **Do this first.**", page)

    def test_links_are_rebased_to_the_page_and_the_changelog(self):
        self.tree.run("assemble", "9.9.0")
        page = self.tree.read("docs/releases/9.9.0.md")
        self.assertIn("[the lib](../../libs/x/README.md#usage)", page)
        self.assertIn("[a site](https://example.com/a)", page)
        self.assertIn("[an anchor](#here)", page)
        self.assertIn("[the finding](../findings/F-0002.yaml)", page)
        changelog = self.tree.read("CHANGELOG.md")
        self.assertIn("[F-0001](docs/findings/F-0001.yaml)", changelog)

    def test_notes_become_package_sections_before_findings_closed(self):
        self.tree.run("assemble", "9.9.0")
        page = self.tree.read("docs/releases/9.9.0.md")
        a1 = page.index("## Package A1: The thing\n\nWhat changed")
        b2 = page.index("## Package B2: quiet change\n\nOnly internal.")
        self.assertLess(page.index("## Package OLD"), a1)
        self.assertLess(a1, b2)
        self.assertLess(b2, page.index("## Findings closed in 9.9.0"))
        self.assertNotIn("None.", page)

    def test_changelog_bullets_close_the_unreleased_section(self):
        self.tree.run("assemble", "9.9.0")
        changelog = self.tree.read("CHANGELOG.md")
        self.assertIn(
            "- **Existing** - a bullet.\n\n- Plan item A1: the thing. Closes [F-0001](docs/findings/F-0001.yaml).\n\n"
            "- Plan item B2: nothing a consumer does.\n\n## [9.8.0] - 2026-01-01",
            changelog,
        )

    def test_the_fragments_are_deleted_and_the_readme_kept(self):
        self.tree.run("assemble", "9.9.0")
        self.assertFalse(self.tree.exists("docs/releases/unreleased/A1.md"))
        self.assertFalse(self.tree.exists("docs/releases/unreleased/B2.md"))
        self.assertTrue(self.tree.exists("docs/releases/unreleased/README.md"))
        self.assertEqual(0, self.tree.run("check")[0])

    def test_a_second_run_folds_nothing(self):
        self.tree.run("assemble", "9.9.0")
        page = self.tree.read("docs/releases/9.9.0.md")
        code, out, _ = self.tree.run("assemble", "9.9.0")
        self.assertEqual(0, code)
        self.assertIn("no fragments to fold", out)
        self.assertEqual(page, self.tree.read("docs/releases/9.9.0.md"))

    def test_a_malformed_fragment_stops_everything(self):
        self.tree.write("docs/releases/unreleased/C3.md", GOOD.replace("## Notes\n", ""))
        code, _, err = self.tree.run("assemble", "9.9.0")
        self.assertEqual(1, code)
        self.assertIn("nothing written", err)
        self.assertEqual(PAGE, self.tree.read("docs/releases/9.9.0.md"))
        self.assertEqual(CHANGELOG, self.tree.read("CHANGELOG.md"))
        self.assertTrue(self.tree.exists("docs/releases/unreleased/A1.md"))

    def test_a_page_without_its_sections_is_refused(self):
        self.tree.write("docs/releases/9.9.0.md", PAGE.replace("## Findings closed in 9.9.0", "## Findings"))
        code, _, err = self.tree.run("assemble", "9.9.0")
        self.assertEqual(1, code)
        self.assertIn("'## Findings closed'", err)
        self.assertTrue(self.tree.exists("docs/releases/unreleased/A1.md"))

    def test_a_missing_page_or_a_bad_version_is_refused(self):
        self.assertIn("does not exist", self.tree.run("assemble", "9.9.1")[2])
        self.assertIn("not a release version", self.tree.run("assemble", "9.9")[2])

    def test_a_changelog_without_unreleased_is_refused(self):
        self.tree.write("CHANGELOG.md", CHANGELOG.replace("## [Unreleased]", "## [9.9.0]"))
        self.assertIn("'## [Unreleased]'", self.tree.run("assemble", "9.9.0")[2])

    def test_a_page_with_ten_items_keeps_nested_lines_inside_the_renumbered_item(self):
        many = "\n".join(f"{n}. **Item {n}.** Text." for n in range(1, 10))
        self.tree.write("docs/releases/9.9.0.md", PAGE.replace(
            "1. **First thing.** Text\n   that continues.\n2. **Second thing.** See [the guide](../operator/README.md).", many))
        self.tree.run("assemble", "9.9.0")
        page = self.tree.read("docs/releases/9.9.0.md")
        self.assertIn("9. **Item 9.** Text.\n10. **Do this first.** (A1)", page)
        self.assertIn("11. **Then do that.** (A1) Link to [the lib](../../libs/x/README.md#usage), and\n"
                      "    [a site](https://example.com/a), and [an anchor](#here).\n"
                      "    - a nested point\n    - another\n", page)


class AttributeTest(unittest.TestCase):
    def test_the_package_follows_the_bold_title(self):
        self.assertEqual(["1. **T.** (S1B) a"], rn.attribute(["1. **T.** a"], "S1B"))

    def test_a_wrapped_title_is_followed_on_its_last_line(self):
        self.assertEqual(["1. **A long", "   title.** (HYG) a"], rn.attribute(["1. **A long", "   title.** a"], "HYG"))

    def test_an_item_that_names_its_origin_is_left_alone(self):
        self.assertEqual(["1. **T.** (S3a) a"], rn.attribute(["1. **T.** (S3a) a"], "S1B"))


class RenumberTest(unittest.TestCase):
    def test_a_narrower_marker_pulls_its_lines_in(self):
        self.assertEqual(["2. **T.** a", "   b", "   - c"], rn.renumber(["12. **T.** a", "    b", "    - c"], 2))
        # A line indented less than the old marker was never inside the item's block; it is left as it is.
        self.assertEqual(["2. **T.** a", "  lazy"], rn.renumber(["12. **T.** a", "  lazy"], 2))

    def test_the_same_width_changes_only_the_number(self):
        self.assertEqual(["7. **T.** a", "   b"], rn.renumber(["1. **T.** a", "   b"], 7))


if __name__ == "__main__":
    unittest.main()
