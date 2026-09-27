"""tools/check-showcase-links.py's judgement of one citation and one document link: a tracked file and its
lines, a line past the end, an untracked file, and a generated file - checked when the build left one, noted
when it did not."""
import unittest

from _tools import load

csl = load("check-showcase-links.py")

TRACKED = {"src/Gate.java", "docs/guide.md"}
DIRECTORIES = {"src", "docs", "."}
SIBLINGS = {"pf-oidf-modules"}


def ten_lines(path):
    return 10


class ProblemsTest(unittest.TestCase):
    def judge(self, reference, tracked=TRACKED, unbuilt=frozenset()):
        skipped = []
        found = csl.problems(reference, tracked, DIRECTORIES, SIBLINGS, ten_lines, unbuilt, skipped)
        return found, skipped

    def test_a_tracked_file_and_its_lines_pass(self):
        self.assertEqual(self.judge("src/Gate.java:3-5,9"), ([], []))
        self.assertEqual(self.judge("src/Gate.java"), ([], []))
        self.assertEqual(self.judge("pf-oidf-modules:anything/at/all:400"), ([], []))

    def test_a_line_past_the_end_fails(self):
        found, _ = self.judge("src/Gate.java:9-11")
        self.assertEqual(found, ["src/Gate.java:9-11: src/Gate.java has 10 lines, not 9-11"])

    def test_an_untracked_file_fails(self):
        found, skipped = self.judge("docs/nothing.md:1")
        self.assertEqual(found, ["docs/nothing.md:1: docs/nothing.md is not a tracked file"])
        self.assertEqual(skipped, [])

    def test_a_generated_file_that_is_not_built_is_noted_not_failed(self):
        found, skipped = self.judge("docs/coverage-dashboard.md:9-36 the gates table",
                                    unbuilt={"docs/coverage-dashboard.md"})
        self.assertEqual(found, [])
        self.assertEqual(skipped, ["docs/coverage-dashboard.md:9-36 the gates table"])

    def test_a_generated_file_the_build_left_is_checked_like_a_tracked_one(self):
        built = TRACKED | {"docs/coverage-dashboard.md"}
        self.assertEqual(self.judge("docs/coverage-dashboard.md:9-10", tracked=built), ([], []))
        found, skipped = self.judge("docs/coverage-dashboard.md:9-36", tracked=built)
        self.assertEqual(found, ["docs/coverage-dashboard.md:9-36: docs/coverage-dashboard.md has 10 lines, not 9-36"])
        self.assertEqual(skipped, [])


class DocMissingTest(unittest.TestCase):
    DOCS = {"docs/guide.md": {"title": "Guide", "html": ""}}

    def judge(self, target):
        failures, skipped = [], []
        csl.doc_missing(target, self.DOCS, f"#doc:{target} (in DATA)", failures, skipped)
        return failures, skipped

    def test_a_carried_document_passes(self):
        self.assertEqual(self.judge("docs/guide.md"), ([], []))

    def test_an_unknown_document_fails(self):
        self.assertEqual(self.judge("docs/nothing.md"),
                         (["#doc:docs/nothing.md (in DATA): the page carries no such document"], []))

    def test_a_generated_document_docs_js_lacks_is_noted(self):
        self.assertEqual(self.judge("docs/coverage-dashboard.md"), ([], ["#doc:docs/coverage-dashboard.md (in DATA)"]))


if __name__ == "__main__":
    unittest.main()
