"""tools/findings.py on fixture registers: the YAML subset it reads, the schema it enforces, the plan ids it
takes from a plan, the gate, and the listings. The last test runs the check over the repository's own
register, so a malformed finding fails the tools' tests as well as the docs workflow."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

fd = load("findings.py")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

PLAN = """# A plan

## Programme at a glance

| Phase | Packages |
|---|---|
| 1 | S1a S1b · X-D02 + R-I1 · D-1 D-2 |

## Workstream S

**S-1 Shared model** (B1). PRs: S1a (L), S1b (M).
- **S2a hotfix:** fail open only on transport errors.
  Absorbs X-A02 when it lands.
- Plain bullet naming H-FED-9, which is not an item definition.

| Finding | Closed by |
|---|---|
| B1 scalars | S-1 (+ S-4d) |
"""

F_OK = """id: F-0001
title: B1 RAR containment ignores scalars
severity: blocker
area: client-attestation, rar-paz-plugin
source: review-2026-09-26
status: open
plan_items: [S-1, S1a]
prs: []
verification: ''
target_release: 0.4.0
notes: >
  Two lines of folded
  text.
"""

U_OK = """id: U-0001
title: 'Something nobody has checked: with a colon'
area: ssf
source: design
status: open
plan_items:
  - S2a
  - X-D02
prs: [11]
recorded_in: docs/unverified.md item 1
verify_by: Run it on the rig.
verification: ''
notes: |
  Literal
    block.
"""


def register(files):
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "docs", "findings"))
    with open(os.path.join(root, "docs", "findings", "plan-ids.txt"), "w", encoding="utf-8") as f:
        f.write("# ids\n" + "\n".join(sorted(fd.plan_ids_of(PLAN))) + "\n")
    for name, text in files.items():
        with open(os.path.join(root, "docs", "findings", name), "w", encoding="utf-8") as f:
            f.write(text)
    return root


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = fd.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Parser(unittest.TestCase):

    def test_the_shapes_the_register_uses(self):
        data = fd.parse(F_OK, "F-0001.yaml")
        self.assertEqual(data["plan_items"], ["S-1", "S1a"])
        self.assertEqual(data["prs"], [])
        self.assertEqual(data["verification"], "")
        self.assertEqual(data["notes"], "Two lines of folded text.")
        data = fd.parse(U_OK, "U-0001.yaml")
        self.assertEqual(data["title"], "Something nobody has checked: with a colon")
        self.assertEqual(data["plan_items"], ["S2a", "X-D02"])
        self.assertEqual(data["prs"], ["11"])
        self.assertEqual(data["notes"], "Literal\n  block.")

    def test_quotes_comments_and_document_markers(self):
        data = fd.parse('---\n# a comment\nid: "F-0002"  # trailing\ntitle: \'it\'\'s\'\nprs: ["11", \'12\']\n...\n')
        self.assertEqual(data, {"id": "F-0002", "title": "it's", "prs": ["11", "12"]})

    def test_folded_paragraphs_keep_a_newline(self):
        data = fd.parse("notes: >\n  one\n  two\n\n  three\n")
        self.assertEqual(data["notes"], "one two\nthree")

    def test_what_it_refuses(self):
        for text, message in [
            ("id: F-0001\nid: F-0002\n", "given twice"),
            ("  id: F-0001\n", "indentation"),
            ("id\n", "expected `key: value`"),
            ("notes:\n", "has no value"),
            ("prs: [1,\n", "close on the same line"),
            ("prs: [[1]]\n", "nested"),
            ("prs: [1,,2]\n", "empty item"),
            ("title: \"open\n", "unterminated"),
            ("title: 'it's'\n", "after the closing quote"),
            ("title: 'open\n", "unterminated single"),
            ("title: \"a\" b\n", "after the closing quote"),
            ("title: a: b\n", "': '"),
            ("title: |x\n", "may not start"),
            ("title: *ref\n", "may not start"),
            ("prs: - 1\n", "next line"),
        ]:
            with self.assertRaises(fd.ParseError, msg=text) as ctx:
                fd.parse(text, "x.yaml")
            self.assertIn(message, str(ctx.exception), text)
            self.assertIn("x.yaml:", str(ctx.exception))


class PlanIds(unittest.TestCase):

    def test_ids_come_from_headings_tables_and_bold_led_items_including_wrapped_lines(self):
        ids = fd.plan_ids_of(PLAN)
        self.assertEqual(ids, {"S1a", "S1b", "X-D02", "R-I1", "D-1", "D-2", "S-1", "B1", "S2a", "X-A02", "S-4d"})
        self.assertNotIn("H-FED-9", ids)

    def test_the_repo_plan_ids_file_is_read_as_one_id_per_line(self):
        root = register({})
        ids = fd.read_plan_ids(os.path.join(root, "docs", "findings", "plan-ids.txt"))
        self.assertIn("S1a", ids)
        self.assertNotIn("# ids", ids)

    def test_plan_ids_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "plan.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(PLAN)
            code, out, err = run(["plan-ids", path])
            self.assertEqual(code, 0)
            self.assertEqual(out.split(), sorted(fd.plan_ids_of(PLAN)))


class Check(unittest.TestCase):

    def test_a_well_formed_register(self):
        root = register({"F-0001.yaml": F_OK, "U-0001.yaml": U_OK})
        code, out, err = run(["--root", root, "--check"])
        self.assertEqual(code, 0, err)
        self.assertIn("ok: 1 findings and 1 unverified items", out)

    def test_a_plan_file_can_replace_the_ids_file(self):
        root = register({"F-0001.yaml": F_OK})
        with open(os.path.join(root, "plan.md"), "w", encoding="utf-8") as f:
            f.write(PLAN)
        self.assertEqual(run(["--root", root, "--check", "--plan", os.path.join(root, "plan.md")])[0], 0)
        with open(os.path.join(root, "plan.md"), "w", encoding="utf-8") as f:
            f.write("# nothing\n")
        code, out, err = run(["--root", root, "--check", "--plan", os.path.join(root, "plan.md")])
        self.assertEqual(code, 1)
        self.assertIn("plan item 'S-1' is not one the plan names", err)

    def test_what_it_refuses(self):
        cases = {
            "id mismatch": ("F-0009.yaml", F_OK, "does not match the file name"),
            "duplicate id": ("F-0002.yaml", F_OK, "is also"),
            "bad severity": ("F-0001.yaml", F_OK.replace("severity: blocker", "severity: urgent"), "severity 'urgent'"),
            "bad source": ("F-0001.yaml", F_OK.replace("source: review-2026-09-26", "source: gut"), "source 'gut'"),
            "bad status": ("F-0001.yaml", F_OK.replace("status: open", "status: wontfix"), "status 'wontfix'"),
            "U status": ("U-0001.yaml", U_OK.replace("status: open", "status: mitigated"), "status 'mitigated'"),
            "unknown plan item": ("F-0001.yaml", F_OK.replace("[S-1, S1a]", "[S-99]"), "plan item 'S-99'"),
            "missing field": ("F-0001.yaml", F_OK.replace("target_release: 0.4.0\n", ""), "missing target_release"),
            "unknown field": ("F-0001.yaml", F_OK + "owner: me\n", "unknown field owner"),
            "bad area": ("F-0001.yaml", F_OK.replace("area: client-attestation, rar-paz-plugin", "area: Client Attestation"), "area 'Client Attestation'"),
            "bad pr": ("F-0001.yaml", F_OK.replace("prs: []", "prs: [PR 11]"), "pr 'PR 11'"),
            "bad version": ("F-0001.yaml", F_OK.replace("target_release: 0.4.0", "target_release: v0.4"), "target_release 'v0.4'"),
            "closed without verification": ("F-0001.yaml", F_OK.replace("status: open", "status: closed"), "needs verification text"),
            "closed without a date": ("F-0001.yaml", F_OK.replace("status: open", "status: closed").replace("verification: ''", "verification: done"), "carry the date"),
            "accepted without expiry": ("F-0001.yaml", F_OK.replace("status: open", "status: accepted").replace("verification: ''", "verification: accepted 2026-09-27"), "needs an expiry"),
            "expiry on an open finding": ("F-0001.yaml", F_OK + "expiry: 2027-01-01\n", "belongs only on an accepted"),
            "list as string": ("F-0001.yaml", F_OK.replace("prs: []", "prs: none"), "prs must be a list"),
            "long title": ("F-0001.yaml", F_OK.replace("title: B1 RAR containment ignores scalars", "title: " + "x" * 161), "longer than 160"),
            "empty verify_by": ("U-0001.yaml", U_OK.replace("verify_by: Run it on the rig.", "verify_by: ''"), "verify_by is empty"),
        }
        for label, (name, text, message) in cases.items():
            files = {"F-0001.yaml": F_OK, "U-0001.yaml": U_OK}
            files[name] = text
            root = register(files)
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1, label)
            self.assertIn(message, err, label)

    def test_a_file_that_does_not_parse_names_its_line(self):
        root = register({"F-0001.yaml": F_OK.replace("status: open", "  status: open")})
        code, out, err = run(["--root", root, "--check"])
        self.assertEqual(code, 1)
        self.assertIn("F-0001.yaml:6: unexpected indentation", err)

    def test_an_empty_register_is_an_error(self):
        root = register({})
        code, out, err = run(["--root", root, "--check"])
        self.assertEqual(code, 1)
        self.assertIn("has no findings", err)


def closed(text, date="2026-09-27"):
    return text.replace("status: open", "status: closed").replace("verification: ''", f"verification: done on {date}")


class Gate(unittest.TestCase):

    def test_one_point_zero_needs_every_blocker_and_high_closed_and_no_open_unverified(self):
        root = register({"F-0001.yaml": F_OK, "U-0001.yaml": U_OK})
        code, out, err = run(["--root", root, "--gate", "1.0"])
        self.assertEqual(code, 1)
        self.assertIn("F-0001: blocker, open", out)
        self.assertIn("U-0001: unverified, open", out)
        root = register({"F-0001.yaml": closed(F_OK), "U-0001.yaml": closed(U_OK)})
        code, out, err = run(["--root", root, "--gate", "1.0.0"])
        self.assertEqual(code, 0, out)
        self.assertIn("gate 1.0.0: met", out)

    def test_a_mitigated_blocker_is_not_closed(self):
        root = register({"F-0001.yaml": F_OK.replace("status: open", "status: mitigated").replace("verification: ''", "verification: stopgap 2026-09-27")})
        code, out, err = run(["--root", root, "--gate", "1.0"])
        self.assertEqual(code, 1)
        self.assertIn("F-0001: blocker, mitigated", out)

    def test_accepted_needs_a_future_expiry_and_never_covers_a_blocker_or_high(self):
        medium = F_OK.replace("severity: blocker", "severity: medium")
        accepted = medium.replace("status: open", "status: accepted").replace("verification: ''", "verification: accepted 2026-09-27") + "expiry: 2027-03-01\n"
        root = register({"F-0001.yaml": accepted})
        self.assertEqual(run(["--root", root, "--gate", "1.0", "--today", "2027-02-28"])[0], 0)
        code, out, err = run(["--root", root, "--gate", "1.0", "--today", "2027-03-01"])
        self.assertEqual(code, 1)
        self.assertIn("expired on 2027-03-01", out)
        high = accepted.replace("severity: medium", "severity: high")
        root = register({"F-0001.yaml": high})
        code, out, err = run(["--root", root, "--gate", "1.0", "--today", "2027-02-28"])
        self.assertEqual(code, 1)
        self.assertIn("cannot be accepted for 1.0.0", out)

    def test_an_earlier_release_gates_only_what_targets_it(self):
        later = F_OK.replace("target_release: 0.4.0", "target_release: 0.6.0")
        root = register({"F-0001.yaml": later, "U-0001.yaml": U_OK})
        self.assertEqual(run(["--root", root, "--gate", "0.4.0"])[0], 0)
        code, out, err = run(["--root", root, "--gate", "0.6.0"])
        self.assertEqual(code, 1)
        self.assertIn("targeted at 0.6.0", out)
        self.assertNotIn("U-0001", out)

    def test_a_release_that_is_not_one_is_a_usage_error(self):
        root = register({"F-0001.yaml": F_OK})
        self.assertEqual(run(["--root", root, "--gate", "next"])[0], 2)


class Listings(unittest.TestCase):

    def test_list_filters(self):
        root = register({"F-0001.yaml": F_OK, "U-0001.yaml": U_OK})
        code, out, err = run(["--root", root, "list"])
        self.assertEqual(code, 0)
        self.assertIn("F-0001  blocker  open", out)
        self.assertIn("U-0001", out)
        code, out, err = run(["--root", root, "list", "--severity", "high"])
        self.assertEqual(out, "")
        code, out, err = run(["--root", root, "list", "--kind", "U", "--area", "ssf"])
        self.assertIn("U-0001", out)
        self.assertNotIn("F-0001", out)
        code, out, err = run(["--root", root, "list", "--status", "closed"])
        self.assertEqual(out, "")

    def test_index_is_a_markdown_table_per_kind(self):
        root = register({"F-0001.yaml": F_OK, "U-0001.yaml": U_OK})
        code, out, err = run(["--root", root, "index"])
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0], "| Id | Severity | Status | Area | Title | Plan items | Target |")
        self.assertIn("| F-0001 | blocker | open | client-attestation, rar-paz-plugin | B1 RAR containment ignores scalars | S-1, S1a | 0.4.0 |", lines)
        self.assertIn("| U-0001 | open | ssf | Something nobody has checked: with a colon | S2a, X-D02 | docs/unverified.md item 1 |", lines)

    def test_one_mode_at_a_time(self):
        root = register({"F-0001.yaml": F_OK})
        self.assertEqual(run(["--root", root])[0], 2)
        self.assertEqual(run(["--root", root, "--check", "list"])[0], 2)


class TheRepositoryRegister(unittest.TestCase):

    def test_the_committed_register_passes_the_check(self):
        code, out, err = run(["--root", REPO, "--check"])
        self.assertEqual(code, 0, err)

    def test_u_0004_keeps_the_number_unverified_md_gave_it(self):
        with open(os.path.join(REPO, "docs", "findings", "U-0004.yaml"), encoding="utf-8") as f:
            data = fd.parse(f.read())
        self.assertEqual(data["recorded_in"], "docs/unverified.md item 14")


if __name__ == "__main__":
    unittest.main()
