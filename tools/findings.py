#!/usr/bin/env python3
"""The findings register: one YAML file per finding under docs/findings/, checked, listed, gated and indexed.

  tools/findings.py --check                        every file parses, every id is unique, every value is allowed
  tools/findings.py --check --plan PLAN.md         ... with the plan items checked against a plan file, not the txt
  tools/findings.py list [--status open] [--severity high] [--kind F] [--area ssf]
  tools/findings.py --gate 1.0                     exit 1 while anything stands in the way of that release
  tools/findings.py index [--kind F]               a Markdown table, on demand, never committed
  tools/findings.py plan-ids PLAN.md               the plan item ids a plan file names, one per line

A finding is docs/findings/F-NNNN.yaml (a defect, a gap or a risk) or docs/findings/U-NNNN.yaml (an
assumption nobody has verified yet). One file per finding so that parallel pull requests do not fight over one
register; the index is generated here when someone wants to read it. docs/findings/README.md describes the fields.

The files are read by the small parser below, not by a YAML library: the runner that checks them has none, and
a register that needs only a dozen shapes is better refused than guessed at. What it reads is plain YAML - a
top-level mapping of `key: value` lines, flow lists (`[a, b]`), block lists (`- a`), block scalars (`|`, `>`)
and comments - so a YAML library reads the same files the same way. Anything else is an error that names the
file and the line.

Plan items are the ids the programme plan gives its packages (S1a, H-FED-3, X-A15 ...). A finding names the
plan items that close it, and --check refuses an id the plan does not have. The plan lives outside the
repository, so docs/findings/plan-ids.txt carries the ids it named when it was last read; `plan-ids` prints
them from the plan's headings, tables and bold-led items so that file can be refreshed.

Exit status: 0 when the check, gate or command succeeds; 1 when --check finds a problem or --gate is not met;
2 for a usage error or a file that does not parse.
"""
import argparse
import datetime
import os
import re
import sys

REGISTER = "docs/findings"
PLAN_IDS = "docs/findings/plan-ids.txt"

SEVERITIES = ("blocker", "high", "medium", "low")
SOURCES = ("review-2026-09-26", "design", "reviewer-report", "phase-0-review")
F_STATUSES = ("open", "mitigated", "closed", "accepted")
U_STATUSES = ("open", "closed", "accepted")

F_FIELDS = ("id", "title", "severity", "area", "source", "status", "plan_items", "prs", "verification",
            "target_release", "notes")
U_FIELDS = ("id", "title", "area", "source", "status", "plan_items", "prs", "recorded_in", "verify_by",
            "verification", "notes")
OPTIONAL_FIELDS = ("expiry",)

ID_RE = re.compile(r"^([FU])-(\d{4})$")
AREA_RE = re.compile(r"^[a-z0-9][a-z0-9-]*(, [a-z0-9][a-z0-9-]*)*$")
PR_RE = re.compile(r"^\d+$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# The ids the plan gives its packages: a workstream letter or word, a hyphen or not, a number, an optional
# letter (S4d), and the H-* items with their area (H-FED-3). B1-B7 are the review's blockers, named in the
# traceability table.
PLAN_ID_RE = re.compile(r"(?<![A-Za-z0-9-])(?:P0-\d+|S-?\d+[a-z]?(?:-\d+)?|F-\d+|ST-\d+|PR-\d+|O-\d+|DB-\d+|C-\d+|"
                        r"R-I\d+|R-CI\d+|X-[A-Z]\d{2}[a-z]?|D-\d+|H-[A-Z]+-\d+|M-\d+|V-\d+|B\d)(?![A-Za-z0-9-])")


class ParseError(Exception):
    """A file that is not the YAML this register reads; carries the file and line."""


# --- the YAML subset ------------------------------------------------------------------------------------------

def _quoted_end(raw, where):
    """The index of the quote that closes a quoted scalar, honouring \\" inside double quotes and '' inside
    single quotes."""
    quote = raw[0]
    i = 1
    while i < len(raw):
        c = raw[i]
        if quote == '"' and c == "\\":
            i += 2
            continue
        if c == quote:
            if quote == "'" and raw[i + 1:i + 2] == "'":
                i += 2
                continue
            return i
        i += 1
    raise ParseError(f"{where}: unterminated {'double' if quote == chr(34) else 'single'}-quoted string")


def _unquote(raw, where):
    """A double- or single-quoted scalar, or a plain one with its trailing comment removed."""
    if raw[:1] in ('"', "'"):
        end = _quoted_end(raw, where)
        rest = raw[end + 1:]
        if rest.strip() and not re.match(r"\s+#", rest):
            raise ParseError(f"{where}: text after the closing quote")
        raw = raw[:end + 1]
    if raw.startswith('"'):
        body = raw[1:-1]
        out, i = [], 0
        while i < len(body):
            c = body[i]
            if c == "\\":
                if i + 1 >= len(body):
                    raise ParseError(f"{where}: a backslash ends the string")
                nxt = body[i + 1]
                escapes = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "/": "/"}
                if nxt not in escapes:
                    raise ParseError(f"{where}: unsupported escape \\{nxt} (only \\\" \\\\ \\n \\t are read)")
                out.append(escapes[nxt])
                i += 2
            elif c == '"':
                raise ParseError(f"{where}: a double quote inside a double-quoted string must be written \\\"")
            else:
                out.append(c)
                i += 1
        return "".join(out)
    if raw.startswith("'"):
        body = raw[1:-1]
        return body.replace("''", "'")
    # A plain scalar: ` #` starts a comment, and the indicators YAML gives a meaning to are refused rather
    # than read as something else.
    value = re.split(r"\s#", raw, maxsplit=1)[0].rstrip()
    if value and value[0] in "{}&*!|>%@`":
        raise ParseError(f"{where}: a value may not start with {value[0]!r}; quote it")
    if value.endswith(":") or ": " in value:
        raise ParseError(f"{where}: a plain value may not contain ': '; quote it")
    return value


def _flow_list(raw, where):
    inner = raw[1:-1].strip()
    if not inner:
        return []
    items, current, quote = [], [], None
    i = 0
    while i < len(inner):
        c = inner[i]
        if quote:
            current.append(c)
            if c == quote and not (quote == "'" and inner[i + 1:i + 2] == "'"):
                quote = None
            elif quote == "'" and c == "'" and inner[i + 1:i + 2] == "'":
                current.append("'")
                i += 1
        elif c in "\"'" and not "".join(current).strip():
            current = [c]
            quote = c
        elif c == ",":
            items.append("".join(current).strip())
            current = []
        elif c in "[]{}":
            raise ParseError(f"{where}: nested collections are not read; one flat list per key")
        else:
            current.append(c)
        i += 1
    if quote:
        raise ParseError(f"{where}: unterminated quoted string in list")
    items.append("".join(current).strip())
    if any(item == "" for item in items):
        raise ParseError(f"{where}: an empty item in a list (a trailing comma, or two commas)")
    return [_unquote(item, where) for item in items]


def parse(text, name="<text>"):
    """The top-level mapping of one register file: keys to strings or lists of strings."""
    lines = text.split("\n")
    mapping, order = {}, []
    i = 0
    n = len(lines)
    if lines and lines[0].strip() == "---":
        i = 1
    while i < n:
        line = lines[i]
        stripped = line.strip()
        where = f"{name}:{i + 1}"
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if line[0] in " \t":
            raise ParseError(f"{where}: unexpected indentation; every key sits at column 0")
        if stripped == "...":
            break
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):(?:\s+(.*))?$", line.rstrip())
        if not m:
            raise ParseError(f"{where}: expected `key: value`")
        key, raw = m.group(1), (m.group(2) or "")
        if key in mapping:
            raise ParseError(f"{where}: {key} is given twice")
        raw = raw.strip()
        i += 1
        if raw in ("|", "|-", ">", ">-"):
            block = []
            while i < n and (lines[i].startswith("  ") or not lines[i].strip()):
                block.append(lines[i][2:] if lines[i].startswith("  ") else "")
                i += 1
            while block and not block[-1].strip():
                block.pop()
            if raw.startswith("|"):
                value = "\n".join(block)
            else:
                paragraphs, current = [], []
                for b in block:
                    if b.strip():
                        current.append(b.strip())
                    else:
                        paragraphs.append(" ".join(current))
                        current = []
                paragraphs.append(" ".join(current))
                value = "\n".join(paragraphs)
            mapping[key] = value
        elif raw == "":
            items = []
            while i < n and lines[i].startswith("  - "):
                items.append(_unquote(lines[i][4:].strip(), f"{name}:{i + 1}"))
                i += 1
            if not items:
                raise ParseError(f"{where}: {key} has no value; write [] for an empty list or '' for an empty string")
            mapping[key] = items
        elif raw.startswith("["):
            if not raw.endswith("]"):
                raise ParseError(f"{where}: a flow list must close on the same line")
            mapping[key] = _flow_list(raw, where)
        elif raw.startswith("-"):
            raise ParseError(f"{where}: a block list starts on the next line, indented two spaces")
        else:
            mapping[key] = _unquote(raw, where)
        order.append(key)
    return mapping


# --- the register --------------------------------------------------------------------------------------------

class Finding:
    def __init__(self, path, data):
        self.path = path
        self.data = data
        self.kind = ID_RE.match(data.get("id", "")).group(1) if ID_RE.match(data.get("id", "")) else None

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    @property
    def id(self):
        return self.data.get("id", os.path.basename(self.path))


def read_plan_ids(path):
    """The plan item ids a plan-ids.txt lists, or a plan .md names in its headings, tables and bold-led items."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith(".md"):
        return plan_ids_of(text)
    ids = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ids.add(line)
    return ids


def plan_ids_of(plan_text):
    """The ids a plan names where it defines or schedules its items: headings, table rows, and items whose
    text begins in bold (`- **S-1 ...**`, `**S-1 ...**`)."""
    # A plan wraps long items over several lines; a wrapped line is indented and starts with prose, and it
    # belongs to the item above it.
    logical = []
    for line in plan_text.splitlines():
        stripped = line.strip()
        if not stripped:
            logical.append("")
            continue
        continues = (line[0] in " \t" and logical and logical[-1]
                     and not re.match(r"^(?:[-*+]\s+|\d+\.\s+|[#|])", stripped))
        if continues:
            logical[-1] += " " + stripped
        else:
            logical.append(stripped)
    ids = set()
    for item in logical:
        heading = item.startswith("#")
        table_row = item.startswith("|")
        bold_led = re.match(r"^(?:[-*+]\s+|\d+\.\s+)?\*\*", item) is not None
        if heading or table_row or bold_led:
            ids.update(PLAN_ID_RE.findall(item))
    return ids


def load(root):
    """Every register file, parsed; a file that does not parse is a ParseError naming it."""
    register = os.path.join(root, REGISTER)
    findings = []
    if not os.path.isdir(register):
        raise ParseError(f"{REGISTER} does not exist under {root}")
    for name in sorted(os.listdir(register)):
        if not name.endswith(".yaml"):
            continue
        path = os.path.join(register, name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        findings.append(Finding(path, parse(text, os.path.relpath(path, root))))
    return findings


def problems_of(finding, plan_ids, rel):
    """What is wrong with one finding, as messages; empty when it is well formed."""
    data = finding.data
    out = []
    kind_match = ID_RE.match(data.get("id", ""))
    stem = os.path.splitext(os.path.basename(finding.path))[0]
    if not kind_match:
        out.append(f"{rel}: id {data.get('id', '')!r} is not F-NNNN or U-NNNN")
        return out
    if data["id"] != stem:
        out.append(f"{rel}: id {data['id']} does not match the file name {stem}")
    kind = kind_match.group(1)
    fields = F_FIELDS if kind == "F" else U_FIELDS
    for key in fields:
        if key not in data:
            out.append(f"{rel}: missing {key}")
    for key in data:
        if key not in fields and key not in OPTIONAL_FIELDS:
            out.append(f"{rel}: unknown field {key}")
    if out:
        return out
    for key in ("plan_items", "prs"):
        if not isinstance(data[key], list):
            out.append(f"{rel}: {key} must be a list ([] when empty)")
    for key in fields:
        if key not in ("plan_items", "prs") and not isinstance(data[key], str):
            out.append(f"{rel}: {key} must be a string")
    if out:
        return out
    if not data["title"].strip():
        out.append(f"{rel}: title is empty")
    if len(data["title"]) > 160:
        out.append(f"{rel}: title is longer than 160 characters; the detail belongs in notes")
    if not AREA_RE.match(data["area"]):
        out.append(f"{rel}: area {data['area']!r} is not a lower-case module or workstream name (comma-separated when several)")
    if data["source"] not in SOURCES:
        out.append(f"{rel}: source {data['source']!r} is not one of {', '.join(SOURCES)}")
    statuses = F_STATUSES if kind == "F" else U_STATUSES
    if data["status"] not in statuses:
        out.append(f"{rel}: status {data['status']!r} is not one of {', '.join(statuses)}")
    for item in data["plan_items"]:
        if item not in plan_ids:
            out.append(f"{rel}: plan item {item!r} is not one the plan names (see {PLAN_IDS})")
    for pr in data["prs"]:
        if not PR_RE.match(pr):
            out.append(f"{rel}: pr {pr!r} is not a pull request number")
    if kind == "F":
        if data["severity"] not in SEVERITIES:
            out.append(f"{rel}: severity {data['severity']!r} is not one of {', '.join(SEVERITIES)}")
        if not VERSION_RE.match(data["target_release"]):
            out.append(f"{rel}: target_release {data['target_release']!r} is not a version like 0.4.0")
    else:
        if not data["recorded_in"].strip():
            out.append(f"{rel}: recorded_in is empty; say where the assumption is written down")
        if not data["verify_by"].strip():
            out.append(f"{rel}: verify_by is empty; say what would verify it")
    if data["status"] in ("closed", "mitigated", "accepted"):
        if not data["verification"].strip():
            out.append(f"{rel}: a {data['status']} finding needs verification text")
        elif not DATE_RE.search(data["verification"]):
            out.append(f"{rel}: verification must carry the date it was done (YYYY-MM-DD)")
    if data["status"] == "accepted":
        if "expiry" not in data:
            out.append(f"{rel}: an accepted finding needs an expiry (YYYY-MM-DD), when the acceptance is reviewed")
        elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["expiry"]):
            out.append(f"{rel}: expiry {data['expiry']!r} is not YYYY-MM-DD")
    elif "expiry" in data:
        out.append(f"{rel}: expiry belongs only on an accepted finding")
    return out


def check(root, plan_path=None):
    plan_path = plan_path or os.path.join(root, PLAN_IDS)
    if not os.path.isfile(plan_path):
        print(f"error: no plan ids at {os.path.relpath(plan_path, root)}", file=sys.stderr)
        return False
    plan_ids = read_plan_ids(plan_path)
    try:
        findings = load(root)
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return False
    problems = []
    seen = {}
    for f in findings:
        rel = os.path.relpath(f.path, root)
        problems.extend(problems_of(f, plan_ids, rel))
        fid = f.get("id")
        if fid in seen:
            problems.append(f"{rel}: id {fid} is also {seen[fid]}")
        seen[fid] = rel
    if not findings:
        problems.append(f"{REGISTER} has no findings")
    if problems:
        print(f"error: {len(problems)} problem{'s' if len(problems) != 1 else ''} in {REGISTER}:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return False
    counts = {"F": sum(1 for f in findings if f.kind == "F"), "U": sum(1 for f in findings if f.kind == "U")}
    print(f"ok: {counts['F']} findings and {counts['U']} unverified items in {REGISTER} are well formed, "
          f"against {len(plan_ids)} plan items")
    return True


def version_tuple(v):
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    return tuple(int(p) for p in parts)


def gate(root, release, today):
    """What stands in the way of a release. For 1.0.0 the plan's rule: no blocker or high left open, everything
    else closed or accepted with an expiry still in the future, and no unverified item still open. For an
    earlier release: every finding whose target_release is that release or earlier is closed, or accepted the
    same way."""
    try:
        findings = load(root)
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return False
    target = version_tuple(release)
    final = target[0] >= 1
    failures = []
    for f in findings:
        fid = f.id
        status = f.get("status")
        if status == "accepted":
            expiry = f.get("expiry", "")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
                failures.append(f"{fid}: accepted without an expiry")
            elif datetime.date.fromisoformat(expiry) <= today:
                failures.append(f"{fid}: accepted, but the acceptance expired on {expiry}")
            elif final and f.kind == "F" and f.get("severity") in ("blocker", "high"):
                failures.append(f"{fid}: a {f.get('severity')} finding cannot be accepted for 1.0.0; it must be closed")
            continue
        if status == "closed":
            continue
        if f.kind == "F":
            sev = f.get("severity")
            if final:
                failures.append(f"{fid}: {sev}, {status} ({f.get('title')})")
            elif version_tuple(f.get("target_release", "9999.0.0")) <= target:
                failures.append(f"{fid}: {sev}, {status}, targeted at {f.get('target_release')} ({f.get('title')})")
        elif final:
            failures.append(f"{fid}: unverified, {status} ({f.get('title')})")
    if failures:
        print(f"gate {release}: not met, {len(failures)} finding{'s' if len(failures) != 1 else ''} in the way:")
        for line in failures:
            print(f"  {line}")
        return False
    print(f"gate {release}: met ({len(findings)} findings and unverified items considered)")
    return True


def selected(findings, args):
    out = []
    for f in findings:
        if args.kind and f.kind != args.kind:
            continue
        if args.status and f.get("status") not in args.status:
            continue
        if args.severity and f.get("severity") not in args.severity:
            continue
        if args.area and args.area not in [a.strip() for a in f.get("area", "").split(",")]:
            continue
        out.append(f)
    return out


def list_findings(findings):
    for f in findings:
        items = ", ".join(f["plan_items"]) or "-"
        if f.kind == "F":
            print(f"{f.id}  {f['severity']:<8} {f['status']:<10} {f['target_release']:<7} {f['area']}: {f['title']}  [{items}]")
        else:
            print(f"{f.id}  {'':<8} {f['status']:<10} {'':<7} {f['area']}: {f['title']}  [{items}]")


def cell(text):
    return text.replace("|", "\\|").replace("\n", " ")


def index(findings):
    fs = [f for f in findings if f.kind == "F"]
    us = [f for f in findings if f.kind == "U"]
    out = []
    if fs:
        out.append("| Id | Severity | Status | Area | Title | Plan items | Target |")
        out.append("|---|---|---|---|---|---|---|")
        for f in fs:
            out.append(f"| {f.id} | {f['severity']} | {f['status']} | {cell(f['area'])} | {cell(f['title'])} | "
                       f"{cell(', '.join(f['plan_items'])) or '-'} | {f['target_release']} |")
    if us:
        if out:
            out.append("")
        out.append("| Id | Status | Area | Title | Plan items | Recorded in |")
        out.append("|---|---|---|---|---|---|")
        for f in us:
            out.append(f"| {f.id} | {f['status']} | {cell(f['area'])} | {cell(f['title'])} | "
                       f"{cell(', '.join(f['plan_items'])) or '-'} | {cell(f['recorded_in'])} |")
    print("\n".join(out))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", nargs="?", choices=["list", "index", "plan-ids"], help="a listing, the index, or the ids a plan names")
    ap.add_argument("plan", nargs="?", help="with plan-ids: the plan file to read")
    ap.add_argument("--check", action="store_true", help="check every file in the register")
    ap.add_argument("--gate", metavar="RELEASE", help="exit 1 while findings stand in the way of RELEASE (1.0, 0.4.0, ...)")
    ap.add_argument("--plan", dest="plan_path", metavar="PATH", help="with --check: read the plan items from this file instead of docs/findings/plan-ids.txt")
    ap.add_argument("--status", action="append", help="list: only these statuses (repeatable)")
    ap.add_argument("--severity", action="append", help="list: only these severities (repeatable)")
    ap.add_argument("--kind", choices=["F", "U"], help="list, index: only findings (F) or unverified items (U)")
    ap.add_argument("--area", help="list: only this area")
    ap.add_argument("--today", help="with --gate: the date to judge expiries against (default: today)")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the repository root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    modes = sum(1 for x in (args.check, args.gate, args.command) if x)
    if modes != 1:
        ap.error("one of --check, --gate RELEASE, list, index or plan-ids")
    if args.check:
        return 0 if check(root, args.plan_path) else 1
    if args.gate:
        if not re.fullmatch(r"\d+(\.\d+){0,2}", args.gate):
            ap.error(f"{args.gate!r} is not a release like 1.0 or 0.4.0")
        today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
        return 0 if gate(root, args.gate, today) else 1
    if args.command == "plan-ids":
        if not args.plan:
            ap.error("plan-ids needs the plan file")
        with open(args.plan, encoding="utf-8") as f:
            for item in sorted(plan_ids_of(f.read())):
                print(item)
        return 0
    try:
        findings = load(root)
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    chosen = selected(findings, args)
    if args.command == "list":
        list_findings(chosen)
    else:
        index(chosen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
