# The findings register

Every known defect, gap and risk in this repository, and every assumption nobody has verified yet, one file
each. `F-NNNN.yaml` is a finding; `U-NNNN.yaml` is an unverified assumption. The register is the record the
production programme works from: a pull request that fixes something names the finding it closes, and 1.0.0
ships only when `python3 tools/findings.py --gate 1.0` passes.

One file per finding so that pull requests landing in parallel do not fight over one table. There is no index
in git: `python3 tools/findings.py index` prints one when you want to read it, and `list` filters. Never commit
the output.

```sh
python3 tools/findings.py --check                     # every file well formed; CI runs this
python3 tools/findings.py list --status open --severity blocker
python3 tools/findings.py list --kind U --area ssf
python3 tools/findings.py index                       # a Markdown table, to read or paste
python3 tools/findings.py --gate 0.4.0                # what stands in the way of that release
python3 tools/findings.py --gate 1.0                  # the 1.0 rule
```

## A finding (`F-NNNN.yaml`)

```yaml
id: F-0016
title: The RAR plugin's fail-open catches everything
severity: high                     # blocker | high | medium | low
area: rar-paz-plugin               # a module or workstream, lower case; several separated by ", "
source: review-2026-09-26          # review-2026-09-26 | design | reviewer-report | phase-0-review | pr-review
status: open                       # open | mitigated | closed | accepted
plan_items: [S2a]                  # the plan's package or design ids that close it
prs: []                            # pull request numbers, as they land
verification: ''                   # what was checked, where and when; required once mitigated, closed or accepted
target_release: 0.4.0              # the release expected to close it
notes: >
  Why it matters and what the fix is, in a paragraph or two.
```

The fields:

- **severity** is the exposure as found, and does not change when a mitigation lands - the status does.
  *blocker*: a control that can be bypassed, or something that stops a production deployment outright.
  *high*: a security defect with a real path to it, or an operational failure that takes the service down.
  *medium*: hardening, a setting that does not do what its row says, correctness at the edges. *low*:
  conformance, diagnostics, tidiness. The register's rule for the reviewer reports' long tail (Workstream H
  of the plan) is medium unless the plan says otherwise, so a medium there is the rule, not a judgement.
- **status**. *open*: nothing has landed. *mitigated*: a stopgap reduces the exposure and the full fix is still
  to come (the plan item says which). *closed*: fixed, with dated verification. *accepted*: a risk taken in
  writing, with an `expiry` (`YYYY-MM-DD`) after which it must be looked at again; an accepted finding
  without a future expiry fails the gate, and a blocker or high is never accepted for 1.0.0.
- **source**: `review-2026-09-26` is the production-readiness review of origin/main f95b522; `design` is the
  plan's "Found while designing" list and its "To verify before relying on it" list; `reviewer-report` is the
  seven per-module reviewer reports the plan's Workstream H lists; `phase-0-review` is the adversarial reviews
  of the Phase 0 pull requests and the 0.3.0 notes' known gaps; `pr-review` is the adversarial review of a
  later pull request, which the notes name with its date.
- **plan_items** must be ids the plan names - packages (`S1a`, `X-A15`), designs (`S-1`), hardening items
  (`H-FED-3`), phase items (`P0-4`) or mitigations (`M-2`). The plan lives outside the repository, so
  [plan-ids.txt](plan-ids.txt) carries the ids it named when it was last read (with the date in its header);
  `--check` reads that file, or a plan given with `--plan`, and refuses anything else. Refresh the file with
  `python3 tools/findings.py plan-ids <plan.md>` when the plan changes. The plan spells some packages two ways
  (`S4d` and `S-4d`); use the workstream's own spelling, `S4d`.
- **verification** is free text and must carry a date: what was run or read, where (the rig, javap on which
  jar, which commit), and when. It is what a later reader re-checks.
- **target_release** is the release expected to close the finding; `--gate <release>` lists every open finding
  targeted at that release or earlier.

## An unverified assumption (`U-NNNN.yaml`)

```yaml
id: U-0016
title: getUserKey() per flow on a booted 13.1.3
area: rar-paz-plugin
source: design
status: open                       # open | closed | accepted
plan_items: [S2b]                  # the package that will do the verifying
prs: []
recorded_in: the plan, To verify before relying on it, booted PingFederate item 1
verify_by: >
  What would settle it: the command, the rig profile, the document section to read.
verification: ''
notes: ''
```

`recorded_in` says where the assumption is written down in full (`docs/unverified.md item 14`, a plan section,
a pull request's Unverified list); `verify_by` says what would verify it. *closed* means verified, or that
nothing relies on the answer any more - the verification text says which. The 1.0 gate treats an open `U-` as
a finding in the way: 1.0.0 does not ship on an assumption.

`docs/unverified.md` keeps the long form of the assumptions it recorded before the register existed, and each of
its items names its `U-` id; `U-0004` was numbered there first and keeps its number.

## Writing one

- Take the next number of its kind: `ls docs/findings | tail`. Never reuse or renumber.
- Say what the defect lets an attacker or an operator do, not only where it is. Cite code by class and, where
  a line matters, by line with the commit the line was read at (`RequestObject.java:122-124 at f95b522`).
- One finding per defect. A class of defects the review reported as one row is one umbrella finding
  (F-0025 to F-0029) until a pull request splits out the piece it fixes; a new file for that piece is fine.
- A pull request that closes a finding sets `status: closed`, adds its number to `prs`, writes the
  verification with the date, and says `Closes F-NNNN` in its body. A pull request that lands a stopgap sets
  `mitigated` and leaves the full fix's plan item in `plan_items`.
- A new defect found on the way gets its own file in the same pull request, `open`, so it is not lost in a
  review comment.

## The file format

Plain YAML, read by a small parser in `tools/findings.py` (the CI runner has no YAML library, and a register
this simple is better refused than guessed at): a top-level mapping of `key: value` lines, flow lists
(`[S1a, S1b]`), block lists (`- S1a` on the lines below, indented two spaces), block scalars (`|` literal,
`>` folded, indented two spaces), quoted strings (`'it''s'`, `"a \"b\""`) and `#` comments. Nothing nested
beyond that. A YAML library reads the same values from the same files, apart from the trailing newline it
keeps on a block scalar and the numbers it types (a pull request number is a string here); checked against
Ruby's psych over the whole register on 2026-09-27. The parser names the file and line of anything it will
not read.
