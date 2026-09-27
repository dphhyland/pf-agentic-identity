# Style guide

The house style, written down from what the repository already does: the module READMEs, the release notes,
the upgrade guide, the workflow comments and the commit log, read on 2026-09-27. It exists so that a document
written by someone new - or by an assistant - reads like the rest, and so that the part a machine can check is
checked: `python3 tools/doc-lint.py` runs in CI against every tracked Markdown file, ratcheted by
[doc-lint-baseline.txt](doc-lint-baseline.txt).

## Prose

**Plain short sentences.** One idea per sentence. Say what a thing is and what it does; cut "serves as",
"in order to", "so as to", "this document will describe". A list is better than a paragraph that is a list.

**A spaced hyphen, never an em dash.** Clauses are joined and bracketed with ` - ` (space, hyphen, space).
The em dash (U+2014) and the en dash used as one (U+2013 between spaces or letters) are refused by the lint. An
en dash between two numbers is a range and is fine, but a plain hyphen there is fine too and is what most of the
repository writes.

**British spelling.** Artefact, behaviour, catalogue, organisation, recognise, initialise, licence (the noun),
authorise. Two exceptions, both because a name is a name:

- A specification's own words stay as the specification spells them. OAuth's is "authorization server", the
  parameter is `authorization_details`, the header is `Authorization`, the plugin is an
  `AuthorizationDetailProcessor`. Write the concept in British ("the client is authorised") and the
  identifier as it is.
- Code, file names, settings, claims, class names and command output are quoted as they are, in backticks.

The lint carries a short, explicit list of American spellings whose British form the repository uses; it does
not try to know English. Text inside double quotes, code spans, fenced blocks, URLs and link targets is left
alone.

**Specification identifiers verbatim.** `client_id`, `authorization_details`, `cnf.jkt`, `Rfc7523bisCompliantAudienceVerification`,
`OIDF_FEDERATION_TRUST_ANCHOR_JWKS`: in backticks, spelled exactly, never paraphrased ("the trust anchor keys
setting") when the name will do. Sections are cited as the document numbers them: RFC 9396 §6.1, CAS §7.1,
OpenID Federation 1.0 §12.3, FAPI 2.0 Security Profile 5.3.2.1(2.8) - and in a `@Requirement` tag, as
[the annotation's javadoc](../../libs/conformance/src/main/java/com/pingidentity/ps/oidf/conformance/Requirement.java)
spells the prefix, because the coverage report joins on the exact string.

**Dated evidence.** A claim about what was observed says when and where: "verified 2026-09-26 on the rig,
PingFederate 13.1.3.0", "run 36234516459 on eba9640", "characterised from javap of pf-protocolengine 13.1.3.0
(2026-09-26, commit 621336e)". A number without a date is an assertion; with one it is a record someone can
re-check. Results that are old are kept as history and said to be old ("recorded 2026-09-23, before the
cut-over, not re-run on 13.1.3").

**"When it's wrong."** A setting is described with what happens when it is missing or malformed, not only
with what it does when it is right - see [Settings](#settings). The same for a procedure: say what the reader
sees when a step fails ("a filter fails the merged war with a 503; an annotated servlet is never mapped").

**Normative text quoted, with its section.** A statement that a specification requires something is made only
after reading the primary text, and quotes it: *"SHOULD use the mechanisms defined in this specification when
available"* (draft-ietf-oauth-spiffe-client-auth-02 §6.2). A summary of a specification can invent a MUST NOT;
this repository has been caught by that once. What could not be read is written as "not verified" and, if
anything rests on it, becomes a `U-` entry in the [findings register](../findings/README.md).

**No scaffolding.** No "let's dive in", "in conclusion", "I hope this helps", "delve"; no sentence that
announces the next sentence. The lint refuses those four; the rest is taste.

**Say who decided.** A choice that could have gone another way names the decision and the date: "pf-13.0 is
frozen at v0.1.5 (David, 2026-09-26)"; "broad attestation defaults are David's decision (2026-08-24)".

## Documents

Each module README opens with one paragraph on what the module is, what it depends on and what lives elsewhere,
then the sections a reader needs in the order they need them: what is here, endpoints, configuration, security
posture, build. Headings are sentence case. Links are relative and resolve (the lint checks); a link to another
tracked document is the document, not a copy of what it says.

A document that records evidence says what it rests on, at the end: "What this page rests on" in the upgrade
guide names the files and commands it was written from and the date. A document that describes another
repository says what it could not check there.

The showcase (`showcase/index.html`) renders every tracked Markdown file; anything written here is public and
is rendered as it stands.

## Settings

A settings row has four columns and every row fills all four:

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_SIGNING_ALG` (init-param `signingAlgorithm`) | `RS256` | How this entity signs its statements: `RS256` or `PS256`, with PingFederate's current RSA key | Anything else: PingFederate doesn't start |

"When it's wrong" uses the vocabulary [docs/federation/configuration.md](../federation/configuration.md)
defines: **PingFederate doesn't start** (the component fails at deploy and the log names the setting), **first
request** (a lazily started servlet fails on its first request, and only its paths), **per request** (nothing
at start-up; the requests that need it fail), and **not checked** when nothing checks it - which is a sentence
to write, not a cell to leave empty. A switch is `true` or `false`, in any case, and anything else is refused
unless the row says otherwise. From Phase 2 the rows are generated from the settings catalogue
([docs/configuration](../configuration/README.md)); the shape stays.

## Code comments

The repository's comments explain why, not what. The density rule, from the files that do it well
(`build.yml`, `release.yml`, `Requirement.java`, `set-version.py`):

- A comment records a decision, a constraint the reader cannot see, or the failure the code prevents - and
  where it can, the incident that taught it: "this guard's first version flagged pf-entrypoint.sh, which
  documents the variable in a comment, and failed two builds before anyone looked". A comment that restates the
  line below it is deleted.
- A file or class opens with one sentence saying what it is for; a public type's javadoc states its contract
  and, where the behaviour comes from a specification, the clause. A private method with an obvious name has
  no comment.
- A workflow step's `name:` is a sentence in the same register as the rest ("the tag must match the declared
  version"); the comment above it says why the step exists.
- A test is named as the sentence it proves, in the module's existing form (`aMarkUnderAGrantThatStandsIsActive`),
  and carries `@Requirement` with the clause it pins, spelled as the annotation's javadoc says. A test of a
  deliberate divergence is tagged with the divergence, never with the clause it departs from. A repository
  default is not a specification requirement.
- No comment claims a fact about PingFederate that was not checked against the jar or a booted instance; if it
  was inferred, it says so.

Match the file you are in: a dense file stays dense, a sparse one sparse.

## Commits

The subject is one plain-English sentence, sentence case, no full stop, that says what is true after the
commit - not what was done to get there:

```
A throwing OGNL criterion denies: verified on the rig, and written where the question was asked
Build can be run by hand on a branch, so a release dry run there has the green Build it requires
The upgrade guide counts v0.1.5's filters right, and the notes quote the plugin's switch labels as it declares them
```

The body, when there is one, says why, what was found, and what was verified with its date - in paragraphs,
not bullets. A commit that fixes a review's finding says which. Every commit ends with the line
`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` when an assistant wrote it. Run
`git branch --show-current` first; never commit on `main`.

## Pull requests

The body follows [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md): Summary, What
changed, Verification, Adversarial review, Merge order, Upgrade notes, Findings, Unverified. Verification is a
table of commands and results with dates and the commit they ran on, and links the CI run - a local build is
not CI. The adversarial review's verdict and every issue's resolution are written in, fixed or declined with a
reason. Findings name `Closes F-NNNN`. Unverified is never empty unless it is true. Merge commits only.

## A release-note fragment

One bullet under `Unreleased` in [CHANGELOG.md](../../CHANGELOG.md), one line, naming the plan item, in the
shape the released entries use:

```
- **Findings register** (D-2) - one YAML file per finding under docs/findings, seeded from the review and the
  plan; `tools/findings.py --check` in CI and `--gate` for a release.
```

Bold lead, the plan item in brackets, a spaced hyphen, what is true now. The heading above it stays
`[Unreleased] - <version>-SNAPSHOT` until the maintainer tags the release and gives it its date.

## An upgrade note

A numbered item under "Before you deploy" in `docs/releases/<version>.md`, for anything a consumer must change,
written when the change merges, not at release time:

```
6. **Check every stored RAR plugin instance's switches** (PR #7, `554e688`). Each switch is read with its
   secure default when the stored configuration lacks the field: "Deny unless PERMIT" and "Prefix Attributes
   with Type" now read as `true` ... An instance saved through the admin API or an archive that left a field
   out now refuses a PDP answer other than PERMIT.
```

Bold lead naming the action, the pull request or commit in brackets, then what changed, what the consumer sees
if they do nothing, and what to do. The operator guide under [docs/operator/upgrading](../operator/README.md)
repeats each item with the version it arrived in.

## Verify, don't reason

A claim that code is safe, unused, equivalent or unreachable is made by reading it: the callers, the
configuration that selects it, and `git log` for how it got that way - not by generalising from one function
to the module. This repository once recorded five wrong security claims in one session, every one reasoned from
a single function. Trace first; then write. What could not be traced goes under "Unverified" in the pull
request and, if a design rests on it, into the register as a `U-` entry with what would verify it. "Should be
fine" is not a sentence this repository writes.

## What the lint checks

`tools/doc-lint.py`: em dashes, en dashes used as dashes, the spelling list, the four scaffolding phrases,
and relative links that do not resolve, in every tracked `.md` outside `.claude/` directories. Hits a document
already carried when the check arrived are in the baseline, per file and rule, as counts: a document may not
gain one, and fixing some lets `--update-baseline` lower its count. A page a generator writes
(`docs/coverage-dashboard.md`, while it is tracked) is the generator's business: the lint skips it, and its
wording is fixed in `tools/coverage-report.py`. Everything else above is a reader's job.
