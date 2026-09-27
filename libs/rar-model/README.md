# rar-model

The per-type containment model for RFC 9396 `authorization_details`: which fields each type may carry, how each
one is compared, and the three questions every enforcement point in this repository asks - is a candidate
within a ceiling, what is granted for it, and what is within two ceilings at once. Package
`com.pingidentity.ps.oidf.rar.model`. Depends on nothing: no JSON library, no jose, no servlet, no
PingFederate, so the RAR plugin can shade and relocate it and the servlets borrow nothing from PingFederate's
classpath for it. Plan item S1a of the production programme, closing the review's blocker B1
([F-0001](../../docs/findings/F-0001.yaml)): the two containment checks this repository had,
`RarEntitlement` in [libs/client-attestation](../client-attestation/README.md) and `RarContainment` in
[plugins/rar-paz-plugin](../../plugins/rar-paz-plugin/README.md), compared five array fields and let every
other value through. This library replaces both; the wiring is wave 2 (S1b the authenticator and the
issuer, S1c the plugin), and until it lands nothing in a running PingFederate reads this module.

## What's here

- **`RarModels`** - the model set: the three built-in types, whatever a models document adds, and the operations.
  `builtIn()`, `load(document)`, `fromEnvironment()`; `contains`, `authorize`, `intersect`, `fullCeiling`,
  `validate`; `fingerprint()` and `canonicalJson()`; `parseDetails` and `details` for the list-of-objects shape.
  Immutable, safe to share.
- **`TypeModel`** - one type's fields in declaration order, each with its **`FieldRule`** (a `Rule` and its
  options: the `unit_field` a limit is paired with, the nested `TypeModel` an object compares by), and the
  type's alternatives, if it has any (below).
- **`Rule`** - the nine ways a field is compared, below.
- **`Omission`** - what a constrained field the candidate leaves out means to `authorize`: `INHERIT` or `STRICT`.
- **`RarModelException`** - every refusal, with a `Reason` the caller maps to its own error: `MALFORMED`,
  `TOO_LARGE`, `UNDECLARED_FIELD`, `UNMODELLED_TYPE`, `EXCEEDS_CEILING`, `MODEL_INVALID`. The message names the
  detail and the field, never the value, and any name it repeats is quoted with control characters escaped and
  cut at 64 characters.
- **`Limits`** - the size limits, applied to every list before anything reads it.
- **`Json`** - a strict RFC 8259 reader (duplicate member names refused, ASCII hex in Unicode escapes, no half
  surrogate pairs, nesting and number literals capped) and a canonical writer (members by name, no whitespace,
  plain decimals, no number past the digit limit), so the module needs no JSON library and the fingerprint and
  structural equality have one definition.
- The test-jar carries `rar-model-vectors.json` and `Vectors`, the runner the wave-2 modules reuse (below).

## The rules

A type's model names its fields and gives each one a rule. Every value is checked against its rule whether or
not the ceiling constrains the field; a value the rule cannot compare is refused, never skipped.

| Rule | The value | Contained when | The meet |
|---|---|---|---|
| `set` | A non-empty array of strings | The candidate's values are all among the ceiling's (duplicates count once) | The common values, sorted; none when disjoint |
| `set_of_values` | A non-empty array of values `equal` would take (an account object, say) | As `set`, by structural equality (member order and number spelling do not matter) | As `set` |
| `limit` | A non-negative number, or a string that is a plain decimal (`"123.50"`; no sign, no exponent, no spaces), of at most 64 digits | The candidate's is at most the ceiling's, compared as decimals | The smaller |
| `limit` with `unit_field` | As `limit`, and whenever the field is present its unit field must be present beside it | As `limit`; the unit field has its own `equal` or `string` rule, so an unequal unit is not contained | The smaller, when the units meet |
| `amount` | The RFC 9396 `instructedAmount` object: exactly `amount` (as `limit`) and `currency` (a non-empty string) | Equal `currency` and an `amount` at most the ceiling's | The smaller amount; none across currencies |
| `instant_limit` | RFC 3339 §5.6: a date-time with seconds and an offset (`2026-12-31T23:59:59Z`, `+01:00`; `t` and `z` in either case; at most nine fraction digits), or a full date, which means the end of that day in UTC. Four-digit years only; a date or time that does not exist, a leap second and an offset past 18 hours are malformed | The candidate's instant is no later than the ceiling's | The earlier |
| `equal` | Any JSON value but `null`, `[]` and `{}` (and nothing `null` inside it) | Structurally equal | The value, when equal; none otherwise |
| `string` | A string with something in it besides whitespace | Exactly the ceiling's string | The string, when equal; none otherwise |
| `object` | A JSON object with field rules of its own, applied recursively | Every field the ceiling's object carries, the candidate's carries too, within it | Field by field; none when any field has none |
| `forbidden` | Must not appear at all | Never present | Never present |

A negative `limit` or `amount` is malformed rather than small: it is within every ceiling, and it asks for a
payment the other way.

The list-level rules, from CAS §7 rule 1 and RFC 9396 §6.1:

- **A field the ceiling omits is unconstrained.** The candidate may carry any well-formed value for it.
- **A field the ceiling carries and the candidate omits is not contained.** Silence is not a narrower request
  under `contains`; under `authorize(INHERIT)` it takes the ceiling's value (next section).
- **`null`, `[]`, `{}` (under `equal`), a blank `string` and a wrong JSON type are malformed.** Refused, on
  either side, never read as "no constraint" or "nothing requested".
- **Undeclared fields are refused.** A field the type's model does not declare is never compared, so it is
  never granted: `UNDECLARED_FIELD`. RFC 9396 §2.1 makes the type the owner of its fields; §6.1 leaves the
  comparison to the type's definition.
- **One thing, one spelling.** Where a type can say the same thing two ways, the ways are *alternatives*: a
  group of spellings, each a set of fields. A detail that uses two spellings of one group is `MALFORMED`. A
  ceiling entry that uses a spelling holds the candidate to it, so the same thing said the other way is not
  contained, and `INHERIT` never fills a spelling the candidate is not using. Without this the ceiling
  constrains one spelling and leaves the other open, because a field the ceiling omits is unconstrained - B1
  again, one level down. `payment_initiation`'s amount is the built-in case (next section but one).
- **A candidate must fit one same-type ceiling entry.** Never a union of several. The first entry that contains
  it is the one used.
- **A type no model names is refused** (`UNMODELLED_TYPE`), unless the deployment profile is `development`, when
  the common-fields model stands in (Configuration, below).
- **Both lists are validated on every call**, an empty candidate included: a malformed ceiling is a
  configuration or attester fault and is reported as such, not served past.

## The operations

- **`contains(ceiling, candidate)`** - true when every candidate detail is within some same-type ceiling entry,
  strictly. An empty candidate is within anything; nothing is within an empty ceiling. A question that cannot
  be answered (a malformed list, an unmodelled type) is refused with its reason, never answered "no". The refresh
  path's `isEqualOrSubset` is this, once S1c wires it.
- **`authorize(candidate, ceiling, mode)`** - the details granted for a candidate, in the candidate's order, or
  `EXCEEDS_CEILING` (CAS §7 rule 3, `reject`). Under `Omission.INHERIT` each granted detail carries the
  ceiling's value for every constrained field the candidate omitted, nested objects included - the reading the
  token endpoint has used since `RarEntitlement` (silence is a request for the whole of what the ceiling allows
  there) extended from the five array fields to every rule. A limit sent without its unit (`"amount": "42.00"`
  with no `currency`) takes the unit from the entry; an entry that has no unit to give is passed over, and when
  no same-type entry has one the request is `MALFORMED`. Under `Omission.STRICT` the granted detail is the
  candidate as sent and a constrained field it omits is a refusal. In both modes the result is checked against
  the ceiling before it is returned; a grant outside it is a defect in this library and stops the request with
  an `IllegalStateException` rather than serving it. The mode is required. An empty candidate grants nothing;
  the CAS's reading of an empty request (§7 rule 2, the full ceiling) is `fullCeiling`.
- **`fullCeiling(ceiling)`** - the ceiling itself, validated and copied.
- **`intersect(a, b)`** - the meet: for every pair of same-type entries, one from each list, the largest detail
  within both, when one exists. Deduplicated and sorted by canonical JSON, so it is the same list whichever way
  round the arguments come. It is within each argument, it is the greatest such thing (anything within both is
  within it), and it is monotone in each argument; `RarModelPropertyTest` checks all of that over random details.
  Sixteen entries each side can meet in 256 ways, so a meet of more than 16 entries is `TOO_LARGE` rather than
  a list no operation could take. This is CAS §7 rule 3's `narrow`, the asserted-context narrowing the issuer
  does today by hand, and what plan items X-B09 and X-B10 need.
- **`validate(details, side)`** - the limits and every detail's shape, for a caller that wants the check alone.

What `authorize`, `intersect` and `fullCeiling` return is new: nothing in it aliases a ceiling or a candidate the
caller still holds. `validate` and `details` return the caller's own maps, checked.

## The built-in models

Every built-in type starts from the RFC 9396 §2.2 common data fields and the bookkeeping names seen in this
repository's traffic:

| Field | Rule | Where it comes from |
|---|---|---|
| `actions`, `locations`, `datatypes`, `privileges` | `set` | RFC 9396 §2.2: "An array of strings" |
| `identifier` | `string` | RFC 9396 §2.2: "A string identifier indicating a specific resource" |
| `purpose` | `string` | Sent by clients in this repository's demos; the RAR plugin's consent text drops it as bookkeeping |
| `_principal_sub`, `_agent_id` | `forbidden` | Names this repository's own components write into a detail after the authority question is settled: the plugin's development-only client-asserted principal, and the marker the token filter carries from PAR. A caller strips its own bookkeeping before it asks the model and puts it back after; a request that arrives carrying them is refused with a message that says so |

Then, per type:

| Type | Field | Rule | Where it comes from |
|---|---|---|---|
| `sales_agent` | `sales_regions` | `set` | The CAS specification's running example and this repository's demos |
| `sales_agent` | `max_txn_eur` | `limit` | CAS Appendix A (`"max_txn_eur": 5000`); the unit is in the name |
| `payment_initiation` | `instructedAmount` | `amount` | RFC 9396 Figure 2 |
| `payment_initiation` | `creditorName`, `remittanceInformationUnstructured` | `string` | RFC 9396 Figure 2 |
| `payment_initiation` | `creditorAccount`, `debtorAccount` | `equal` | RFC 9396 Figure 2 (`debtorAccount` from the plugin's consent text); an object there, and whatever the plugin's consent text prints here |
| `payment_initiation` | `amount` | `limit`, unit field `currency` | The flat shape the RAR plugin's consent text reads and its tests send (`"amount": "42.00", "currency": "AUD"`) |
| `payment_initiation` | `currency` | `string` | As above |
| `account_information` | `accounts` | `set_of_values` | Plan S-1; account objects (`{"iban": ...}`) or identifiers |
| `account_information` | `validUntil` | `instant_limit` | Plan S-1 |
| `account_information` | `recurringIndicator` | `equal` | RFC 9396 §7.1, Figure 16 |

`payment_initiation` says its amount two ways, so the two are alternatives: `instructedAmount`, or the flat
`amount` and `currency`. A detail carries one or the other. A ceiling that says `instructedAmount` does not
contain a flat `amount` of any size, a ceiling that says the flat pair - or `currency` alone - does not contain
an `instructedAmount`, and a ceiling that says neither leaves both open.

`account_information` has no `access` object. RFC 9396 §7.1 shows one (Figures 16 and 17) and calls it
"illustrative only", and it does not fit this model: Figure 16's request sends `[]` placeholders, which the plan's
rules refuse as malformed; the object reads a member it leaves out as "no access" where a ceiling here reads an
omitted field as unconstrained; and it names accounts a second way beside `accounts`. Figure 16 is refused by the
built-in model as `UNDECLARED_FIELD`. A deployment that uses the object swaps it in with a models document (next
section); a client then leaves the arrays out (`"access": {}`) where Figure 16 sends them empty, and `INHERIT`
fills them from the ceiling.

What idp-agentic-demo sends is not visible from this repository; [U-0057](../../docs/findings/U-0057.yaml)
records it. A field it sends that is not in the tables above is refused once S1b/S1c wire the model in, and
the fix is a models document that extends the type (next section), not a wider built-in.

## A models document

More types, and fields added to the built-in ones, come from one JSON document, read once at start-up from
`OIDF_RAR_MODELS_FILE` or inline from `OIDF_RAR_MODELS`. One source for every classloader: the plugin GUI has
no field for it, because a model the plugin had and the authenticator did not is the mismatch the fingerprint
exists to catch.

```json
{
  "types": {
    "https://scheme.example.org/files": {
      "fields": {
        "locations": "set",
        "permissions": "set_of_values",
        "max_files": "limit",
        "budget": { "rule": "limit", "unit_field": "budget_currency" },
        "budget_currency": "string",
        "instructedAmount": "amount",
        "validUntil": "instant_limit",
        "owner": "equal",
        "access": { "rule": "object", "fields": { "paths": "set", "mode": "string" } },
        "secret": "forbidden"
      }
    },
    "payment_initiation": {
      "extends": "payment_initiation",
      "fields": { "remittanceInformationStructured": "string" }
    }
  }
}
```

- The document is one object with one key, `types`; each type is an object with `fields` and, optionally,
  `extends`.
- A field is a rule name, or an object with `rule` and that rule's options: `unit_field` for `limit` (it must
  name a field of the same object whose rule is `equal` or `string`), `fields` for `object` (at least one). A
  rule with no options takes none.
- `extends` names a built-in type or one declared earlier in the document. The extension inherits the base's
  fields and alternatives, adds its own fields, and may redefine an inherited field only as `forbidden`: a
  redefinition that changed how an inherited field is compared would relax a rule somebody relies on.
- An entry named like a built-in must extend that built-in, and nothing else. Redefining a built-in from scratch
  is refused, and so is a built-in name that extends another type, so a document cannot silently replace
  `payment_initiation` with a model that has no `instructedAmount`.
- A document cannot declare alternatives of its own. A limit it adds must sit in the same spelling as its unit,
  so an extension of `payment_initiation` cannot pair a new limit with `currency`. To say a built-in's thing a new
  way, an extension forbids the old spelling in the same entry. RFC 9396 §7.1's `access` object, for example:

  ```json
  { "types": { "account_information": { "extends": "account_information", "fields": {
      "accounts": "forbidden",
      "access": { "rule": "object", "fields": {
          "accounts": "set_of_values", "balances": "set_of_values", "transactions": "set_of_values" } } } } } }
  ```

  A ceiling in this shape constrains only the members its `access` names; one that means "balances only" has
  no way to say it, because `[]` is malformed, so name all three.
- `type` is implicit and cannot be a field. Objects can nest to depth 7, one short of the value depth limit.
- Anything the schema does not name - an unknown key at any level, an unknown rule, an option on the wrong rule,
  a document that is not valid JSON, a name holding half a surrogate pair - is `MODEL_INVALID`. The component
  that loads the model should refuse to start on it rather than serve with a model it could not read.

## Configuration

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_RAR_MODELS_FILE` | unset | The path of a models document, read once, UTF-8 | A missing or unreadable file, or a document the schema refuses: `MODEL_INVALID` at load, and the component should not start. Set together with `OIDF_RAR_MODELS`: refused, the same way |
| `OIDF_RAR_MODELS` | unset | The models document inline. Blank counts as unset | As above |
| `OIDF_DEPLOYMENT_PROFILE` | unset, which means production | Exactly `development` (whitespace trimmed) lets a type no model names fall back to the common-fields model: the RFC 9396 §2.2 fields, `purpose`, the two forbidden names, and nothing else, so a custom field on a custom type is refused even in development until the type has a model | Any other value is production: an unmodelled type is `UNMODELLED_TYPE`. Read directly here until plan item PR-1 centralises the profile |

Nothing else is read from the environment. `RarModels.fromEnvironment(Map)` takes the environment as a map for
tests and for a caller that reads it elsewhere. `RarModels.load(document)` has production semantics: only the
environment's profile turns the fallback on.

## The fingerprint

`fingerprint()` is SHA-256, lower-case hex, over `canonicalJson()`: the fallback flag, `semantics`, and every
type's fields by name, with each rule described the way a models document writes it (`"set"`,
`{"rule":"limit","unit_field":"currency"}`, `{"rule":"object","fields":{...}}`), and the type's alternatives when
it has any; members sorted, no whitespace. Two components with the same effective model - the same built-ins,
the same document, the same profile, the same library semantics - have the same fingerprint whatever order the
document declared its fields in; a component with a different document, or one classloader in development and
another not, does not.

`semantics` is `RarModels.SEMANTICS`, 1 in this release. It is raised with any change to what a rule accepts
or contains, so that a plugin that shaded one build of this library and an authenticator on another, which would
answer differently over the same document, do not share a fingerprint. The reader refuses a name holding half a
surrogate pair, which UTF-8 cannot carry, so two documents cannot hash alike and compare apart.

S1b puts the fingerprint in health and in the attestation context and S1c makes the plugin deny on a mismatch,
which is what keeps the classloaders in step. The built-ins' fingerprint is pinned in the vector file, so a
change to a built-in model, or to `SEMANTICS`, is a deliberate change to that line.

## Size limits

Every list, ceiling or candidate, from any parser, is held to these before anything reads its types:

| Limit | Value | Refused as |
|---|---|---|
| Entries in an `authorization_details` array | 16 | `TOO_LARGE` |
| Depth of a container (the detail object is depth 1) | 8 | `TOO_LARGE` |
| Members of an array or object | 256 | `TOO_LARGE` |
| Characters in a string or a member name | 2048 | `TOO_LARGE` |
| Digits in a number written out as a plain decimal (`5E+3` is four, `0.05` three) | 64 | `TOO_LARGE` |

The first four are the plan's. The digit limit is this library's: a string costs its length, but `1e999999999`
is eleven characters and a billion digits once anything writes it out or strips its zeros, so a number is
measured from its scale and size without being written, and the writer refuses one past the limit too. A
decimal sent as a string under `limit` or `amount` is held to the same 64 digits. A list entry that is not an
object, a member name that is not a string, a `double` with no finite value, a `Number` of a class no JSON
parser produces, or a Java object of some other class is `MALFORMED`.

`parseDetails` reads at most 262,144 characters of text, and its reader caps nesting at 32 and a number literal
at 128 characters, all refused as `TOO_LARGE` before the recursion or the decimal arithmetic costs anything (the
work on a long literal grows faster than its length: the review measured 8.4 s for a 100 KB one, 2026-09-27).
With every value's cost bounded, the model's work is linear in the size of the lists it is given; a caller that
parses the text itself bounds that size there.

## The vectors

`src/test/resources/rar-model-vectors.json` names a case for every rule, every malformed shape, the
alternatives, the size limits and the models document - 238 on 2026-09-27 - each with an `op`, its lists (or,
for `parse`, JSON text), an optional `models` and an `expect`. `RarModelVectorsTest` runs each as its own test
through `Vectors.run`, the library's reading of a case; the wave-2 runners (the authenticator's token gate,
the issuer's mint, the plugin's refresh check) read the same file through `Vectors.load()` from this module's
test-jar and compare their surface's answer with the case's `expect` by `Vectors.canonical`, so a semantics
change fails in every module that enforces containment and not only in the one whose tests were updated.
Expectations compare canonical JSON: member order and number spelling do not matter. A `parse` case says what
only text can - a number literal too long to read, a duplicate member name, half a surrogate pair - and a runner
whose surface takes text sends it as it is. `RarModelPropertyTest` is the algebra over random details, seeded,
so a failure names the iteration and the inputs that can then become a vector; its payment details come in
either spelling or neither, so random pairs cross spellings often.

## What changes for consumers once S1b and S1c wire it in

Nothing in this release's module set reads this library yet; these are the changes the wiring brings, written
here now so that the upgrade note is ready when it lands
([docs/releases/0.4.0.md](../../docs/releases/0.4.0.md), "Before you deploy").

- Every field of a request is compared. A request that relied on a scalar going unexamined - an amount above
  the ceiling's, a different creditor account, a later `validUntil` - is refused, and the authorization server
  answers `invalid_authorization_details` (CAS §7.1), where 0.3.0 granted it.
- A field the type's model does not declare is refused. idp-agentic-demo's payment fields in the built-in table
  pass; anything else needs a models document with `extends`.
- Values are typed. `identifier`, `purpose`, `creditorName`, `remittanceInformationUnstructured` and the flat
  `currency` must be non-blank strings; `limit` and `amount` values must be non-negative, with at most 64
  digits; `validUntil` must be RFC 3339 with seconds, or a full date.
- A `payment_initiation` detail says its amount one way, `instructedAmount` or the flat `amount` and
  `currency`, and a request must use the spelling of the ceiling that constrains it.
- `account_information` has no `access` object, so RFC 9396 §7.1-shaped requests are refused until a models
  document swaps it in for `accounts`.
- A ceiling that constrains a field the request omits fills that field in the grant - for every rule, not only
  the five array fields - so tokens carry, say, `max_txn_eur` and `currency` explicitly.
- The two copies of the check (`RarEntitlement`, `RarContainment`) go, with `RarContainmentContractTest`; the
  instance-ceiling check in `AttestationIssuanceConfig` becomes `authorize(instance, client)` and keeps its
  result, closing item 5 of the plan's "Found while designing".
- The RAR plugin needs the same models document as the authenticator (`OIDF_RAR_MODELS_FILE` in one place for the
  whole PingFederate process) and denies when the fingerprints differ; the fingerprint appears in health and in
  the attestation context.
- `OIDF_RAR_EXTRA_TYPES` no longer makes a type acceptable on its own: a type needs a model, or the development
  profile.

## Security posture

The model never widens: `authorize` fills a silent field from the ceiling and never from the candidate, and
never in a spelling the candidate is not using; `intersect` returns only what is within both arguments; and
every grant is checked against the ceiling before it leaves. A value the rule cannot compare is refused rather
than passed through, because "unexamined" is the whole of blocker B1, and a thing a type can say two ways is
held to one spelling for the same reason. Messages name the detail, the field and what was wrong with it and
never repeat the value - a detail can carry an account number - and the names they do repeat are quoted,
escaped and cut, so a request cannot write a line of its own into a log. Every value's cost is bounded before a
type is looked up (the size limits above), every refusal is a `RarModelException` with its reason, and the
model's work is linear in the size of its input.

## Build

```sh
mvn -pl libs/rar-model -am verify     # or `mvn verify` at the repo root; tests and both coverage gates run with the build
```

The jacoco gate is per METHOD at 100% line and branch on the decision methods and the reader (the pom lists
them, 51 on 2026-09-27), and a floor of 95% of instructions and 92% of branches under the whole module.
