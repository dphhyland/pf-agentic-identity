# Conformance

How we know the federation support does what OpenID Federation 1.0 says: the OpenID Foundation's own test
suite, run against a PingFederate built from this repo, and our own tests, each tagged with the clause it
pins. This page says how to run both and what they found.

## The OpenID Foundation suite

The [conformance suite](https://gitlab.com/openid/conformance-suite) has three OpenID Federation plans. They
are alpha. Two apply to PingFederate; the third tests relying parties, which PingFederate isn't.

Against PingFederate 13.1.3 built by [`conformance/up.sh`](../../conformance/README.md), with a suite we run
ourselves at release-v5.3.1:

| Plan | How PingFederate is set up | Result |
|---|---|---|
| `openid-federation-deployed-entity-test-plan` | `PF_PROFILE=federation`: PingFederate is its own trust anchor | 5 modules, 5 WARNING, 0 FAILED (2026-09-25) |
| `openid-federation-entity-joined-to-test-federation-op-test-plan` | `PF_PROFILE=federation-op`: PingFederate joins the suite's own federation, whose anchor it pins | 20 modules, 20 WARNING, 0 FAILED (2026-09-25) |

The deployed-entity plan checks PingFederate's Entity Configuration, its fetch endpoint (including the errors
for a subject it doesn't know and for itself), that the anchor keys it was given match, and that a chain it
builds by hand agrees with what PingFederate's resolve endpoint returns.

The OP plan is the demanding one. The suite hosts a trust anchor and a relying party beneath it, and the relying
party registers at PingFederate's authorization endpoint by GET and by POST and at PAR, each with and without a
trust chain in the request, and once with an encrypted request object. Then it sends thirteen bad requests: a
`client_id` that doesn't match, a request object with a bad signature or one made with other keys, a wrong
`exp`, `iss` or `aud`, one carrying `sub`, one missing `jti`, `exp`, `iss` or `aud`, and one reusing a `jti`.
Each of the thirteen is refused with an error page, which the suite accepts as a picture: §12.1.3 says the
redirect URI of a client you can't trust isn't one to send anyone to, so there is no redirect to follow.

**The warning on every module** is about PingFederate, not the federation: the Entity Configuration's
`oauth_authorization_server` block carries PingFederate's own discovery document, which has parameters the
suite doesn't know - PingFederate's `ping_*` endpoints, its identity-chaining parameters, and the attestation
draft's `client_attestation_pop_methods_supported`.

**What the suite found.** Its first runs failed, and each failure was a real defect, fixed:

- all five deployed-entity modules failed because the Entity Configuration described PingFederate as an OP
  without the parameters OpenID Connect Discovery requires. It now starts from PingFederate's own discovery
  document.
- an RP already registered went unchecked on later requests: PingFederate had quietly dropped the extended
  properties that mark a federation client. Registration now reads the client back and refuses if they didn't
  survive, and the rig declares them.
- an RP's later requests weren't held to §12.1.1.1; now every request is.
- a token request renewed an RP registered at the authorization endpoint in an agent's shape. It no longer does.

To run them yourself, see [`conformance/README.md`](../../conformance/README.md) ("Testing it"). The
deployed-entity plan also runs weekly in CI (`.github/workflows/conformance-federation.yml`) against a
PingFederate built from the clone. A run against a suite you host is evidence, not a certification: that is made
on the Foundation's hosted suite, by a person.

## Our own tests

Every test that pins a clause of the specification says which, with `@Requirement("OIDFED §8.1.1(2.2)")`: the
section, and the paragraph or list item from the published text's anchors (`#section-8.1.1-2.2`). A test that
pins a place where we deliberately depart from the text is tagged with the departure, never the clause.

The [coverage dashboard](../coverage-dashboard.md) joins the tags to the [conformance matrix](conformance-matrix.md),
one row per requirement implemented, and shows any row nothing pins. On 2026-09-25: 349 OpenID Federation
requirements pinned by 655 tests, and 209 of the 216 matrix rows across the repo pinned.

Three more measures:

- **The methods that decide something are held at 100%**, line and branch: 217 in the federation library and 175
  in PingFederate's side, each named in its module's pom. A change that leaves one of them short fails the build,
  and each new decision method joins the list with the change that adds it.
- **Each module has a floor**: the build fails if the federation library falls below 95% of instructions and 92%
  of branches covered, or PingFederate's side below 85% and 80%.
- **Mutation testing** changes the decision code one small way at a time - a condition turned round, a boundary
  moved - and checks a test notices. 95% of the changes to the library's decisions are caught (924 of 969), and
  93% of PingFederate's side (712 of 767). It runs weekly in CI and by hand (`mvn -Pmutation verify` on either
  module), and fails below 85%.

To run them: `mvn verify` from the repository root, then `python3 tools/coverage-report.py` to regenerate the
dashboard. [`docs/federation/conformance-matrix.md`](conformance-matrix.md) says how the ids are written.
