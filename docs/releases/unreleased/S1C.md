# The RAR plugin holds every request, every PDP answer and every refresh to the containment model

## Changelog

- Plan item S1c: the RAR plugin shades and relocates `libs/rar-model` and asks it every containment question -
  a request before the PDP, the PDP's answer after it (narrow, never widen), a refresh against its grant - and
  compares the attestation context's `rar_models_fingerprint` with its own. `RarContainment` and its contract test
  are gone. Closes F-0031 and, with S1b, F-0001 (blocker B1); closes F-0106. New in the register: F-0105, F-0106,
  F-0107, U-0115 and U-0116.

## Before you deploy

1. **Deploy the plugin and the attestation filter from one release.** The filter publishes its model set's
   fingerprint in the attestation context from 0.4.0 (S1b), and the plugin refuses a request whose context lacks
   it or carries another: a 0.4.0 plugin beside a 0.3.0 `pf-integration` refuses every request from an attested
   client, before the PDP is asked, with `invalid_authorization_details`. A request with no attestation context -
   a client the filter did not verify, or the authorization endpoint's resume - is decided without the comparison.
2. **Give the whole PingFederate process one models document.** The plugin reads `OIDF_RAR_MODELS_FILE` or
   `OIDF_RAR_MODELS` itself, once, as the filter and the attester do; a plugin GUI field would let the two drift,
   which the fingerprint exists to catch. Unset, the model is the three built-in types. A document the library
   refuses leaves the plugin with no model: it logs a SEVERE line saying why and refuses every request until the
   document is fixed and PingFederate restarted. The start-up line `RAR models loaded: fingerprint=...` and each
   instance's `rarModels=` say which model set a node runs.
3. **A detail the model cannot read is refused before the PDP.** Every field is compared now, so a field the
   type's model does not declare, a type no model names (outside `OIDF_DEPLOYMENT_PROFILE=development`) and a
   value of the wrong shape - a flat `amount` without `currency`, a negative limit, an empty array, a blank
   string - answer `invalid_authorization_details`, and the PDP is not asked. idp-agentic-demo's payment fields
   pass; what else it sends is not visible from here (U-0057). A field of your own needs a models document with
   `extends`, and a type of your own needs a model and a name in `OIDF_RAR_EXTRA_TYPES`, which still decides what
   PingFederate may bind to the processor.
4. **A PDP's statements may narrow a request and never widen it.** After a PERMIT the plugin merges the statements
   into a copy of the request and refuses the result unless the model finds it within the request: a lower
   amount, a region fewer or a limit the request left open is granted; a higher amount, another currency, another
   payee, an added region, a changed type or a field the type does not declare is `invalid_authorization_details`.
   Every AuthZEN response `context` member other than `id`, `reason_admin` and `reason_user` is a statement, so a
   PDP that returns, say, a trace id in its context now denies. The policies under `plugins/rar-paz-plugin/paz`
   return no statements; check what yours return before you upgrade.
5. **A refresh that restates `authorization_details` must stay within its grant.** It is compared with the
   model's strict `contains`: more than the grant, another payee or another currency, or a constrained field left
   out, is `invalid_authorization_details` where 0.3.0 compared five array fields and issued the rest. A grant
   issued before 0.4.0 whose stored details the model cannot read - a statement's field no model declares, say -
   can no longer be refreshed with `authorization_details`. A refresh without the parameter is unchanged: the
   stored details are reissued and neither the plugin nor the PDP is asked (F-0105).
6. **Consent and grant reuse follow the stricter answer.** PingFederate 13.1.3 also asks `isEqualOrSubset`
   whether approved consent covers a request, which stored grant a request may reuse, and which consent records a
   changed consent deletes (read with `javap`, not driven: U-0115). Expect a consent prompt where 0.3.0 reused a
   consent for a larger amount. With "bypass authorization for approved consents" on, a grant issued before 0.4.0
   whose details exceed its consent, or cannot be read by the model, is revoked at its next refresh
   (`invalid_scope`, "revoked, or expired consent"), bare refreshes included. Revoke or re-issue such grants on
   your own schedule before the upgrade if that matters.

## Notes

What changed. The plugin depends on `rar-model` and shades it into its jar as
`com.pingidentity.ps.oidf.rar.shaded.rarmodel`, as it does Jackson; `ShadedJarCheck` fails the build when the
library's own package is in the jar or named by a class, and when the relocated copy's fingerprint differs from
the library's. `ModelGate` is the plugin's one door to the model: it loads the model set once per classloader,
strips `_principal_sub` and `_agent_id` (after the principal resolver has read them), checks a requested detail,
answers `within` with the model's `contains`, and compares the context's fingerprint. `enrich` checks the detail
before the PDP (so the fail-open path grants only a checked detail), builds the grant on a deep copy - with the
shallow copy it used to take, a statement naming a nested member such as `instructedAmount.amount` rewrote the
request as well, and the grant would have been compared with itself - and refuses a grant the model does not find
within the request. `isEqualOrSubset` is the model's `contains` with the grant as the ceiling. The mirrored
`req_*`/`att_*` field list moved into `GovernanceEngineRequestBuilder`, unchanged; it is the PDP's vocabulary,
not the containment rule. The coverage gate names every method explicitly, with nested classes dotted as jacoco
names them: the two `$`-spelt includes from PR #29 matched nothing (F-0106).

Verification, 2026-09-27. The plugin's 309 tests and the shaded-jar check pass on JDK 20.0.2 and 17.0.11 with the
gate at 100% line and branch on every new decision method. `RefreshVectorsTest` sends the library's 148 `contains`
vectors through PingFederate's own parse and the refresh loop transcribed from `javap -c` of 13.1.3.0, to the
plugin's `isEqualOrSubset`: all agree with the library, reasons included, but six listed ones (the three marker
cases, which the plugin strips by design; the empty request, which PingFederate asks no processor about; and two
numbers its parse turns into `"Infinity"` and `0.0` before the plugin is asked), none of which issues more than
the grant. `tools/pf-linkcheck.py` against the 13.1.3 jars: nothing unresolved in the shaded jar. On the rig
(`PF_RIG_NAME=pfai-s1c`, PingFederate 13.1.3.0, 09:33Z) with a stub PDP answering PERMIT with a response context:
a narrowing context was granted (`max_txn_eur` 100; EMEA of EMEA and APAC), a widening one and one writing an
undeclared field answered 400 `invalid_authorization_details`, a request with an undeclared field answered 400
with no PDP call, and a CIBA grant for 42.00 AUD refused refreshes for 43.00 and for another payee and granted
41.00; nothing of the PDP's answer reached `server.log`. The plugin README's "Verified on the rig" has the table.

Residual risk. A bare refresh reissues stored details without the plugin or the PDP (F-0105, PingFederate's own
behaviour, which RFC 9396 section 7 permits). The fingerprint comparison was unit-tested but not driven on a
booted PingFederate, since the filter publishes the member only from S1b on (U-0116). What the strict answer does
to consent and grant reuse and to consent revocation is read from the bytecode, not driven (U-0115). The plugin
still does not compare a request with the attested ceiling itself: the filter does that at the token endpoint
(S1b), and the details a code, CIBA or device grant stored at authorize or PAR are not held to the ceiling until
S4d (F-0032). The plugin reads `OIDF_DEPLOYMENT_PROFILE` in any case and the model exactly (F-0107).
