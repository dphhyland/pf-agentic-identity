# Unverified assumptions

Things this design depends on that could **not** be confirmed against an authoritative source, and
what was assumed instead. Every entry names what was tried, so the next person does not repeat it.

The rule that produced this file: anything from a published spec is verified by fetching the spec;
anything about the PingFederate SDK is verified by enumerating the SDK jar on disk. Where neither was
possible, it lands here rather than being quietly assumed.

Last reviewed: 2026-07-31, against PingFederate 13.0.3.

---

## 1. `LATouchIDAuthenticationMaximumAllowableReuseDuration` has no published value

**Assumed:** nothing. The code must read the constant at runtime.

Apple declares it as `let LATouchIDAuthenticationMaximumAllowableReuseDuration: TimeInterval` with
the abstract "The maximum allowable reuse duration" and **publishes no number**. Microsoft's .NET
binding docs — often a back-channel for header values — only restate the type. A web search summary
asserted 300 seconds; none of the underlying pages say it.

**Treat "5 minutes" as folklore.** Never hardcode 300. Read the constant.

- https://developer.apple.com/documentation/localauthentication/latouchidauthenticationmaximumallowablereuseduration

## 2. Whether the reuse window covers Face ID

**Assumed:** it does not, and the design does not rely on it either way (see item 3).

Apple's documentation for `LAContext.touchIDAuthenticationAllowableReuseDuration` is Touch ID-specific
throughout: *"If the user unlocks the device using Touch ID within the specified time interval, then
authentication for the receiver succeeds automatically."* There is no Apple statement extending this
to Face ID. Community forum posts claim it does; that is not documentation.

Note also that the documented trigger is **device unlock**, not a prior `evaluatePolicy` call in your
app — narrower than it is usually assumed to be.

- https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration

## 3. Whether a pre-authenticated `LAContext` ever expires

**Assumed:** it does not expire on its own. The app owns the window and must call `invalidate()`.

`kSecUseAuthenticationContext` documents the reuse behaviour — *"If this key is specified with a
context that has been previously authenticated, the operation will succeed without asking user for
authentication"* — but states **no expiry**.

This is load-bearing and it is why the plan treats the client-side time-box as **app-enforced, not
platform-enforced**. A compromised app could retain the context indefinitely. The real control is
server-side UV recency checked at token issuance; the client window is UX and blast-radius reduction.
If Apple later documents an expiry, the client-side claim gets stronger — the server-side control
does not change.

- https://developer.apple.com/documentation/security/ksecuseauthenticationcontext

## 4. The complete set of `PF-INF/*` plugin-type names

**Assumed:** the names this repo already uses successfully are correct; no complete list is relied on.

A `strings` scan of `pf-protocolengine-13.0.0.3.jar` recovered only five (`authentication-selectors`,
`connection-module-runtime-descriptor`, `custom-drivers`, `idp-authn-adapters`, `sp-authn-adapters`),
and a broader scan across ~200 jars in a 12.1.3 install added only a handful more. Yet
`plugins/rar-paz-plugin` demonstrably works via `PF-INF/authorization-detail-processors`, which
appears in neither scan.

**Conclusion: the PF-INF names are constructed dynamically and no scan of them is authoritative.**
The SDK *class* enumeration (item 5) is reliable; the PF-INF list is not.

## 5. No PingFederate 13.x javadoc or SDK developer's guide on this machine

**Assumed:** interface shapes read directly from the compiled jar are correct.

The only 13.0.3 SDK artifact present is
`~/.m2/repository/com/pingidentity/pingfederate/pingfederate-sdk/13.0.0.3/pingfederate-sdk-13.0.0.3.jar`
(396,035 bytes, 455 classes, no `PF-INF`, no resources). There is no `*-javadoc.jar` for any PF
artifact anywhere, and no PF 13.x install directory.

Full SDK trees — with `doc/` javadoc HTML and 18 `plugin-src/` examples — exist only for **12.x**, at
`~/Source/pingfederate-12.1.3/pingfederate/sdk` and several sibling checkouts. Those were used for
orientation only; every interface named in the plan was confirmed against the 13.0.3 jar itself.

**Consequence:** method *semantics* (as opposed to signatures) are inferred. Where behaviour matters —
notably `CustomDataSourceDriver.retrieveValues` and the `DynamicClientRegistrationPlugin.processPlugin`
lifecycle — it must be confirmed empirically against a running instance before being relied on.

## 6. CAEP Interoperability Profile is a draft, not Final

**Assumed:** it is guidance, not a requirement. The plan does not cite it as normative.

SSF 1.0 and CAEP 1.0 **are** Final (approved by OIDF membership vote, 2 September 2025 — 85 approve /
1 object / 25 abstain). The *Interoperability Profile* is a different document: currently **draft 01**,
published 21 July 2026, in public review to 25 September 2026, with voting 26 September to
10 October 2026. Its last approved status is Implementer's Draft ID1 (August 2024).

Trap worth knowing: neither SSF 1.0 nor CAEP 1.0 prints a `Status: Final` line in its masthead, and
the OIDF specs index still lists them under Implementer's Drafts as well as Final. The `-final.html`
URLs are byte-identical to the unsuffixed ones.

No OIDF certification programme for the profile was found.

- https://openid.net/three-shared-signals-final-specifications-approved/

## 7. Which PingOne capability emits device-compliance CAEP events

**Assumed:** nothing yet. Milestone 6 begins by determining this.

The decision is that PingOne is the authoritative device compliance source, but it is not established
whether that means PingOne MDM signals, PingOne Protect, or an integration that republishes from a
third-party MDM. No PingOne reference exists anywhere in this repository today.

Whether PingOne transmits SSF/CAEP natively, or whether a polling shim must translate into CAEP, is a
meaningful difference in effort and must be settled before milestone 6 is estimated.

## 8. Whether PingFederate can emit `act` as a JSON object

**Assumed:** nothing. The resource server accepts both forms and reports which one arrived.

RFC 8693 §4.1 defines `act` as a claim whose value is a **JSON object**.
`deploy/gke-spiffe-demo/pf/terraform/token-exchange.tf` emits it as a JSON *string* for consumers to
decode, with a comment noting PF 13.x rejects OGNL referencing an attribute literally named `act`
(`ognl_expression_invalid_attribute`, worked around with a second contract name `prior_act`).

Whether PF's JWT access token manager can emit a genuinely nested JSON claim — rather than a string
holding JSON — was **not determined**. It needs a running PF to settle, and guessing would mean
either shipping a spec deviation or breaking the existing mapping.

Until then `ActChain` parses both: the object form is the spec shape, and the legacy string form is
parsed so older tokens keep working but reported via `legacyStringForm()` so the deviation is visible
rather than permanent.

## 9. The PingFederate access token mapping for the instance registry

**Assumed:** the `CustomDataSourceDriver` contract as compiled, nothing about how PF drives it.

`InstanceRegistryDataSource` implements the interface exactly as it appears in the 13.0.3 SDK jar, and
`InstanceLookup` — all the actual logic — is unit tested with no PF on the classpath. What is
**unverified** is the surrounding configuration: that `PF-INF/custom-drivers` is the right descriptor
name for this plugin type (see item 4), that a filter field reaches `retrieveValues` the way the GUI
descriptor implies, and that an issuance criterion can gate on the returned booleans.

Symptom to expect if the descriptor name is wrong: PF ignores the jar silently, with no error.

## 10. demo-rs has no HTTP surface or replay cache yet

**Assumed:** nothing, but the gap is load-bearing enough to name.

`DelegatedTokenValidator` reports the DPoP proof's `jti` precisely so a caller can replay-cache it,
and a test asserts it is reported — but no caller exists yet. A resource server that skips that cache
accepts a captured proof for as long as it stays fresh, so the HTTP layer must wire
`AttestationReplayCache` (which already exists in `libs/client-attestation`) before it is used for
anything real.

---

## Related deliberate divergences

These are *decisions*, not gaps — they are recorded in [claim-dictionary.md](claim-dictionary.md)
rather than here:

- retaining `iss` on the attestation, which draft -08 removed;
- reusing an attestation within its 15-minute window, where the EUDI ARF mandates single-use;
- asserting `iso_18045_moderate` rather than `iso_18045_high` for Secure Enclave key storage.
