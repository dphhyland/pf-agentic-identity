# harness

In-process verification CLIs — run by hand, not by `mvn test` — that exercise the real classes end to
end in a way surefire alone doesn't. Ported from `pf-oidf-modules` (2026-08-18) when that repo was
reduced to the demo UI + shell probes; import paths were updated for this repo's package layout and
every call verified against the current class signatures before porting.

| Class | What it proves |
|---|---|
| `AttestationFlowHarness` | `selfverify`: the real `ClientAttestationVerifier` accepts a correctly-built PoP/DPoP request and an RFC 9396 request within the attested entitlement, and rejects a tampered DPoP key and an out-of-entitlement request. `live <baseUrl>`: fetches a real challenge from a **deployed** PingFederate, mints a full attestation + PoP + DPoP, and executes a live token request — prints the response and a ready-to-run `curl`. |
| `AttestationIssuanceHarness` | The issuance servlet's flow via its public building blocks (`SpiffeSvidValidator`, `AttestationIssuanceConfig`, `InstanceKeyProofValidator`, `AttesterSigningKey`, `AttestationMinter`) — a valid SVID + instance proof mints an attestation that round-trips through the real verifier; an unbound SPIFFE ID and a wrong-key proof are both refused. |
| `SsfSelfVerify` | Mints a CAEP session-revoked SET with the real `SetMinter` and verifies its signature, `typ` header, and claims. |

## Run

Build the reactor once so every module this depends on is in your local repo:

```sh
mvn -o install -DskipTests   # from the repo root
```

Then, from the repo root:

```sh
mvn -pl services/harness exec:java -Dexec.mainClass=com.pingidentity.ps.oidf.harness.SsfSelfVerify

mvn -pl services/harness exec:java -Dexec.mainClass=com.pingidentity.ps.oidf.harness.AttestationIssuanceHarness

mvn -pl services/harness exec:java -Dexec.mainClass=com.pingidentity.ps.oidf.harness.AttestationFlowHarness \
  -Dexec.args=selfverify

# against a deployed PingFederate — the host is yours to supply; this repo deploys nothing and
# deliberately names no environment. Note the module serves at ROOT context, no /oidf prefix.
mvn -pl services/harness exec:java -Dexec.mainClass=com.pingidentity.ps.oidf.harness.AttestationFlowHarness \
  -Dexec.args="live https://<your-pf-host>"
```

`live` mode env: `OIDF_CLIENT_SECRET` (**required** - it goes on the wire, so there is no default);
`OIDF_ATTESTER_JWK` (a private JWK JSON matching an entry in the target's mock-attesters trust file —
without it a random key is used, which any real deployment correctly rejects with
`attestation_validation_failed`); `OIDF_SALES_REGION`; `OIDF_NO_CHALLENGE=1`;
`OIDF_HARNESS_INSECURE_TLS=true` to accept a self-signed local PF (verification is on by default and
the flag warns loudly - never set it against a real deployment).

`selfverify` also runs under surefire (`AttestationFlowHarnessSmokeTest`) - the harness reaches the
verifier by reflection on class names, so a rename now fails the build rather than a demo.
