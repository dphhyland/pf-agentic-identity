# phone-simulator

Not a production artefact — a demo. Two runnable classes that let the device-enrolment ceremony be
shown working over a real HTTP server, real Postgres, and (optionally) real PingOne authentication,
without a physical iPhone.

| Class | Plays | Real, or standing in? |
|---|---|---|
| `DemoServerMain` | the agent platform backend | [Main.java](../../services/device-enrolment/src/main/java/com/pingidentity/ps/oidf/enrolment/Main.java)'s own wiring, verbatim, except the App Attest trust root — see below |
| `PhoneSimulatorCli` | the iOS agent | a software P-256 key stands in for the Secure Enclave; a synthetic chain stands in for genuine Apple hardware |

## The one thing this cannot do

App Attest can only be verified against a chain rooted at Apple's real App Attestation Root CA, and
nothing but a physical device holding a real Apple account can produce one. `Main.java` trusts exactly
that root and nothing else — deliberately: *"a service whose job is attestation should not ship a flag
that makes it accept anyone's root."*

So `DemoServerMain` trusts a **different, bundled root** instead
([`demo-appattest-root-cert.pem`](src/main/resources/demo/appattest-root-cert.pem)), and
`PhoneSimulatorCli` signs its synthetic attestations with the matching private key
([`appattest-root-key.pem`](src/main/resources/demo/appattest-root-key.pem)) — checked in openly,
exactly like the RFC 7515 example signing key already in
[docker-compose.yml](../../deploy/device-enrolment/docker-compose.yml). It is not a secret in any
sense that matters; a verifier trusting it is only ever appropriate here, which is why the
substitution lives in its own class rather than a flag on `Main`.

**What this proves**: the whole ceremony — challenge, nonce commitment to the enclave key, chain
validation, key-id derivation, rpIdHash, aaguid, counter, PingOne verification, registry writes, the
issued attestation's shape, re-minting, the CAEP suspension loop — over real HTTP and real Postgres.

**What it still cannot prove**: that Apple's *real* attestation objects parse. Only a physical device
can. See [docs/unverified.md](../../docs/unverified.md) and milestone 1 (M1b) in the plan.

## Running it

```bash
docker compose -f deploy/device-enrolment/docker-compose.yml up --build
```

Brings up real Postgres with the schema applied, and `DemoServerMain` on `:8080`, wired to the real
PingOne tenant (`fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d`, matching
[vars.staging.env](../../deploy/device-enrolment/vars.staging.env) exactly) — so `user_authentication`
is genuinely verified, not stubbed.

Build the simulator once:

```bash
mvn -pl demo/phone-simulator -am -DskipTests package
```

### See it fail closed (zero setup beyond the two commands above)

```bash
java -cp demo/phone-simulator/target/phone-simulator-0.1.0.jar:demo/phone-simulator/target/dependency/* \
  com.pingidentity.ps.oidf.demo.phonesim.PhoneSimulatorCli --demo-evidence
```

This builds a real, verifiable synthetic App Attest attestation and gets past the challenge, the nonce
commitment and the chain validation — then is correctly refused at `user_authentication_failed`,
because `--demo-evidence` sends an obviously-fake string and the server is wired to a real IdP. That
refusal *is* the point of this run: even fully wired to production authentication, garbage evidence
does not get in.

### See the green path (needs a real PingOne ID token)

The registered client (`fad0652e`, "Device Agent Enrolment") is a public native app whose only
redirect URI is `com.idpartners.bankapprover://enrolment/callback` — the iOS app's custom scheme, not
a loopback address a CLI can catch. Until either the iOS app exists or a loopback redirect URI is
added to that PingOne client (a live-tenant change, out of scope for this demo to make on its own),
obtaining a real ID token means completing an actual passkey authentication against
`https://auth.pingone.asia/fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d/as` out of band and capturing the
`id_token` from the result — for example via PingOne's own hosted test/playground tooling, or a
temporary redirect URI added deliberately for this purpose.

Once you have one:

```bash
java -cp demo/phone-simulator/target/phone-simulator-0.1.0.jar:demo/phone-simulator/target/dependency/* \
  com.pingidentity.ps.oidf.demo.phonesim.PhoneSimulatorCli --id-token <the ID token>
```

This runs the full ceremony: challenge, App Attest, enrolment, and a re-mint on the hot path, printing
the issued Client Attestation's claims at each step — `sub` naming the instance (never the human),
`cnf.jwk` present, a short `exp - iat`.

### See the CAEP loop suspend an instance mid-session

`EnrolmentService.Enrolled` deliberately never carries `device_id` — *"the instance identifier is the
client's handle from here on; it never learns the device id"* — so this cannot come from the CLI's own
output. Read it from the registry, the way an operator actually would:

```bash
docker compose -f deploy/device-enrolment/docker-compose.yml exec postgres \
  psql -U enrolment -d enrolment -c "select id from device order by created_at desc limit 1;"
```

Then:

```bash
java -cp demo/phone-simulator/target/phone-simulator-0.1.0.jar:demo/phone-simulator/target/dependency/* \
  com.pingidentity.ps.oidf.demo.phonesim.PhoneSimulatorCli --id-token <token> --suspend-device <that id>
```

The run enrols, re-mints once, applies a `device-compliance-change`-shaped signal, then re-mints again
— which now fails with `instance_not_active`, with no agent re-authentication and no revocation call
involved. That is the milestone 6 acceptance criterion, live.

## Flags

| Flag | Meaning |
|---|---|
| `--base-url URL` | default `http://localhost:8080` |
| `--id-token JWT` | a real PingOne ID token, for the green path |
| `--demo-evidence` | send an honestly-fake evidence string instead — proves the fail-closed refusal |
| `--development` | build the App Attest object in the `DEVELOPMENT` environment rather than `PRODUCTION` |
| `--suspend-device ID` | after enrolling and re-minting once, apply a compliance signal to this device and show the next re-mint refused |

Exactly one of `--id-token` / `--demo-evidence` is required — the CLI does not default to either,
matching the server's own refusal to guess.
