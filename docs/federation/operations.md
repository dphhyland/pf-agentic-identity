# Operations

Running the federation support day to day: pinning trust anchors and rolling their keys, hosting agents,
granting Trust Marks, wiring a policy engine, and reading what it logs. Every setting named here is in
[configuration](configuration.md); what each part does is in [how it works](how-it-works.md).

## Pinning a trust anchor

Nothing validates a chain until PingFederate has its anchors' public keys, and those arrive out of band
(OpenID Federation 1.0 §10(1)): never fetched from the anchor at request time.

1. Get the anchor's keys from somewhere you trust. The best source is the federation operator, through a
   channel separate from the anchor's own website (§11.3). Failing that, capture them once from a network you
   trust with `tools/pin-trust-anchor.py https://anchor.example`, and **compare the printed thumbprints with the
   key the anchor actually holds** before you use them.
2. Set `OIDF_FEDERATION_TRUST_ANCHOR_JWKS`. For one anchor, its JWK Set, with the anchor named in
   `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`. For several, a map of anchor to JWK Set:

   ```json
   {"https://federation.example.org": {"keys": [...]}, "https://partners.example.net": {"keys": [...]}}
   ```

   A set with a private key, a symmetric key, or a key without a `kid` or with a repeated one stops the
   registration filters starting.
3. Restart PingFederate. The first chain that reaches the anchor checks the anchor's own Entity Configuration
   against what you pinned; a wrong capture fails there, loudly.

**PingFederate as its own anchor.** Set `OIDF_FEDERATION_SELF_ANCHOR` to PingFederate's Entity Identifier (its
issuer, an https URL) and name it in `OIDF_FEDERATION_TRUST_ANCHORS` too, so its Entity Configuration says it is
an anchor. Chains that end at PingFederate are then checked with the key it signs with, read from its key store
each time. Don't also pin PingFederate's keys in `OIDF_FEDERATION_TRUST_ANCHOR_JWKS`: that is refused, because the
copy would go stale at the first rotation.

## Rolling an anchor key

An anchor rolls its key by publishing the new one alongside the old for a while (§11.2). On the PingFederate
side:

1. When the anchor announces the new key, add it to the pinned set for that anchor - both keys, old and new.
2. Restart PingFederate. Chains signed with either key now check out.
3. After the anchor has stopped signing with the old key, and every statement it signed with it has expired,
   remove the old key and restart again.

If you remove the old key too early, chains built from statements the anchor signed before the roll fail until
those statements expire - at most their lifetime, often an hour.

## Hosting agents

With `OIDF_AUTHORITY_ENTITY_ID` and `OIDF_AUTHORITY_ADMIN_TOKEN` set, PingFederate is a domain authority: it
publishes and signs Entity Configurations for agents that can't publish their own, with a key per agent kept
in OpenBao. Keep the agents in a database (`OIDF_AUTHORITY_JDBC_URL` or `OIDF_AUTHORITY_DATA_STORE_ID`, with the
`V100`-`V101` migrations applied) - in memory they are gone at the next restart.

**Enrol an agent** - the OpenBao transit key must exist already:

```sh
curl -sS https://pf.example.com/federation/agents \
  -H "Authorization: Bearer $OIDF_AUTHORITY_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"id": "payments-agent", "hostingKeyRef": "agent-payments-1",
       "metadata": {"oauth_client": {"client_name": "Payments agent", "scope": "payments.read"}}}'
```

Its Entity Configuration is then at `https://pf.example.com/federation/agents/payments-agent/.well-known/openid-federation`
(the id is built from `OIDF_AUTHORITY_ENTITY_ID`, never the request's `Host`). Optional fields: `listable`
(default false - it stays out of `/federation/list`), `notAfterSeconds`, `ownerRef`, and `metadataPolicy`, which
can only narrow the domain default (`OIDF_AUTHORITY_METADATA_POLICY`). With the policy engine asked at enrolment,
a refusal is a 403.

**Change it** through the admin API, each a POST with the admin bearer and a JSON body naming the agent:

| Route | Body | What happens |
|---|---|---|
| `/federation/admin/entities/suspend` | `{"entity_id", "reason"?}` | Stops resolving at once; can be undone |
| `/federation/admin/entities/reactivate` | `{"entity_id", "reason"?}` | Resolves again |
| `/federation/admin/entities/revoke` | `{"entity_id", "reason"?}` | Stops resolving, for good (a revoked agent is a 409 after) |
| `/federation/admin/entities/metadata` | `{"entity_id", "metadata"}` | Replaces its metadata |
| `/federation/admin/entities/metadata-policy` | `{"entity_id", "metadata_policy"}` | Replaces its own policy, which must only narrow the domain default |
| `/federation/admin/entities/rotate-key` | `{"entity_id", "hosting_key_ref"}` | Moves it to a new OpenBao key, after checking the key signs |

`GET /federation/admin/entities` lists every hosted agent whatever its status; `?entity_id=` gives one, with its
metadata and policy; `/federation/admin/entities/audit?entity_id=` gives its history. Every change records who
made it: `admin:` and the first eight hex digits of the admin token's SHA-256, followed by the
`X-Federation-Actor` header when you send one - for accountability, it grants nothing. The token itself is never
logged.

Suspending or revoking stops the agent resolving here straight away. What it doesn't stop is in
[how it works](how-it-works.md#what-stops-when).

## Trust Marks

To issue marks, name the types in `OIDF_FEDERATION_TRUST_MARK_TYPES` and keep the grants in the authority's
database (`V102__trust_mark.sql`). Then grant them:

```sh
curl -sS https://pf.example.com/federation/admin/trust-marks \
  -H "Authorization: Bearer $OIDF_AUTHORITY_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"trust_mark_type": "https://pf.example.com/marks/certified", "sub": "https://rp.example.com"}'
```

Granting a type again revokes every mark issued under the old grant. `POST /federation/admin/trust-marks/revoke`
with `{"trust_mark_type", "sub", "reason"?}` revokes; `GET /federation/admin/trust-marks?sub=` or
`?trust_mark_type=` lists grants, and `/trust-marks/audit` gives one grant's history. A type issued to hosted
agents only can be granted only to an active one.

Revoking a grant makes the status endpoint answer `revoked` straight away. A copy of the mark someone already
has still verifies until it expires, for anyone who doesn't ask the status endpoint - so keep mark lifetimes
short, or have relying parties set `OIDF_FEDERATION_TRUST_MARK_STATUS_CHECK=true`.

## Key history

With `OIDF_FEDERATION_HISTORICAL_KEYS=true` (and `V103__federation_key_history.sql` applied), PingFederate notices
at start-up that its signing key changed since it last started, publishes the old key as retired, and serves
the lot at `/federation/historical_keys`. `GET /federation/admin/keys` shows the history;
`POST /federation/admin/keys/revoke` with `{"kid", "reason"?}` revokes a retired key (`unspecified`,
`compromised` or `superseded`). PingFederate refuses to start signing with a key that has been revoked, so rotate
its signing key in the admin console before you revoke the one in use.

## Wiring a policy engine

1. Point PingFederate at an AuthZEN 1.0 PDP: `OIDF_PDP_MODE=authzen`, `OIDF_PDP_URL` (evaluation at
   `/access/v1/evaluation` under it), or `OIDF_PDP_EVALUATION_URL` for an endpoint elsewhere, or
   `OIDF_PDP_DISCOVER=true` to read it from the PDP's `/.well-known/authzen-configuration`. The URL must be https.
2. Authenticate to it: `OIDF_PDP_AUTH=bearer` or `header` with `OIDF_PDP_AUTH_TOKEN` (the header is
   `CLIENT-TOKEN` unless `OIDF_PDP_AUTH_HEADER` says otherwise, as the RAR plugin sends it).
3. Choose where it is asked: `OIDF_PDP_DECISION_POINTS` - `explicit_registration` and
   `automatic_registration` by default; add `hosted_entity_enrol` and `token_issuance` if you want them.
4. Give it a policy for the actions it will be asked about before you switch it on: every registration waits for
   it, and no decision is a 503.

What it is asked, for an automatic registration at the authorization endpoint:

```json
{
  "subject":  {"type": "federation_entity", "id": "https://rp.example.com",
               "properties": {"entity_types": ["openid_relying_party"], "trust_anchor": "https://ta.example.org"}},
  "action":   {"name": "federation.register.automatic",
               "properties": {"endpoint": "authorization", "entity_type": "openid_relying_party"}},
  "resource": {"type": "openid_provider", "id": "https://pf.example.com"},
  "context":  {"scope": "openid profile", "grant_types": ["authorization_code"],
               "redirect_uris": ["https://rp.example.com/cb"], "chain_expires_at": 1790294400,
               "request": {"tracking_id": "tid:..."}}
}
```

It answers `{"decision": true}` or `false`. A `true` may carry obligations in its `context`, and each only
narrows: `scope`, `grant_types` and `response_types` (keep only these), `registration_ttl_seconds` (a shorter
registration), `require_trust_mark` (a mark the entity must hold). At token issuance they are checks instead: a
token that doesn't meet them is refused. `reason_admin` goes to PingFederate's logs; `reason_user` is shown to
the client only with `OIDF_PDP_SURFACE_USER_REASON=true`.

Only a 200 with a boolean `decision` is an answer (AuthZEN §10.1.2). Anything else - an error status, a timeout
(2 s to connect, 3 s for the answer by default), a body that isn't a decision - is refused with a 503, unless
`OIDF_PDP_FAIL_OPEN=true`, which lets the request through unnarrowed and logs `federation.pdp.failopen`. To test a
PDP by hand, POST the request above to it:

```sh
curl -sS "$OIDF_PDP_URL/access/v1/evaluation" -H 'Content-Type: application/json' \
  -H "CLIENT-TOKEN: $OIDF_PDP_AUTH_TOKEN" -H 'X-Request-ID: manual-1' -d @request.json
```

## Reading the logs

Each decision is written as one line in `server.log`, on a logger named for its family -
`com.pingidentity.ps.oidf.federation.event.registration`, `.chain`, `.pdp` and so on:

```
event=federation.registration.refreshed outcome=success subject=https://agents.example.com/payments-agent partner=https://ta.example.com type=automatic endpoint=token entity_type=oauth_client expires_at=1790294400 previous_expires_at=1790208000 keys_changed=true
```

The parts come in a fixed order - `event`, `outcome`, `reason`, `subject` (the client or entity), `partner` (the
trust anchor, or the issuer), the event's own fields, `desc` - and PingFederate's log layout adds its
timestamp and tracking id in front. A refusal that matters for security is written at WARN; everything else at
INFO. The security-relevant events also go to PingFederate's `audit.log`, with the code as the event, `success` or
`failure`, the subject as the user, the partner as the connection, and the rest of the line as the description.
`OIDF_EVENTS_AUDIT=false` keeps them out of the audit log.

What never reaches an event: tokens (anything shaped like a JWT becomes `jwt:sha256:` and twelve hex digits of
its hash, so lines still correlate), control characters (a forged newline can't split a line), values beyond 512
characters (`OIDF_EVENTS_MAX_VALUE_LENGTH`), the admin token, the policy engine's obligation values, and its
`reason_user`. That covers the event lines only; the modules' ordinary log lines are written with the same care
but not by the same code.

| Event | When | Audit |
|---|---|---|
| `federation.registration.created`, `.refreshed` | A client was registered, or its registration renewed or replaced - explicit or automatic, at which endpoint, until when, and whether its keys changed | Yes |
| `federation.registration.refused` | A registration was refused: the chain, a missing metadata policy, a missing Trust Mark, the policy engine, or PingFederate dropping the extended properties | Yes |
| `federation.registration.expired` | A request found a registration past its end and not renewed; what happened next follows `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` | Yes |
| `federation.registration.disabled` | An expired client was disabled - by the request that found it, or by the sweeper | Yes |
| `federation.registration.refresh_deferred` | A due renewal failed but the registration hasn't expired, so it stands for now | No |
| `federation.registration.expired_at_issuance` | The OGNL criterion found an expired registration at token issuance | Yes |
| `federation.chain.validated`, `.refused` | The OGNL criterion checked a client's chain at token issuance | Refused only |
| `federation.token.refused` | Token issuance refused by the policy engine, or for an obligation the token doesn't meet | Yes |
| `federation.pdp.consulted` | The policy engine answered (read `decision`), or gave no answer (`no_decision`) | Yes |
| `federation.pdp.failopen` | No answer, and `OIDF_PDP_FAIL_OPEN=true` let the request through | Yes |
| `federation.hosted_entity.enrolled`, `.suspended`, `.reactivated`, `.revoked`, `.updated`, `.rotated` | A hosted agent was enrolled or changed, and by whom | Yes |
| `federation.hosted_entity.refused` | The policy engine refused an enrolment | Yes |
| `federation.trust_mark.granted`, `.revoked` | A Trust Mark grant was made or revoked, and by whom | Yes |
| `federation.trust_mark.issued` | PingFederate signed a Trust Mark | Yes |
| `federation.trust_mark.verified` | Another issuer's Trust Mark checked out | No |
| `federation.client.authenticated`, `.refused` | A client authenticated at a federation endpoint, or was refused | Refused only |
| `federation.key.retired`, `.revoked` | PingFederate's signing key changed since it last started, or a retired key was revoked | Yes |

Not everything is an event. Serving an Entity Configuration, a fetch, a list or a resolve isn't; a refusal at a
federation endpoint is a line on `com.pingidentity.ps.oidf.servlet.trustanchor.FederationErrors` (INFO for a
refusal, WARN for a 503, ERROR for a fault of ours), and it never reaches the audit log. Nor do a few registration
refusals that happen before any chain is checked - a client an administrator made, a request object that breaks
the rules - which the filters log on their own loggers.

Each audit record carries the caller's address in `ip`. The servlets, both filters and the OGNL criterion enter a
request scope as each request starts and leave it when the request ends, however it ends, so a pooled thread never
carries one caller's address into its next request. The address is the one PingFederate records for its own
events: behind a proxy it is the proxy's, unless PingFederate's incoming proxy settings name the header that carries
the client's (`forwarded_ip_address_header_name` on `pingfederate_incoming_proxy_settings`). `host` is PingFederate's
own - the name of the node that wrote the record - and `protocol` is `OpenID Federation`. A record written off a
request, by the sweeper or for a key rotation noticed at start-up, has no `ip`. The sweeper's lines carry a
tracking id of their own, `oidf-sweep-` and eight hex digits.

**Turning events into Shared Signals.** The SSF transmitter can listen to the same audit logger and send CAEP
events for the ones you map, for example
`OIDF_SSF_AUDIT_EVENT_MAP=federation.hosted_entity.revoked=account-disabled,federation.registration.disabled=account-disabled`.
Nothing is mapped by default, and only successes with a subject can be. It works only if PingFederate's
`log4j2.xml` declares the `com.pingidentity.sdk.logging.LoggingUtil` logger; SSF says at start-up how many audit
loggers it attached to.

## The registration sweeper

Every five minutes (`OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS`, `0` turns it off) a background task disables
federation clients whose registration has ended. It never deletes one, and a renewal enables it again; a client
an operator disabled stays disabled. It doesn't run while `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log`, which
records expiries and enforces none - the setting for an upgrade, while relying parties catch up. One sweeper
runs per PingFederate, whichever component starts first.

## Upgrading

[The 0.3.0 release notes](../releases/0.3.0.md) say what to do before deploying: declare the extended
properties, apply the migrations, decide about clients registered before expiries were recorded, and
re-assemble `pf-runtime.war`.
