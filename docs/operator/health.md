# Health endpoints

From 0.5.0, a PingFederate built from this repository answers four paths on its runtime port (plan item O-4).
They come from `libs/platform-pf`'s `HealthServlet`, which `pf-runtime.war` maps by annotation, and they answer from
the webapp's own record of its components. Nothing needs configuring for live and ready; the detail and info are
operator routes, which need a PingFederate-issued access token with the scope `oidf.health.read` (from 0.6.0, plan
item S8b; [operator-authentication.md](operator-authentication.md)).

| Path | Authentication | Answer |
|---|---|---|
| `/agentic-identity/health/live` | none | 200 `{"status":"UP"}` while the webapp answers |
| `/agentic-identity/health/ready` | none | 200 `{"status":"UP"}`, or 503 `{"status":"DOWN"}` |
| `/agentic-identity/health` | an operator access token with `oidf.health.read` | the detail, with ready's status code |
| `/agentic-identity/info` | the same | this repository's version, the commit (null for now), PingFederate's and the JVM's |

## Access

The detail and info go through the same `OperatorAuthenticator` as the federation operator API (route `health.detail`
and `health.info`): in production a token DPoP-bound (or certificate-bound) to the caller, with `oidf.health.read` in
its scope, and each request - let through or refused - is an `admin.request.*` event in PingFederate's audit log. A
refusal is the authenticator's, with its challenge and no body: 401 without a usable token, 403
`insufficient_scope` for a token without `oidf.health.read` (an `oidf.admin.read` token does not read health), 429
after ten failed attempts from one address in a minute, and 503 when operator authentication is not configured.
Before 0.6.0 these answered 404 to anyone without the static bearer, as if nothing were mapped; they now say they are
there and what they need, because the failed-attempt limit, not obscurity, is what stops guessing.

`OIDF_AUTHORITY_ADMIN_TOKEN` opens them in development only, with a WARN per request; in production it is never
accepted, and while it is set the detail and info answer 503 like every operator route
([the static bearer](operator-authentication.md#the-static-bearer)). The second copy of the static-bearer rule that
lived here, `HealthAccess`, is gone (finding [F-0194](../findings/F-0194.yaml)).

Only GET and HEAD are served; any other method is 405 before a token is looked at. Every answer has
`Cache-Control: no-store`. A war that bundles platform-pf without rs-validation - `gm-api.war` today - cannot load the
authenticator, so its detail and info answer 503 while its live and ready work.

## What ready means

Each feature is a component with one of S-9's names: `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`,
`ATTESTATION_ISSUER`, `HOSTING`, `SSF`, `SSF_RECEIVER`, `OPERATOR_API`, `FAPI`. From 0.6.0 its enable switch,
`OIDF_<NAME>_ENABLED`, decides whether it runs - `true`, `false`, or unset and inferred from today's configuration
([components.md](components.md) has the rule, and why production refuses an unset switch beside the component's
settings). An enabled component reports `STARTING`, `READY`, `DEGRADED`, `FAILED_CONFIG`, `FAILED_DEPENDENCY` or
`REFUSED`, with a reason. Ready is 503 when an enabled component is not `READY` or `DEGRADED`. A disabled component
does not count. The table of which class serves which component, and when each is enabled, is in
[libs/platform's README](../../libs/platform/README.md#health).

Things to know before routing on ready:

- **A failed component no longer takes the war down.** Before 0.6.0 a servlet or filter that refused to start stopped
  the whole `pf-runtime.war`, live included, and every runtime endpoint answered 503 (verified on the rig,
  [components.md](components.md#verified-on-the-rig)). Now every `init` returns: the component is `FAILED_CONFIG` or
  `FAILED_DEPENDENCY` with its reason, its own surfaces answer 503 `temporarily_unavailable`, ready is 503, and live,
  `/pf/heartbeat.ping` and PingFederate's own SSO and OAuth endpoints keep answering - except under a failed `FAPI`,
  whose filter cannot tell a FAPI client from any other without the client list it failed to read, so every request to
  the endpoints it covers answers 503 ([components.md](components.md#what-a-component-does-when-it-fails)). A load
  balancer that routes on ready takes such a node out; one that routes on live or on PingFederate's heartbeat keeps
  sending it traffic, and the component's own requests meet the 503. A component that failed on a dependency (an I/O,
  SQL, timeout or linkage failure in its start - today, in practice, a file its start reads that is not there yet,
  such as `OIDF_FEDERATION_ERROR_PAGE`; the stores are not contacted until the first request) is retried with backoff
  from 5 s to 300 s and becomes ready by itself once the dependency is back; one that failed on configuration waits
  for a restart.
- **Every part starts at deploy.** Explicit registration, hosting, the admin API and the attester's issuance endpoint
  used to start on their first request, so ready did not see them until someone called them
  ([F-0193](../findings/F-0193.yaml), closed by S9a). They now load at start-up. The SSF receiver still starts on its
  first request until ST-5 moves the SSF start-up.
- **A PingFederate that names a trust controller before its anchor's keys are pinned is not ready**: automatic
  registration refuses everything until the keys are set. If it is its own trust anchor, capture the keys from the
  node directly, not through a load balancer that routes on ready ([F-0192](../findings/F-0192.yaml)).
- **An SSF transmitter whose settings do not parse is reported disabled**, as the transmitter itself treats it
  ([F-0191](../findings/F-0191.yaml)); read server.log's "SSF transmitter not configured" line.
- **Live is not PingFederate's heartbeat.** `/pf/heartbeat.ping` is PingFederate's own; live says only that this
  webapp answers. R-I3 (Phase 3) makes the image's HEALTHCHECK use both.

## The detail

```json
{"components":[{"enabled":true,"name":"AUTO_REGISTRATION","parts":[
   {"name":"FrontChannelAutoRegistrationFilter","reason":"","since":"2026-09-28T01:02:03Z","state":"READY"},
   {"name":"TokenEndpointAutoRegistrationFilter","reason":"","since":"2026-09-28T01:02:03Z","state":"READY"}],
  "reason":"","since":"2026-09-28T01:02:03Z","state":"READY"}],
 "profile":"production","status":"UP",
 "versions":{"agentic-identity":"0.5.0","commit":null,"java":"21.0.12.1+1-LTS","pingfederate":"13.1.3.0"}}
```

A reason can carry a setting's name, a file path or an exception message, which is why the detail is not open: it
needs `oidf.health.read`, a scope of its own, so a monitoring client can read health without being able to read or
change the federation administration.

## Other wars

`oidf.war` (demo-only) answers the same paths under `/oidf`, and `gm-api.war`, which bundles platform-pf from 0.5.0,
under `/gm-api`; each reports only its own components. gm-api's are one, `GM_API`, the worst of its two load-on-startup
servlets (seen on the rig on 2026-09-28: live and ready 200 `{"status":"UP"}` with `GM_API` READY). gm-api.war does
not carry rs-validation, so from 0.6.0 its detail and info answer 503 (see [Access](#access)).
