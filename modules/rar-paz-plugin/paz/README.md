# Local PingAuthorize + RAR containment policy

Stands up PingAuthorize (PDP + PAP) locally and authors, via the PAP REST API, a policy that makes the
**governance-engine decision** our [plugin](../README.md) calls: PERMIT when the requested region is within
the attestation's entitlement, DENY when it exceeds it.

## Prerequisites
Docker running. The images are Ping's `pingauthorize` / `pingauthorizepap` `10.2.0.1` (amd64; run emulated on
Apple Silicon). Licenses + EULA are shipped/accepted by the upstream repo
`idpartners-authzen-ping-authorize` (referenced by absolute path in `paz-compose.yml`).

## Bring it up
```bash
docker compose -f paz-compose.yml up -d          # authzen-pdp :8443, authzen-pap :7443
# import the shipped policy tree as branch "AuthZEN" (the repo's install hook looks in the wrong dir):
SNAP=/Users/davidhyland/Source/idpartners-authzen-ping-authorize/ping-authorize/pap/policies/AuthZEN.snapshot
curl -sk -H "x-user-id: admin" -H "Content-Type: application/json" --data-binary @"$SNAP" \
     "https://localhost:7443/api/snapshot/AuthZEN/import"
```

## Author the policy (as-run scripts)
```bash
python3 01-author-permit.py        # rule + policy (1c5385f3) under node 6ae6edd5, commit; probe -> PERMIT
python3 02-author-containment.py   # scalar containment demo (req_region/attested_regions) + Contains; commit
python3 03-align-plugin-scalars.py # align to the plugin's flat mirrors; probe the plugin's real request shape
```
`02` prints the proof:
```
5 probe EMEA (within): PERMIT authorised=True
6 probe AMER (beyond): DENY  authorised=False
```
Verify anytime with [`../probe-decision.sh`](../probe-decision.sh) (uses header `CLIENT_TOKEN: 2FederateM0re`).

> The scripts contain IDs captured from the first run (branch `58a67ffb…`, rule `805ab29f…`). Re-running from a
> fresh PAP means re-importing the branch and updating those IDs. The PAP API: base `https://localhost:7443`,
> auth header `x-user-id: admin`, branch via `?branch=AuthZEN`; entities under `/api/trust-framework/roots/{TYPE}`
> and `/api/v2/policy-manager/{rules,policies,policysets}`; commit `POST /api/version-control/branches/{id}/commit`.

## Final state (verified)
`paz-compose.yml` sets `POLICY_NODE_ID` to **our policy** (`1c5385f3…`) so the PDP evaluates only it — the stock
AuthZen policies otherwise throw INDETERMINATE on our request under `DenyOverrides`. The plugin
([GovernanceEngineRequestBuilder](../src/main/java/com/pingidentity/ps/oidf/rar/GovernanceEngineRequestBuilder.java))
emits flat, dot-free mirrors `req_<field>` / `att_<field>` (PingAuthorize attribute names can't contain `.`), and
the rule is `att_sales_regions Contains req_sales_regions`. Verified with the plugin's real request shape:
`EMEA`/`APAC` → PERMIT, `AMER` → DENY.

Note: `Contains` here is substring on space-joined strings — fine for the demo. A production policy should parse
the JSON arrays into COLLECTIONs (json-path value processor `$[*].sales_regions[*]`, which PingAuthorize supports
on the stock `action.Actions` attribute) and use collection subset; an attempt at that hit a collection-`Contains`
INDETERMINATE on the permit path that needs further work.
