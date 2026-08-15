# Local PingAuthorize + RAR containment policy

Stands up PingAuthorize (PDP + PAP) locally and authors, via the PAP REST API, the policy behind the
**governance-engine** decision our [plugin](../README.md) calls: PERMIT when the requested region is
within the attestation's entitlement, DENY when it exceeds it. This tree covers the `governance-engine`
dialect only; the plugin's `authzen` dialect needs no Trust Framework work — any AuthZEN 1.0 PDP.

## Read this before `docker compose up`

**`paz-compose.yml` is author-local.** It mounts absolute paths under
`/Users/davidhyland/Source/idpartners-authzen-ping-authorize/` — that sibling checkout supplies the
server profile, the PAP options file, the console war, the certs and the licence files (`LICENSE_DIR`,
`PingAuthorize.lic`). Anyone else needs that checkout at that path, or has to edit every volume line.
It is left this way on purpose: it records the exact rig the policy was authored against, not a
portable stack.

**Every secret in it is Ping's public demo default.** `2FederateM0re` (`PDP_SHARED_SECRET`,
`SIDEBAND_SHARED_SECRET`, `DECISION_POINT_SHARED_SECRET`) and the `CLIENT_TOKEN` header name; the PAP is
called with an `x-user-id: admin` header rather than any real authentication. Nothing here is a
credential worth protecting, and nothing here should reach a network anyone else can see.

Images: `pingidentity/pingauthorize` / `pingauthorizepap` `10.2.0.1-latest` (amd64; emulated on Apple
Silicon). EULA is accepted in the compose environment.

## Bring it up

```bash
docker compose -f paz-compose.yml up -d          # authzen-pdp :8443, authzen-pap :7443
# import the shipped policy tree as branch "AuthZEN" (the upstream install hook looks in the wrong dir):
SNAP=/Users/davidhyland/Source/idpartners-authzen-ping-authorize/ping-authorize/pap/policies/AuthZEN.snapshot
curl -sk -H "x-user-id: admin" -H "Content-Type: application/json" --data-binary @"$SNAP" \
     "https://localhost:7443/api/snapshot/AuthZEN/import"
```

## Author the policy (as-run scripts)

```bash
python3 01-author-permit.py        # rule + policy (1c5385f3…) under node 6ae6edd5, commit; probe → PERMIT
python3 02-author-containment.py   # scalar containment (req_region/attested_regions) + Contains; commit
python3 03-align-plugin-scalars.py # align to the plugin's flat mirrors; probe the plugin's real request shape
```

`02` prints the proof: `probe EMEA (within): PERMIT authorised=True` / `probe AMER (beyond): DENY
authorised=False`. Verify any time with [`../probe-decision.sh`](../probe-decision.sh) (defaults:
`https://localhost:8443/governance-engine`, header `CLIENT_TOKEN`, secret `2FederateM0re`). Note the
header name: this PDP is configured with `JSON_API_HEADER_NAME=CLIENT_TOKEN` (underscore), while the
plugin's **Shared Secret Header** field defaults to `CLIENT-TOKEN` — set it to match.

The scripts hard-code IDs captured from the first run (branch `58a67ffb…`, rule `805ab29f…`,
policy `1c5385f3…`, node `6ae6edd5…`). Re-running against a fresh PAP means re-importing the branch and
updating those IDs. PAP API in one line: base `https://localhost:7443`, header `x-user-id: admin`,
branch via `?branch=AuthZEN`; entities under `/api/trust-framework/roots/{TYPE}` and
`/api/v2/policy-manager/{rules,policies,policysets}`; commit
`POST /api/version-control/branches/{id}/commit`.

## Final state (verified when authored)

`paz-compose.yml` pins `POLICY_NODE_ID` to **our policy** (`1c5385f3…`) so the PDP evaluates only it —
the stock AuthZen policies otherwise throw INDETERMINATE on our request under `DenyOverrides`. The plugin
([`GovernanceEngineRequestBuilder`](../src/main/java/com/pingidentity/ps/oidf/rar/GovernanceEngineRequestBuilder.java))
emits flat, dot-free mirrors `req_<field>` / `att_<field>` (PingAuthorize attribute names cannot contain
`.`), and the rule is `att_sales_regions Contains req_sales_regions`. Verified with the plugin's real
request shape: `EMEA` / `APAC` → PERMIT, `AMER` → DENY.

Caveat: `Contains` here is substring on space-joined strings — fine for the demo. A production policy
should parse the JSON arrays into COLLECTIONs (json-path value processor `$[*].sales_regions[*]`, which
PingAuthorize supports on the stock `action.Actions` attribute) and use collection subset; an attempt at
that hit a collection-`Contains` INDETERMINATE on the permit path that needs further work.
