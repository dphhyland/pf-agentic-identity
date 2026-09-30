# Reference PingAuthorize policies for the RAR processor

One reference policy per built-in type, for the processor's **governance-engine** dialect, as files, with a script
that authors them into a PingAuthorize Policy Editor and decision tests that run each one there. They are a starting
point a deployment copies and changes, not a policy it should run unread: the limits and the narrowings are examples.
The plugin's `authzen` dialect talks to any AuthZEN 1.0 PDP and needs none of this.

| File | What |
|---|---|
| [`policies/trust-framework.json`](policies/trust-framework.json) | the domains (`idpartners.authorization_details.<type>`) and the request attributes the policies read |
| [`policies/sales_agent.json`](policies/sales_agent.json) | permit the regions the attestation vouches for; a client alone is held to EMEA |
| [`policies/payment_initiation.json`](policies/payment_initiation.json) | permit a person PingFederate authenticated, up to 1000; a request that also asks to cancel is held to `initiate` |
| [`policies/account_information.json`](policies/account_information.json) | permit a person's balances; balances and transactions are held to balances; transactions alone are denied |
| `policies/<type>.cases.json` | the decision tests: the governance-engine request the processor sends, and the answer the policy must give - a permit, a deny and a narrowing for each type |
| [`author-policies.py`](author-policies.py) | authors the files into a Policy Editor on a branch of their own, through its REST API, and commits it |
| [`decision-tests.py`](decision-tests.py) | runs every case against the branch's decision node; exit 1 on a failure |
| [`paz_client.py`](paz_client.py) | what the two scripts share: the Policy Editor's URL, TLS and the one secret |
| [`paz-compose.yml`](paz-compose.yml) | a Policy Editor to run them against, with Ping's evaluation licence and nothing else from outside this repo |

## Run them

```bash
export PAZ_DECISION_SECRET="$(openssl rand -hex 24)"      # yours; nothing here has a default
docker compose -f paz-compose.yml up -d                    # the Policy Editor on https://localhost:7443
python3 author-policies.py                                 # prints {"branch": "RAR-reference", "decision_node": "..."}
python3 decision-tests.py                                  # 10 cases, "every case passed"
docker compose -f paz-compose.yml down
```

The Policy Editor fetches Ping's evaluation licence at start with `PING_IDENTITY_DEVOPS_USER` and
`PING_IDENTITY_DEVOPS_KEY` from `$PING_DEVOPS_CONFIG` (default `~/.pingidentity/config`), the file
`conformance/up.sh` reads. The decision point shared secret is the only secret: the compose file refuses to start
without `PAZ_DECISION_SECRET`, and `decision-tests.py` reads the same value from `PAZ_DECISION_SECRET` or from the file
`PAZ_DECISION_SECRET_FILE` names and refuses to run with neither. The REST API is called as the user in `PAZ_PAP_USER`
(default `admin`) through the `x-user-id` header, the image's credentials mode, which takes a user name and no secret.
`PAZ_PAP_URL` (default `https://localhost:7443`) points elsewhere; the image's certificate is self-signed, so give its
CA in `PAZ_CA_FILE`, or, on this machine only, the scripts trust the certificate the Policy Editor presents (it names
`localhost` and `127.0.0.1`, and the host name is checked). `author-policies.py --replace` deletes a branch of the
same name first.

Run on 2026-09-30 against `pingidentity/pingauthorizepap:11.1.0.0-latest` brought up by this compose file (package
PLG): the branch authored and committed, and all ten cases passed; with a wrong secret the decision endpoint answered
401 and the script stopped.

## How the policies are shaped

`author-policies.py` writes, on a new branch: the domains and attributes of `trust-framework.json` (a dotted
attribute name is a path of parent attributes, as the processor's `<Attribute Prefix>.<type>.<field>` names are), then
for each type its statements, its rules and a policy that applies only to its own domain, and one policy set, "RAR
reference policies", holding the three. That policy set is the decision node. Every policy and the policy set combine
with `DenyUnlessPermit`, so a request no rule permits is denied.

A narrowing is a statement returned with the permit: its name is the detail member and its payload the value, which
the processor writes into the granted detail (`StatementApplier`) and then holds to the RAR model's `within` - a
narrowing that widens the request is refused there, whatever the policy says. The payloads here narrow a set the
request carried (`sales_regions`, `actions`, `datatypes`), so each is within its request.

What each type reads, from the processor's governance-engine request (`GovernanceEngineRequestBuilder`, default
fields: Attribute Prefix `idp`, Prefix Attributes with Type on, Domain Prefix `idpartners.authorization_details`):
`principal_source` (how the subject was established), the flat mirrors `req_<field>` and `att_<field>` of the
set-valued fields (space-joined, in the order the processor writes them), and for a payment the flat amount as
`idp.payment_initiation.amount`. `Contains` over the mirrors is a substring test on the joined text, which is enough
for these examples and not a set comparison: a production policy that compares sets should parse the JSON-valued
`idp.<type>.<field>` attributes into collections.

The Policy Editor's decision endpoint is `POST /api/governance-engine`, HTTP Basic with the decision point shared
secret as the password, and the branch and decision node in the `x-branch` and `x-decision-node` headers
(`GovernanceEngineRootResource` and `SharedSecretAuthenticator` in the 11.1.0.0 image, read 2026-09-30). The
processor does not call it: it calls a PingAuthorize Server's `/governance-engine`, which in external mode asks the
Policy Editor with that branch and decision node, so point a PingAuthorize Server's policy decision service at the
branch and the id `author-policies.py` prints. [`../probe-decision.sh`](../probe-decision.sh) sends the processor's
request shape to such a server, with the secret from `PAZ_PDP_SECRET` or `PAZ_PDP_SECRET_FILE` and no default.

## Before 0.6.0

This directory held a compose file that mounted a checkout beside this one and three scripts that edited one rule of a
demo branch by hard-coded ids, with Ping's public demo secret as the default in each. They are gone (package PLG): the
policies are files, the scripts author all three types from them, and no secret has a default anywhere here.
