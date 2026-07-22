#!/usr/bin/env python3
"""Phase 2a: author a minimal PERMIT policy under decision node 6ae6edd5 in branch AuthZEN, commit, probe."""
import json, ssl, urllib.request, urllib.error

BASE = "https://localhost:7443"
BRANCH = "AuthZEN"
BRANCH_ID = "58a67ffb-bd0d-4690-893e-45e35cb57baa"
NODE = "6ae6edd5-0283-4ec8-ac84-08df56df1f63"   # AuthZen PolicySet the PDP evaluates
CTX = ssl._create_unverified_context()

def call(method, path, body=None, branch=True):
    url = BASE + path + (("?branch=" + BRANCH) if branch else "")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("x-user-id", "admin")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=25) as r:
            t = r.read().decode()
            return r.status, (json.loads(t) if t.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]
    except Exception as e:
        return 0, str(e)

# 1) create the PERMIT rule
rule = {"type":"Rule","name":"rar-permit-all","description":"RAR demo: permit",
        "shared":False,"disabled":False,"permissions":{"inherit":True,"rolePermissions":[]},
        "condition":{"empty":{}},"statements":[],"targets":[],
        "effectSettings":{"type":"unconditionalPermit"},"properties":[]}
s, r = call("POST", "/api/v2/policy-manager/rules", rule)
R1 = r.get("id") if isinstance(r, dict) else None
print("1 create rule:", s, R1 or r)
if not R1: raise SystemExit("rule create failed")

# 2) create the policy containing the rule
policy = {"type":"Policy","name":"rar-sales-agent","description":"RAR demo policy",
          "shared":False,"disabled":False,"combiningAlgorithm":{"algorithm":"DenyUnlessPermit"},
          "children":[{"id":R1,"type":"Rule"}],"repetitionSettings":None,
          "permissions":{"inherit":True,"rolePermissions":[]},
          "condition":{"empty":{}},"statements":[],"targets":[],"properties":[]}
s, r = call("POST", "/api/v2/policy-manager/policies", policy)
P1 = r.get("id") if isinstance(r, dict) else None
print("2 create policy:", s, P1 or r)
if not P1: raise SystemExit("policy create failed")

# 3) attach the policy under the decision-node PolicySet (GET, append child, PUT)
s, ps = call("GET", "/api/v2/policy-manager/policysets/" + NODE)
print("3a get policyset:", s, "children=", len(ps.get("children", [])) if isinstance(ps, dict) else ps)
if not isinstance(ps, dict): raise SystemExit("get policyset failed")
ps.setdefault("children", []).append({"id": P1, "type": "Policy"})
s, r = call("PUT", "/api/v2/policy-manager/policysets/" + NODE, ps)
print("3b put policyset:", s, (r.get("version") if isinstance(r, dict) else r))

# 4) commit the branch
s, r = call("POST", "/api/version-control/branches/%s/commit" % BRANCH_ID, {"message": "add RAR sales_agent demo policy"}, branch=False)
print("4 commit:", s, r if isinstance(r, str) else r.get("id", r))

# 5) probe the governance engine
body = {"domain":"idpartners.authorization_details.sales_agent","service":"Authorization","action":"authorize",
        "attributes":{"UserID":"https://rp.example.com","idp.sales_agent.sales_regions":"[\"EMEA\"]"}}
req = urllib.request.Request("https://localhost:8443/governance-engine", data=json.dumps(body).encode(), method="POST")
req.add_header("CLIENT_TOKEN","2FederateM0re"); req.add_header("Content-Type","application/json")
try:
    with urllib.request.urlopen(req, context=CTX, timeout=25) as rr:
        print("5 probe:", rr.status, rr.read().decode())
except urllib.error.HTTPError as e:
    print("5 probe:", e.code, e.read().decode()[:400])
