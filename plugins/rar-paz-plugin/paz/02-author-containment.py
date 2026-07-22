#!/usr/bin/env python3
"""Phase 2b: turn the demo rule into a real containment check (attested_regions Contains req_region)."""
import json, ssl, urllib.request, urllib.error

BASE="https://localhost:7443"; BRANCH="AuthZEN"
BRANCH_ID="58a67ffb-bd0d-4690-893e-45e35cb57baa"
RULE="805ab29f-147b-4a11-9a4d-9a8de072f0a6"   # rar-permit-all from phase 2a
CTX=ssl._create_unverified_context()

def call(method, path, body=None, branch=True):
    url=BASE+path+(("?branch="+BRANCH) if branch else "")
    data=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request(url, data=data, method=method)
    req.add_header("x-user-id","admin"); req.add_header("Content-Type","application/json")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=25) as r:
            t=r.read().decode(); return r.status,(json.loads(t) if t.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]
    except Exception as e:
        return 0, str(e)

def attr(name):
    return {"objectType":"AttributeDefinition","type":"ATTRIBUTE","name":name,"fullName":name,
        "description":"RAR demo","parentId":None,"valueType":"STRING","defaultValue":None,
        "repetitionSource":None,"cacheConfig":{"timeToLive":0,"scopeAttributeId":None,"strategy":"NO_CACHING"},
        "secret":False,"permissions":{"inherit":True,"rolePermissions":[]},
        "resolvers":[{"attributeResolverType":"request","condition":{"empty":{}},"valueProcessor":None,"name":None}],
        "querySettings":None,
        "valueProcessor":None,"properties":[]}

s,r=call("POST","/api/trust-framework/roots/ATTRIBUTE",attr("req_region"))
REQ=r.get("id") if isinstance(r,dict) else None
print("1 attr req_region:", s, REQ or r)
s,r=call("POST","/api/trust-framework/roots/ATTRIBUTE",attr("attested_regions"))
ATT=r.get("id") if isinstance(r,dict) else None
print("2 attr attested_regions:", s, ATT or r)
if not (REQ and ATT): raise SystemExit("attribute create failed")

# update the rule: applicable (and permit) only when attested_regions Contains req_region
s,rule=call("GET","/api/v2/policy-manager/rules/"+RULE)
print("3a get rule:", s, rule.get("name") if isinstance(rule,dict) else rule)
rule["condition"]={"comparison":{"left":{"attribute":{"id":ATT}},"op":"Contains","right":{"attribute":{"id":REQ}}}}
rule["effectSettings"]={"type":"unconditionalPermit"}
s,r=call("PUT","/api/v2/policy-manager/rules/"+RULE, rule)
print("3b put rule:", s, (r.get("version") if isinstance(r,dict) else r))

s,r=call("POST","/api/version-control/branches/%s/commit"%BRANCH_ID,{"message":"RAR containment: attested_regions Contains req_region"},branch=False)
print("4 commit:", s, r if isinstance(r,str) else r.get("id",r))

def probe(region):
    body={"domain":"idpartners.authorization_details.sales_agent","service":"Authorization","action":"authorize",
          "attributes":{"UserID":"https://rp.example.com","req_region":region,"attested_regions":"EMEA APAC"}}
    req=urllib.request.Request("https://localhost:8443/governance-engine",data=json.dumps(body).encode(),method="POST")
    req.add_header("CLIENT_TOKEN","2FederateM0re"); req.add_header("Content-Type","application/json")
    try:
        with urllib.request.urlopen(req,context=CTX,timeout=25) as rr:
            d=json.loads(rr.read().decode()); return f"{d.get('decision')} authorised={d.get('authorised')}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} {e.read().decode()[:200]}"

print("5 probe EMEA (within):", probe("EMEA"))
print("6 probe AMER (beyond):", probe("AMER"))
