#!/usr/bin/env python3
"""Phase 3: align policy to the plugin's flat dot-free mirrors (req_sales_regions / att_sales_regions).

The plugin (GovernanceEngineRequestBuilder) now emits, alongside the JSON attributes, flat scalars
req_<field> (requested) and att_<field> (union across the attested entitlement) — PingAuthorize attribute
names cannot contain '.', so the policy reads these directly. This creates the two attributes and points the
demo rule at `att_sales_regions Contains req_sales_regions`, then probes with the plugin's real request shape.

Run after 01-author-permit.py (creates rule 805ab29f inside policy 1c5385f3, which the PDP evaluates —
paz-compose.yml sets POLICY_NODE_ID to that policy for isolation from the stock AuthZen policies).
"""
import json, ssl, urllib.request, urllib.error
BASE="https://localhost:7443"; BRANCH="AuthZEN"; BRANCH_ID="58a67ffb-bd0d-4690-893e-45e35cb57baa"
RULE="805ab29f-147b-4a11-9a4d-9a8de072f0a6"; CTX=ssl._create_unverified_context()

def call(m,p,b=None,br=True):
    url=BASE+p+(("?branch="+BRANCH) if br else ""); data=json.dumps(b).encode() if b is not None else None
    r=urllib.request.Request(url,data=data,method=m); r.add_header("x-user-id","admin"); r.add_header("Content-Type","application/json")
    try:
        with urllib.request.urlopen(r,context=CTX,timeout=25) as x: t=x.read().decode(); return x.status,(json.loads(t) if t.strip() else {})
    except urllib.error.HTTPError as e: return e.code,e.read().decode()[:300]
    except Exception as e: return 0,str(e)

def attr(name):
    return {"objectType":"AttributeDefinition","type":"ATTRIBUTE","name":name,"fullName":name,
        "description":"RAR flat scalar from plugin","parentId":None,"valueType":"STRING","defaultValue":None,
        "repetitionSource":None,"cacheConfig":{"timeToLive":0,"scopeAttributeId":None,"strategy":"NO_CACHING"},
        "secret":False,"permissions":{"inherit":True,"rolePermissions":[]},
        "resolvers":[{"attributeResolverType":"request","condition":{"empty":{}},"valueProcessor":None,"name":None}],
        "querySettings":None,"valueProcessor":None,"properties":[]}

s,r=call("POST","/api/trust-framework/roots/ATTRIBUTE",attr("req_sales_regions")); REQ=r.get("id") if isinstance(r,dict) else None; print("req_sales_regions:",s,REQ)
s,r=call("POST","/api/trust-framework/roots/ATTRIBUTE",attr("att_sales_regions")); ATT=r.get("id") if isinstance(r,dict) else None; print("att_sales_regions:",s,ATT)
s,rule=call("GET","/api/v2/policy-manager/rules/"+RULE)
rule["condition"]={"comparison":{"left":{"attribute":{"id":ATT}},"op":"Contains","right":{"attribute":{"id":REQ}}}}
rule["effectSettings"]={"type":"unconditionalPermit"}
print("put rule:", call("PUT","/api/v2/policy-manager/rules/"+RULE,rule)[0])
print("commit:", call("POST","/api/version-control/branches/%s/commit"%BRANCH_ID,{"message":"RAR containment on plugin flat scalars"},br=False)[0])

ENT=[{"type":"sales_agent","actions":["read_accounts","create_opportunity","submit_quote"],"sales_regions":["EMEA","APAC"]}]
def plugin_request(regions):
    return {"domain":"idpartners.authorization_details.sales_agent","service":"Authorization","action":"authorize",
        "attributes":{"UserID":"https://rp.example.com","client_id":"https://rp.example.com",
            "idp.sales_agent.sales_regions":json.dumps(regions),"attestation.entitlement":json.dumps(ENT),
            "req_sales_regions":" ".join(regions),"att_sales_regions":"EMEA APAC"}}
def probe(regions):
    r=urllib.request.Request("https://localhost:8443/governance-engine",data=json.dumps(plugin_request(regions)).encode(),method="POST")
    r.add_header("CLIENT_TOKEN","2FederateM0re"); r.add_header("Content-Type","application/json")
    with urllib.request.urlopen(r,context=CTX,timeout=25) as x: d=json.loads(x.read().decode()); return f"{d.get('decision')} authorised={d.get('authorised')}"
print("PLUGIN-shape [EMEA] within :", probe(["EMEA"]))
print("PLUGIN-shape [AMER] beyond :", probe(["AMER"]))
print("PLUGIN-shape [APAC] within :", probe(["APAC"]))
