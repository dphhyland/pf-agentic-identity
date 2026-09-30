#!/usr/bin/env python3
"""Authors the RAR processor's reference PingAuthorize policies from the files in policies/, on a branch of their own.

    PAZ_PAP_URL=https://localhost:7443 python3 author-policies.py [--branch RAR-reference] [--replace]

Reads policies/trust-framework.json (the domains and request attributes the policies use, and any attribute derived
from one of them by a SpEL expression) and every
policies/<type>.json (one policy per authorization_details type), and creates, through the Policy Editor's REST API
on a new branch: the Trust Framework entries, each policy's statements and rules, the policy, and one policy set,
"RAR reference policies", that holds the three - the decision node the PDP, and decision-tests.py, evaluate. Then it
commits the branch and prints the branch and the decision node's id.

A policy file is data, not code: "when" is {"all": [...]} or {"any": [...]} over comparisons written
[attribute, operator, value], where value is a constant or {"attribute": name} and the operator is the Policy
Editor's (Equals, NotEquals, RegularExpression - a whole-value match - LesserThanOrEqual, ...); a rule's "statements" are
{name, payload} pairs, sent back with a permit so the processor applies each payload at the detail member the name
gives (StatementApplier). Each policy applies to its own domain (<PDP Domain Prefix>.<type>) only.

--replace deletes a branch of the same name first. No secret is needed to author: see paz_client.py.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paz_client import Pap  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
POLICIES = HERE / "policies"
TYPES = ("sales_agent", "payment_initiation", "account_information")
POLICY_SET = "RAR reference policies"
PERMISSIONS = {"inherit": True, "rolePermissions": []}


def load(name):
    with open(POLICIES / name, encoding="utf-8") as handle:
        return json.load(handle)


def create_branch(pap, name, replace):
    for branch in pap.call("GET", "/api/version-control/branches", branch=False).get("data", []):
        if branch["name"] == name:
            if not replace:
                sys.exit(f"branch {name} exists: pass --replace to delete it first, or --branch another name")
            pap.call("DELETE", "/api/version-control/branches/" + branch["id"], branch=False)
    root = pap.call("GET", "/api/version-control/snapshots/root", branch=False)["id"]
    pap.call("POST", f"/api/version-control/snapshots/{root}/branch", {"name": name}, branch=False)
    for branch in pap.call("GET", "/api/version-control/branches", branch=False).get("data", []):
        if branch["name"] == name:
            return branch["id"]
    sys.exit(f"branch {name} was not created")


def definition(kind, name, description, extra):
    body = {"type": kind, "name": name, "description": description, "parentId": None, "permissions": PERMISSIONS,
            "properties": []}
    body.update(extra)
    return body


def define_paths(pap, kind, entries, extra_of):
    """Creates each dotted name's parents, then the name itself; answers every full name's id."""
    ids = {}
    for full_name, description, leaf in entries:
        parts = full_name.split(".")
        for depth in range(1, len(parts) + 1):
            path = ".".join(parts[:depth])
            if path in ids:
                continue
            is_leaf = depth == len(parts)
            body = definition(kind, parts[depth - 1], description if is_leaf else "",
                              extra_of(leaf if is_leaf else None, ids))
            parent = ids.get(".".join(parts[:depth - 1]))
            created = pap.call("POST", "/api/trust-framework/" + (parent if parent else "roots/" + kind), body)
            ids[path] = created["id"]
    return ids


def attribute_extra(leaf, ids):
    """An attribute read from the request by its name, or, when the file gives "from" and "spel", derived from an
    attribute defined before it by a SpEL expression over its value (#this)."""
    leaf = leaf or {}
    value_type = leaf.get("type", "STRING")
    resolver = {"attributeResolverType": "request", "condition": {"empty": {}}, "valueProcessor": None, "name": None}
    if "from" in leaf:
        if leaf["from"] not in ids:
            sys.exit(f"attribute {leaf['name']} is derived from {leaf['from']}, which trust-framework.json must list first")
        resolver = {"attributeResolverType": "attribute", "id": ids[leaf["from"]], "condition": {"empty": {}},
                    "valueProcessor": {"type": "spel", "expression": leaf["spel"], "valueType": value_type,
                                       "name": None},
                    "name": None}
    return {"objectType": "AttributeDefinition", "valueType": value_type, "defaultValue": None, "repetitionSource": None,
            "cacheConfig": {"timeToLive": 0, "scopeAttributeId": None, "strategy": "NO_CACHING"}, "secret": False,
            "resolvers": [resolver], "querySettings": None, "valueProcessor": None}


def condition(when, attributes):
    """A policy file's condition as the Policy Editor's condition tree."""
    if isinstance(when, dict):
        (kind, items), = when.items()
        if kind not in ("all", "any"):
            sys.exit(f"a condition is all, any or a comparison, not {kind}")
        return {"and" if kind == "all" else "or": {"conditions": [condition(item, attributes) for item in items]}}
    name, op, value = when
    right = ({"attribute": {"id": attributes[value["attribute"]]}} if isinstance(value, dict)
             else {"constant": {"value": str(value)}})
    return {"comparison": {"left": {"attribute": {"id": attributes[name]}}, "op": op, "right": right}}


def author_policy(pap, policy, attributes, domains):
    rule_ids = []
    for rule in policy["rules"]:
        statement_ids = []
        for statement in rule.get("statements", []):
            created = pap.call("POST", "/api/v2/policy-manager/statements", {
                "type": "Statement", "name": statement["name"], "description": rule["name"], "shared": False,
                "code": "rar-narrow", "appliesTo": "PERMIT", "appliesIf": "FINAL_DECISION_MATCHES",
                "payload": json.dumps(statement["payload"], separators=(",", ":")), "obligatory": False,
                "permissions": PERMISSIONS, "attributes": [], "services": []})
            statement_ids.append(created["id"])
        created = pap.call("POST", "/api/v2/policy-manager/rules", {
            "type": "Rule", "name": rule["name"], "description": rule.get("description", ""), "shared": False,
            "disabled": False, "permissions": PERMISSIONS, "statements": statement_ids, "targets": [],
            "effectSettings": {"type": "unconditionalPermit"}, "condition": condition(rule["when"], attributes),
            "properties": []})
        rule_ids.append(created["id"])
    created = pap.call("POST", "/api/v2/policy-manager/policies", {
        "type": "Policy", "name": policy["name"], "description": policy["description"], "shared": False,
        "disabled": False, "combiningAlgorithm": {"algorithm": policy["combining"]},
        "children": [{"id": rule_id, "type": "Rule"} for rule_id in rule_ids], "repetitionSettings": None,
        "permissions": PERMISSIONS, "statements": [], "targets": [], "properties": [],
        "condition": {"comparison": {"left": {"requestAxis": {"type": "DOMAIN"}}, "op": "Matches",
                                     "right": {"definition": {"id": domains[policy["domain"]]}}}}})
    return created["id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--branch", default="RAR-reference")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()

    framework = load("trust-framework.json")
    pap = Pap(branch=args.branch)
    branch_id = create_branch(pap, args.branch, args.replace)
    domains = define_paths(pap, "DOMAIN", [(name, "", None) for name in framework["domains"]],
                           lambda leaf, ids: {"objectType": "DomainDefinition"})
    attributes = define_paths(pap, "ATTRIBUTE", [(a["name"], a["description"], a) for a in framework["attributes"]],
                              attribute_extra)
    policy_ids = [author_policy(pap, load(t + ".json"), attributes, domains) for t in TYPES]
    policy_set = pap.call("POST", "/api/v2/policy-manager/policysets", {
        "type": "PolicySet", "name": POLICY_SET,
        "description": "The RAR processor's reference policies, one per built-in type (plugins/rar-paz-plugin/paz/policies)",
        "shared": False, "disabled": False, "combiningAlgorithm": {"algorithm": "DenyUnlessPermit"},
        "children": [{"id": policy_id, "type": "Policy"} for policy_id in policy_ids], "permissions": PERMISSIONS,
        "statements": [], "targets": [], "condition": {"empty": {}}, "properties": []})
    pap.call("POST", f"/api/version-control/branches/{branch_id}/commit",
             {"message": "The RAR processor's reference policies, from plugins/rar-paz-plugin/paz/policies"}, branch=False)
    print(json.dumps({"branch": args.branch, "decision_node": policy_set["id"]}))


if __name__ == "__main__":
    main()
