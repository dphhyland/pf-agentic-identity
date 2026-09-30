#!/usr/bin/env python3
"""Runs the reference policies' decision tests (policies/<type>.cases.json) against a PingAuthorize Policy Editor.

    PAZ_PAP_URL=https://localhost:7443 PAZ_DECISION_SECRET_FILE=... python3 decision-tests.py [--branch RAR-reference]

Each case is the governance-engine request the RAR processor sends for one detail (GovernanceEngineRequestBuilder:
the domain <PDP Domain Prefix>.<type>, service Authorization, action authorize, and the request's attributes), sent
to the Policy Editor's decision endpoint on the branch author-policies.py wrote, with the decision node found by the
policy set's name. The answer's decision must be the one the case expects, and its statements - name and payload,
the payload read as JSON - exactly the case's. Every case is a permit, a deny or a narrowing (a permit whose
statement narrows a member of the detail). Exit 0 when every case passes, 1 otherwise.

The decision endpoint needs the decision point shared secret, from PAZ_DECISION_SECRET or PAZ_DECISION_SECRET_FILE:
there is no default (see paz_client.py).
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paz_client import Pap, decision_secret  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
TYPES = ("sales_agent", "payment_initiation", "account_information")
POLICY_SET = "RAR reference policies"
DOMAIN_PREFIX = "idpartners.authorization_details"


def decision_node(pap):
    """The id of the policy set author-policies.py created on the branch."""
    tree = pap.call("GET", "/api/v2/policy-manager/tree")
    for node in tree.get("data", []):
        if node.get("name") == POLICY_SET:
            return node["id"]
    sys.exit(f"no policy set named {POLICY_SET!r} on branch {pap.branch}: run author-policies.py first")


def statements_of(answer):
    """The answer's statements as {name, payload}, a JSON payload read."""
    out = []
    for statement in answer.get("statements") or []:
        payload = statement.get("payload")
        try:
            payload = json.loads(payload) if isinstance(payload, str) else payload
        except ValueError:
            pass
        out.append({"name": statement.get("name"), "payload": payload})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--branch", default="RAR-reference")
    args = parser.parse_args()
    secret = decision_secret()
    pap = Pap(branch=args.branch)
    node = decision_node(pap)
    failures = 0
    for type_ in TYPES:
        with open(HERE / "policies" / (type_ + ".cases.json"), encoding="utf-8") as handle:
            cases = json.load(handle)["cases"]
        for case in cases:
            answer = pap.decide(secret, node, {"domain": DOMAIN_PREFIX + "." + type_, "service": "Authorization",
                                               "action": "authorize", "attributes": case["attributes"]})
            got = {"decision": answer.get("decision"), "statements": statements_of(answer)}
            ok = got == case["expect"]
            failures += 0 if ok else 1
            print(("pass" if ok else "FAIL") + f"  {type_}: {case['name']}"
                  + ("" if ok else f"\n      expected {json.dumps(case['expect'])}\n      got      {json.dumps(got)}"))
    print(f"{failures} of the cases failed" if failures else "every case passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
