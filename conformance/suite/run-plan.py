#!/usr/bin/env python3
"""Run a conformance-suite test plan over the suite's REST API and report each module's result.

    run-plan.py <suite-base-url> <plan-name> <config.json> [--variant k=v ...] [--only glob ...]
                [--on-log-marker TEXT --hook CMD]

For a suite you run yourself in dev mode, which needs no login. The hosted suite at
certification.openid.net needs a signed-in browser session instead, and the run that counts for a
certification is made there, by a person; this is for getting to green before that.

Exit status is 0 only if every module that ran finished PASSED, WARNING, REVIEW or SKIPPED - the
results a certification run tolerates. It prints each FAILURE's condition and message, because "FAILED"
alone sends you to a web UI to find out what you could have been told.

Some modules wait for the transmitter's operator to do something - the CAEP Interop module logs
"Please trigger these events on the transmitter now" and gives sixty seconds. --on-log-marker TEXT
--hook CMD watches the running module's log for TEXT and runs CMD (a shell command) once when it
appears, with EXPECTED_CAEP_EVENT_TYPES in its environment when the log entry names them.
"""
import argparse
import fnmatch
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The suite you run yourself serves a self-signed certificate on localhost.
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

TOLERATED = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}


def call(method, url, params=None, body=None):
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method, data=body.encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:600]}


def wait_for(base, module_id, states, timeout, marker=None, hook=None):
    deadline = time.time() + timeout
    fired = False
    while time.time() < deadline:
        _, info = call("GET", f"{base}/api/info/{module_id}")
        if info and info.get("status") in states | {"INTERRUPTED"}:
            return info
        if marker and hook and not fired:
            fired = fire_hook_on_marker(base, module_id, marker, hook)
        time.sleep(1.5)
    return info or {}


def fire_hook_on_marker(base, module_id, marker, hook):
    """Run the hook once the module's log carries the marker. True once it has run (or was tried)."""
    _, log = call("GET", f"{base}/api/log/{module_id}")
    for entry in log or []:
        if marker in (entry.get("msg") or ""):
            env = dict(os.environ)
            expected = entry.get("expected_caep_event_types")
            if expected:
                env["EXPECTED_CAEP_EVENT_TYPES"] = ",".join(expected) if isinstance(expected, list) else str(expected)
            print(f"            hook: {hook}")
            rc = subprocess.call(hook, shell=True, env=env)
            print(f"            hook exit {rc}")
            return True
    return False


def failures(base, module_id):
    _, log = call("GET", f"{base}/api/log/{module_id}")
    out = []
    for entry in log or []:
        if entry.get("result") in ("FAILURE", "WARNING"):
            out.append((entry["result"], entry.get("src", "?"), (entry.get("msg") or "").replace("\n", " ")[:260]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("plan")
    ap.add_argument("config")
    ap.add_argument("--variant", nargs="*", default=[], metavar="k=v")
    ap.add_argument("--only", nargs="*", default=[], metavar="GLOB", help="run only modules whose name matches")
    ap.add_argument("--timeout", type=int, default=420, help="seconds to allow one module")
    ap.add_argument("--on-log-marker", default=None, metavar="TEXT", help="log text that means the module is waiting for the operator")
    ap.add_argument("--hook", default=None, metavar="CMD", help="shell command to run once when the marker appears")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    variant = dict(v.split("=", 1) for v in args.variant)

    status, plan = call("POST", f"{base}/api/plan", {"planName": args.plan, "variant": json.dumps(variant)},
                        open(args.config).read())
    if status != 201:
        sys.exit(f"could not create the plan: HTTP {status} {plan}")
    print(f"plan {plan['id']}  {base}/plan-detail.html?plan={plan['id']}")

    results = {}
    for module in plan["modules"]:
        name = module["testModule"]
        if args.only and not any(fnmatch.fnmatch(name, g) for g in args.only):
            continue
        params = {"test": name, "plan": plan["id"]}
        if module.get("variant"):
            params["variant"] = json.dumps(module["variant"])
        status, created = call("POST", f"{base}/api/runner", params)
        if status != 201:
            results[name] = "NOT-CREATED"
            print(f"{'NOT-CREATED':<11} {name}  HTTP {status} {created}")
            continue
        info = wait_for(base, created["id"], {"CONFIGURED", "WAITING", "FINISHED"}, 90)
        if info.get("status") == "CONFIGURED":
            call("POST", f"{base}/api/runner/{created['id']}")
        info = wait_for(base, created["id"], {"FINISHED"}, args.timeout, args.on_log_marker, args.hook)
        result = info.get("result") or f"({info.get('status', 'NO-STATUS')})"
        results[name] = result
        print(f"{result:<11} {name}  {base}/log-detail.html?log={created['id']}")
        if result not in ("PASSED", "SKIPPED"):
            for level, src, msg in failures(base, created["id"]):
                print(f"            {level:<8} {src}: {msg}")

    counts = {}
    for r in results.values():
        counts[r] = counts.get(r, 0) + 1
    print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())) + f"  (of {len(results)})")
    sys.exit(0 if all(r in TOLERATED for r in results.values()) else 1)


if __name__ == "__main__":
    main()
