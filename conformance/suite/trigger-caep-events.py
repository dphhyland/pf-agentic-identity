#!/usr/bin/env python3
"""Raise the three CAEP Interop events on the rig, the way an operator would.

    trigger-caep-events.py [--base https://host:port] [--subject email] [--stream-id ID]

The openid-ssf-transmitter-caep-test-plan creates a stream, verifies it, then logs "Please trigger
these events on the transmitter now" and waits sixty seconds for a session-revoked, a credential-change
and a device-compliance-change. PingFederate observes only the first, and only when a real session
ends; this script raises all three through POST /ssf/events:emit, which is what that endpoint is for.
run-plan.py runs it as a --hook when it sees that log line.

The token is a client-credentials grant for conformance-ssf-emitter, the one client holding
ssf.provision; its secret is read from ../secrets.env (TF_VAR_ssf_emitter_client_secret), never from
the command line. Exit status is 0 only if every event reached at least one stream.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RIG = os.path.dirname(HERE)
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"

# PingFederate's certificate on the rig is self-signed; the suite does not check it either.
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

EVENTS = [
    (CAEP + "session-revoked", {"reason_admin": "conformance run: session revoked by an administrator"}),
    (CAEP + "credential-change", {"credential_type": "password", "change_type": "update",
                                  "reason_admin": "conformance run: password rotated"}),
    (CAEP + "device-compliance-change", {"previous_status": "compliant", "current_status": "not-compliant",
                                         "reason_admin": "conformance run: disk encryption disabled"}),
]


def base_url():
    for line in open(os.path.join(RIG, "terraform", "variables.tf")):
        if line.strip().startswith('default     = "https:'):
            return line.split('"')[1]
    sys.exit("could not read pf_base_url from terraform/variables.tf")


def secret():
    for line in open(os.path.join(RIG, "secrets.env")):
        if line.startswith("TF_VAR_ssf_emitter_client_secret="):
            return line.strip().split("=", 1)[1]
    sys.exit("no TF_VAR_ssf_emitter_client_secret in secrets.env - run ./gen-keys.sh, then re-apply and re-export")


def post(url, body, headers):
    req = urllib.request.Request(url, method="POST", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:400]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=None, help="the rig's origin (default: terraform's pf_base_url)")
    ap.add_argument("--subject", default="example.user@example.com", help="email of the subject the events are about")
    ap.add_argument("--stream-id", default=None, help="raise to this stream only (default: every subscribing stream)")
    args = ap.parse_args()
    base = (args.base or base_url()).rstrip("/")

    basic = base64.b64encode(f"conformance-ssf-emitter:{secret()}".encode()).decode()
    status, token = post(f"{base}/as/token.oauth2",
                         urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "ssf.provision"}).encode(),
                         {"Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded"})
    if status != 200 or "access_token" not in token:
        sys.exit(f"token request failed: HTTP {status} {token}")

    ok = True
    for event_type, event in EVENTS:
        body = {"event_type": event_type, "subject": {"format": "email", "email": args.subject}, "event": event}
        if args.stream_id:
            body["stream_id"] = args.stream_id
        status, answer = post(f"{base}/ssf/events:emit", json.dumps(body).encode(),
                              {"Authorization": "Bearer " + token["access_token"], "Content-Type": "application/json"})
        count = answer.get("count", 0) if status == 200 else 0
        print(f"{'ok' if count else 'NO':<3} {event_type.rsplit('/', 1)[1]:<26} HTTP {status}  streams={count}"
              + ("" if status == 200 else f"  {answer}"))
        ok = ok and count > 0
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
