"""Offline functional smoke test for deploy/cross-cloud-chain/azure/agent_d.py.

Stands up a fake Azure attester (mint + challenge + discovery), a fake foreign AS token endpoint that
performs a real-shaped RFC 8693 exchange (nesting the act chain one deeper), and a fake resource that
reports what it received. Then drives agent D over real HTTP exactly the way agent C would, and checks:

  1. D accepts C's call shape verbatim (Bearer + payment body) — the transparent-interposer property.
  2. D uses the AKS projected-token file when present (evidence_mode aks-sa-token).
  3. D falls through to Azure IMDS when there is no token file (evidence_mode azure-mi-token),
     extracting access_token from IMDS's JSON envelope.
  4. Without an asserted oid, no asserted_context is sent on the mint.
  5. With one (header, and env default), asserted_context IS sent and the attester's narrowing is
     reflected in the trace.
  6. The act chain that reaches the resource nests D over the chain it was handed ({D,{C,{B,{A}}}}).
  7. D forwards the request body unchanged and passes the resource's response through, with its own
     hop merged into trace.
  8. A call with no Bearer is refused 401.
"""
import base64
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRATCH = tempfile.mkdtemp(prefix="agent-d-test-")

DIRECTORY = {"d7c5a2b1-0000-4000-8000-copilot0demo": [
    {"type": "account_information", "actions": ["read"]}]}
FULL_CEILING = [{"type": "account_information", "actions": ["read"]},
                {"type": "payment_initiation", "actions": ["initiate"]}]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt_of(claims: dict) -> str:
    return (b64url(json.dumps({"alg": "none"}).encode()) + "." +
            b64url(json.dumps(claims).encode()) + ".sig")


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class Fakes(BaseHTTPRequestHandler):
    """One handler playing the attester, the foreign AS and the resource, on one port."""

    mints = []
    exchanges = []
    resource_calls = []

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = "http://" + self.headers["Host"]
        if self.path.startswith("/.well-known/client-attester"):
            return self._json(200, {
                "attestation_endpoint": base + "/federation/attestation",
                "challenge_endpoint": base + "/federation/attestation-challenge",
                "token_endpoint": base + "/as/token.oauth2",
                "evidence_audience": "https://attester.example.com",
                "pop_audience": "https://az.pf.example",
            })
        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"

        if self.path.endswith("/attestation-challenge"):
            return self._json(200, {"attestation_challenge": "chal-1", "expires_in": 300})

        if self.path.endswith("/federation/attestation"):
            body = json.loads(raw)
            type(self).mints.append(body)
            asserted = body.get("asserted_context")
            workload = {"attested_by": "spiffe",
                        "spiffe_id": "spiffe://aks.demo.azure/ns/demo/sa/chain-agent-d"}
            ceiling = FULL_CEILING
            if asserted:
                oid = asserted["value"]
                if oid not in DIRECTORY:
                    return self._json(403, {"error": "access_denied",
                                            "error_description": "oid not in directory"})
                # Narrow, never extend — the intersection of the evidenced ceiling and the entry's.
                allowed = {e["type"] for e in DIRECTORY[oid]}
                ceiling = [e for e in FULL_CEILING if e["type"] in allowed]
                workload["attributes"] = {"asserted": {
                    "type": "entra-copilot-agent-oid", "oid": oid, "groups": ["copilot-bridge-users"]}}
            return self._json(200, {"attestation": jwt_of({
                "sub": "demo-attest-aks-chain", "workload": workload,
                "authorization_details": ceiling}), "expires_in": 300})

        if self.path.endswith("/as/token.oauth2"):
            if not self.headers.get("OAuth-Client-Attestation") \
                    or not self.headers.get("OAuth-Client-Attestation-PoP"):
                return self._json(401, {"error": "invalid_client"})
            form = dict(pair.split("=", 1) for pair in raw.decode().split("&"))
            subject = urllib.parse.unquote(form.get("subject_token", ""))
            type(self).exchanges.append(form)
            incoming = claims_of(subject)
            # Nest the act chain one deeper under this agent, the way a real AS does.
            issued = {"iss": "https://az.pf.example", "sub": incoming.get("sub"),
                      "client_id": "demo-attest-aks-chain",
                      "act": {"sub": "demo-attest-aks-chain", "act": incoming.get("act")},
                      "exp": int(time.time()) + 300}
            return self._json(200, {"access_token": jwt_of(issued), "expires_in": 300,
                                    "token_type": "Bearer"})

        if self.path.endswith("/settle"):
            authorization = self.headers.get("Authorization", "")
            claims = claims_of(authorization[7:]) if authorization.startswith("Bearer ") else {}
            chain, node = [], claims.get("act")
            while isinstance(node, dict):
                chain.append({"sub": node.get("sub")})
                node = node.get("act")
            payload = json.loads(raw or b"{}")
            type(self).resource_calls.append({"claims": claims, "body": payload})
            return self._json(200, {"on_behalf_of": claims.get("sub"), "actor_chain": chain,
                                    "decision": {"allowed": True, "decided_by": "fake"},
                                    "settled": {"reference": "MOCK-1", **payload}})

        return self._json(404, {"error": "not_found"})



def post(url, body, headers):
    data = json.dumps(body).encode()
    request = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def start_agent_d(env_extra: dict, fakes_url: str):
    """Import agent_d fresh with the given env, and serve it on an ephemeral port."""
    for key in ("ATTESTER_BASE_URL", "EXCHANGE_BASE_URL", "NEXT_HOP_URL", "TOKEN_FILE",
                "ASSERTED_COPILOT_AGENT_ID", "AZURE_CLIENT_ID"):
        os.environ.pop(key, None)
    os.environ.update({"ATTESTER_BASE_URL": fakes_url, "EXCHANGE_BASE_URL": fakes_url,
                       "NEXT_HOP_URL": fakes_url + "/settle", **env_extra})
    sys.modules.pop("agent_d", None)
    import agent_d  # noqa: PLC0415
    server = ThreadingHTTPServer(("127.0.0.1", 0), agent_d.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


FAILS = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def main():
    sys.path.insert(0, AGENT_DIR)
    fakes = ThreadingHTTPServer(("127.0.0.1", 0), Fakes)
    threading.Thread(target=fakes.serve_forever, daemon=True).start()
    fakes_url = f"http://127.0.0.1:{fakes.server_address[1]}"

    # The token agent C would hand over: sub=A, act={C,{B,{A}}} — three deep already.
    token_from_c = jwt_of({"iss": "https://eks.pf.example", "sub": "spiffe://gke/ns/demo/sa/payment-agent",
                           "client_id": "demo-attest-gke-delivery",
                           "act": {"sub": "demo-attest-gke-delivery",
                                   "act": {"sub": "demo-attest-agentcore",
                                           "act": {"sub": "demo-attest-gke-native"}}}})
    body = {"amount": 250, "currency": "AUD"}
    bearer = {"Authorization": "Bearer " + token_from_c}

    # ── 1. AKS evidence path, no asserted context ────────────────────────────────────────────────
    print("1) AKS projected-token evidence, no asserted context")
    token_file = os.path.join(SCRATCH, "fake-aks-token")
    with open(token_file, "w") as handle:
        handle.write("fake-aks-projected-sa-token\n")
    Fakes.mints, Fakes.exchanges, Fakes.resource_calls = [], [], []
    server, agent_url = start_agent_d({"TOKEN_FILE": token_file}, fakes_url)
    status, response = post(agent_url + "/settle", body, bearer)
    check("accepts C's Bearer+body call shape", status == 200, str(status))
    trace = (response.get("trace") or [{}])[0]
    check("evidence_mode is aks-sa-token", trace.get("evidence_mode") == "aks-sa-token",
          str(trace.get("evidence_mode")))
    check("read the projected token file", Fakes.mints[0]["svid"] == "fake-aks-projected-sa-token")
    check("no asserted_context on the mint", "asserted_context" not in Fakes.mints[0])
    check("full evidenced ceiling attested (2 entries)",
          len(trace.get("attested_authorization_details") or []) == 2)
    check("resource got the body unchanged", Fakes.resource_calls[0]["body"] == body)
    chain = [a["sub"] for a in response.get("actor_chain", [])]
    check("act chain nests D over C,B,A (4 deep)",
          chain == ["demo-attest-aks-chain", "demo-attest-gke-delivery",
                    "demo-attest-agentcore", "demo-attest-gke-native"], str(chain))
    check("sub (the originating workload) preserved",
          response.get("on_behalf_of") == "spiffe://gke/ns/demo/sa/payment-agent")
    check("resource response passed through", (response.get("settled") or {}).get("reference") == "MOCK-1")
    server.shutdown()

    # ── 2. asserted oid via header → narrowing ───────────────────────────────────────────────────
    print("\n2) asserted Entra Agent ID via X-Copilot-Agent-Id header → ceiling narrowed")
    Fakes.mints, Fakes.exchanges, Fakes.resource_calls = [], [], []
    server, agent_url = start_agent_d({"TOKEN_FILE": token_file}, fakes_url)
    oid = "d7c5a2b1-0000-4000-8000-copilot0demo"
    status, response = post(agent_url + "/settle", body,
                            {**bearer, "X-Copilot-Agent-Id": oid})
    check("still 200", status == 200, str(status))
    check("asserted_context sent on the mint",
          Fakes.mints[0].get("asserted_context") == {"type": "entra-copilot-agent-oid", "value": oid})
    trace = (response.get("trace") or [{}])[0]
    check("trace records the asserted oid", trace.get("asserted_copilot_agent_id") == oid)
    check("attester's asserted block surfaced",
          (trace.get("asserted_by_attester") or {}).get("oid") == oid)
    narrowed = trace.get("attested_authorization_details") or []
    check("ceiling NARROWED to the directory entry (1 entry, accounts only)",
          len(narrowed) == 1 and narrowed[0]["type"] == "account_information", str(narrowed))
    server.shutdown()

    # ── 3. asserted oid via env default ──────────────────────────────────────────────────────────
    print("\n3) asserted Entra Agent ID via ASSERTED_COPILOT_AGENT_ID env default")
    Fakes.mints, Fakes.exchanges, Fakes.resource_calls = [], [], []
    server, agent_url = start_agent_d(
        {"TOKEN_FILE": token_file, "ASSERTED_COPILOT_AGENT_ID": oid}, fakes_url)
    status, response = post(agent_url + "/settle", body, bearer)
    check("env default applied without a header", status == 200
          and Fakes.mints[0].get("asserted_context", {}).get("value") == oid)
    server.shutdown()

    # ── 4. unknown oid → the attester refuses, D surfaces it ─────────────────────────────────────
    print("\n4) unknown asserted oid → refused")
    Fakes.mints, Fakes.exchanges, Fakes.resource_calls = [], [], []
    server, agent_url = start_agent_d({"TOKEN_FILE": token_file}, fakes_url)
    status, response = post(agent_url + "/settle", body,
                            {**bearer, "X-Copilot-Agent-Id": "ffffffff-not-registered"})
    check("mint refusal surfaced, not swallowed", status == 502 and response.get("ok") is False,
          f"{status} {response}")
    check("no exchange attempted after the refusal", len(Fakes.exchanges) == 0)
    server.shutdown()

    # ── 5. IMDS fallback when there is no token file ─────────────────────────────────────────────
    print("\n5) no projected token file → Azure IMDS fallback (JSON envelope)")
    Fakes.mints, Fakes.exchanges, Fakes.resource_calls = [], [], []
    server, agent_url = start_agent_d(
        {"TOKEN_FILE": os.path.join(SCRATCH, "does-not-exist")}, fakes_url)
    import agent_d  # noqa: PLC0415  (the instance just imported by start_agent_d)
    agent_d.AZURE_IMDS_TOKEN = fakes_url + "/imds"
    original_http = agent_d.http

    def fake_http(method, url, **kwargs):
        # Stand in for IMDS: assert the contract (Metadata header, resource param) and return the
        # JSON envelope shape — the one place Azure differs from GCP's raw-JWT metadata response.
        if url.startswith(fakes_url + "/imds"):
            assert (kwargs.get("headers") or {}).get("Metadata") == "true", "IMDS needs Metadata: true"
            assert "resource=" in url, "IMDS needs the resource (audience) param"
            return 200, json.dumps({"access_token": "fake-azure-mi-token", "token_type": "Bearer",
                                    "expires_on": "1700000000"})
        return original_http(method, url, **kwargs)

    agent_d.http = fake_http
    status, response = post(agent_url + "/settle", body, bearer)
    agent_d.http = original_http
    trace = (response.get("trace") or [{}])[0]
    check("evidence_mode is azure-mi-token", trace.get("evidence_mode") == "azure-mi-token",
          str(trace.get("evidence_mode")))
    check("access_token extracted from the JSON envelope",
          Fakes.mints and Fakes.mints[0]["svid"] == "fake-azure-mi-token",
          str(Fakes.mints[:1]))
    server.shutdown()

    # ── 6. no bearer → 401 ───────────────────────────────────────────────────────────────────────
    print("\n6) no bearer token → 401")
    server, agent_url = start_agent_d({"TOKEN_FILE": token_file}, fakes_url)
    status, response = post(agent_url + "/settle", body, {})
    check("refused without a bearer", status == 401, str(status))
    server.shutdown()

    print()
    print("ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} FAILURE(S): {FAILS}")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
