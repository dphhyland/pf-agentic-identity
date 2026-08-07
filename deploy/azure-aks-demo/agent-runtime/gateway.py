"""Azure-hosted A2A gateway: bootstraps ITS OWN identity into PingFederate via evidence-first client
attestation, and (optionally) narrows its ceiling by an asserted Entra Agent ID directory lookup.

The evidence-first chain (discover -> evidence -> proof -> attestation -> PoP -> token) is exactly what
every workload in this rig runs — see agentcore/agent.py for the AWS leg's hand-rolled version of the same
chain. This gateway uses the client-attestation-sdk-polyglot package instead of hand-rolling it, because it
needs the SDK's asserted_context support (client_attestation_sdk >= the version landed alongside this
demo): a caller-supplied, UNVERIFIED discriminator — an Entra Agent ID `oid` — that an opted-in attestation
client resolves against a directory (EntraDirectoryAssertedContextResolver, servlets/attestation-issuer) to
NARROW (never extend) the gateway's own evidenced ceiling.

Why this gateway exists at all, and what it is NOT: Copilot Studio agents share one Microsoft-owned
blueprint per tenant, so an individual Copilot agent has no cryptographic evidence of its own — only the
WORKLOAD HOSTING this gateway (an AKS pod via Workload Identity Federation, or an Azure-managed-identity
compute) has real, evidenceable identity. That evidenced identity is this gateway's own attested identity,
full stop — the same "opaque hosting-platform identity" pattern AgentCore and Agent Engine use elsewhere in
this rig (fall back to the hosting workload's own credential; don't try to model the platform's own
directory-of-agents concept in the evidence layer). The Copilot Studio agent's identity is carried
separately, as the ASSERTED (never cryptographically verified) `copilot_agent_id` on an inbound A2A
message — evidence and assertion are always kept distinguishable in the resulting token's workload claim.

A2A (Agent2Agent — JSON-RPC `message/send`, discovered via an Agent Card) is new to this repo; every other
cross-agent hop here uses plain HTTP+Bearer (see deploy/cross-cloud-chain/). It is the protocol Copilot
Studio (and A2A-speaking callers generally) actually use to invoke an agent, so it is what fronts this one.
"""
from __future__ import annotations

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from client_attestation_sdk import ClientAttestation, ClientAttestationError

ATTESTER_BASE_URL = os.environ["ATTESTER_BASE_URL"].rstrip("/")
PORT = int(os.environ.get("PORT", "8080"))
PUBLIC_URL = os.environ.get("PUBLIC_URL", "")

# One long-lived ClientAttestation: evidence is auto-detected (AKS projected-token file, or Azure IMDS —
# see client_attestation_sdk.evidence.auto_detect_evidence()), so no cloud-specific code lives here.
_CA = ClientAttestation(ATTESTER_BASE_URL)


def _decode_unverified(token: str) -> dict:
    """Decode a compact JWT's payload WITHOUT verifying — for surfacing claims in the A2A response only.
    The relying party downstream of this gateway verifies the token itself; this is display, not trust."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _agent_card(base_url: str) -> dict:
    return {
        "protocolVersion": "0.2.0",
        "name": "Azure Attestation Gateway",
        "description": ("Bootstraps this Azure-hosted workload into PingFederate via evidence-first client "
                        "attestation (AKS Workload Identity Federation, or Azure managed identity), "
                        "optionally narrowing its ceiling by an asserted Entra Agent ID directory lookup."),
        "url": base_url.rstrip("/") + "/a2a",
        "preferredTransport": "JSONRPC",
        "provider": {"organization": "pf-agentic-identity demo"},
        "version": "0.1.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [{
            "id": "attest",
            "name": "attest",
            "description": ("Mint an attested PingFederate access token for this workload's own evidenced "
                            "identity, optionally scoped to an asserted Entra Agent ID."),
            "tags": ["attestation", "azure", "entra"],
        }],
        "securitySchemes": {},
        "security": [],
    }


def _asserted_context_from_metadata(metadata: dict) -> dict | None:
    """An inbound A2A message's metadata may carry `copilot_agent_id` — the ASSERTED (unverified) Entra
    Agent ID `oid` of the logical Copilot Studio agent behind this call. Absent is fine: the gateway then
    presents only its own evidenced identity (no directory narrowing) — a direct call with no upstream
    Copilot Studio context still works, just with the gateway's own (broader) ceiling."""
    oid = (metadata or {}).get("copilot_agent_id")
    if not oid:
        return None
    return {"type": "entra-copilot-agent-oid", "value": oid}


def _handle_message_send(params: dict) -> tuple[dict, dict]:
    message = (params or {}).get("message") or {}
    metadata = message.get("metadata") or {}
    asserted = _asserted_context_from_metadata(metadata)
    try:
        token = _CA.token(asserted_context=asserted) if asserted else _CA.token()
    except ClientAttestationError as exc:
        error_message = {"role": "agent", "parts": [{"kind": "data", "data": {
            "error": "attestation_failed", "detail": str(exc)}}]}
        return error_message, {"attested": False}

    claims = _decode_unverified(token)
    data = {
        "attested": True,
        "sub": claims.get("sub"),
        "workload": claims.get("workload"),
        "authorization_details": claims.get("authorization_details"),
        "asserted_context": asserted,
    }
    result_message = {"role": "agent", "parts": [{"kind": "data", "data": data}]}
    return result_message, {"attested": True, "asserted": asserted is not None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "attester": ATTESTER_BASE_URL})
        if self.path == "/.well-known/agent-card.json":
            base = PUBLIC_URL or f"http://{self.headers.get('Host', '0.0.0.0:' + str(PORT))}"
            return self._send(200, _agent_card(base))
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/a2a":
            return self._send(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:  # noqa: BLE001
            return self._send(200, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "invalid JSON"}})
        rpc_id = body.get("id")
        if body.get("method") != "message/send":
            return self._send(200, {"jsonrpc": "2.0", "id": rpc_id,
                                    "error": {"code": -32601, "message": "unsupported method"}})
        message, metadata = _handle_message_send(body.get("params"))
        return self._send(200, {"jsonrpc": "2.0", "id": rpc_id,
                                "result": {"message": message, "metadata": metadata}})


if __name__ == "__main__":
    print(f"[azure-attestation-gateway] serving /a2a on :{PORT} (attester={ATTESTER_BASE_URL})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
