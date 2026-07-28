"""AgentCore Runtime HTTP contract around agent.py.

Bedrock AgentCore Runtime (serverProtocol HTTP) invokes a container that serves GET /ping (health) and
POST /invocations (the work) on port 8080. This wrapper runs the client-attestation chain from agent.py:
the agent obtains its evidence with sts:GetWebIdentityToken as its AgentCore execution role, then
authenticates to PingFederate. ATTESTER_BASE_URL is injected as an AgentCore environment variable.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent  # reads ATTESTER_BASE_URL at import; runs the chain in invoke()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ping":
            return self._send(200, {"status": "healthy"})
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/invocations":
            length = int(self.headers.get("Content-Length") or 0)
            payload = {}
            if length:
                try:
                    payload = json.loads(self.rfile.read(length))
                except Exception:  # noqa: BLE001
                    payload = {}
            requested = payload.get("authorization_details") or [
                {"type": "sales_agent", "sales_regions": ["EMEA"]}]
            return self._send(200, agent.invoke(requested_details=requested))
        return self._send(404, {"error": "not_found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("[agentcore-runtime] serving /ping and /invocations on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
