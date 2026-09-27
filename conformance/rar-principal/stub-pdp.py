#!/usr/bin/env python3
"""A PDP that says yes and writes down what it was asked.

verify-rar-principal.sh starts this on the host and points the rig's RAR plugin at it over
http://host.docker.internal:<port>/access/v1/evaluation (the AuthZEN dialect). Every request is appended to
the JSONL file as one line - method, path, the headers the plugin sent (the shared secret included, so the
upgrade rehearsal can see whether the stored secret survived the field turning encrypted) and the parsed
body - and answered {"decision": true}. Anything not JSON is recorded and answered 400, so a bad request shows
up in the log rather than as a mysterious PERMIT.

    stub-pdp.py <port> <requests.jsonl>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        record = {"method": "POST", "path": self.path, "headers": dict(self.headers.items())}
        try:
            record["body"] = json.loads(raw) if raw else None
            ok = True
        except ValueError:
            record["raw"] = raw
            ok = False
        with open(sys.argv[2], "a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")
        answer = json.dumps({"decision": True}) if ok else json.dumps({"error": "not json"})
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer.encode())

    def log_message(self, fmt, *args):  # quiet; the JSONL is the record
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
