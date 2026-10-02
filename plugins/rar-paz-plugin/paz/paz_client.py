"""What the two paz/ scripts share: where the PingAuthorize Policy Editor is, how it is called, and the one secret.

The Policy Editor's REST API is called as the user in PAZ_PAP_USER (default admin) through the x-user-id header,
which is how the Policy Editor authenticates in the credentials mode the image starts in; that is a user name, not a
secret. Its decision endpoint, /api/governance-engine, takes HTTP Basic with the decision point shared secret as
the password (the Policy Editor's Authentication.SharedSecret, which the image sets from
DECISION_POINT_SHARED_SECRET). That secret is read from PAZ_DECISION_SECRET, or from the file PAZ_DECISION_SECRET_FILE
names; there is no default, and a script that needs it refuses to run without it.

TLS: the image serves a self-signed certificate. PAZ_CA_FILE names a CA (or the certificate itself) to check it with;
without it, a Policy Editor on this machine (localhost, 127.0.0.1, ::1) is trusted on first use - the certificate it
presents is the one checked, host name included - and any other host is refused.
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def pap_url():
    return os.environ.get("PAZ_PAP_URL", "https://localhost:7443").rstrip("/")


def tls_context(url):
    """A context that checks the Policy Editor's certificate, and the host name in it, against PAZ_CA_FILE; without
    it, on this machine only, against the certificate the Policy Editor presents now (the image's self-signed one, which
    names localhost and 127.0.0.1)."""
    ca_file = os.environ.get("PAZ_CA_FILE")
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    parts = urllib.parse.urlsplit(url)
    if parts.hostname not in LOCAL_HOSTS:
        sys.exit(f"refusing to call {url} without PAZ_CA_FILE: only a Policy Editor on this machine is trusted on first use")
    presented = ssl.get_server_certificate((parts.hostname, parts.port or 443))
    return ssl.create_default_context(cadata=presented)


def decision_secret():
    """The decision point shared secret: PAZ_DECISION_SECRET, or the content of PAZ_DECISION_SECRET_FILE. No default."""
    secret = os.environ.get("PAZ_DECISION_SECRET")
    path = os.environ.get("PAZ_DECISION_SECRET_FILE")
    if secret and path:
        sys.exit("set PAZ_DECISION_SECRET or PAZ_DECISION_SECRET_FILE, not both")
    if path:
        with open(path, encoding="utf-8") as handle:
            secret = handle.read().rstrip("\n")
    if not secret:
        sys.exit("no decision point secret: set PAZ_DECISION_SECRET, or PAZ_DECISION_SECRET_FILE to a file holding it"
                 " (the value the compose file gave the Policy Editor as DECISION_POINT_SHARED_SECRET)")
    return secret


class Pap:
    """The Policy Editor's REST API, on one branch."""

    def __init__(self, url=None, user=None, branch=None):
        self.url = url or pap_url()
        self.user = user or os.environ.get("PAZ_PAP_USER", "admin")
        self.branch = branch
        self.context = tls_context(self.url)

    def call(self, method, path, body=None, branch=True, headers=None, expect=(200, 201, 204)):
        query = ""
        if branch and self.branch:
            query = ("&" if "?" in path else "?") + urllib.parse.urlencode({"branch": self.branch})
        request = urllib.request.Request(self.url + path + query, method=method,
                                         data=None if body is None else json.dumps(body).encode())
        request.add_header("x-user-id", self.user)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                text = response.read().decode()
                status = response.status
        except urllib.error.HTTPError as error:
            text = error.read().decode()
            status = error.code
        if status not in expect:
            raise RuntimeError(f"{method} {path} answered HTTP {status}: {text[:600]}")
        return json.loads(text) if text.strip() else {}

    def decide(self, secret, decision_node, request):
        """One governance-engine decision from the branch's decision node, as the PingAuthorize PDP would ask it."""
        token = base64.b64encode(("pdp:" + secret).encode()).decode()
        return self.call("POST", "/api/governance-engine", request, branch=False, headers={
            "Authorization": "Basic " + token, "x-branch": self.branch, "x-decision-node": decision_node})
