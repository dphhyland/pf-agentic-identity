"""Drive a full authorization code flow against the demo PingFederate.

Stands in for the TPP's browser: sign alice in, approve the consent, swap the code
for tokens. The point is not the tokens -- it is the persistent grant PF creates on
the way, which is what the Grant Evaluation API later answers questions about.
"""
import http.cookiejar, json, re, ssl, sys, urllib.parse, urllib.request

PF = "https://localhost:9131"
REDIRECT = "http://localhost:8081/callback"
CLIENT = "acme-budgeting"
SECRET = open(sys.argv[1]).read().strip()
USER, PASSWORD = "alice", "2FederateM0re"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

jar = http.cookiejar.CookieJar()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)


opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
    NoRedirect,
)


def get(url):
    try:
        r = opener.open(url)
        return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def post(url, fields):
    data = urllib.parse.urlencode(fields, doseq=True).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = opener.open(req)
        return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def form_action(html):
    return re.search(r'<form[^>]*action="([^"]+)"', html).group(1)


def hidden(html, name):
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), html)
    return m.group(1) if m else None


# 1. Authorization request.
authz = PF + "/as/authorization.oauth2?" + urllib.parse.urlencode({
    "client_id": CLIENT,
    "response_type": "code",
    "scope": "accounts.read grant_management_evaluate",
    "redirect_uri": REDIRECT,
    "state": "demo123",
})
status, html, _ = get(authz)
print(f"1. authorize            -> {status} {re.search(r'<title>([^<]*)', html).group(1)}")

# 2. Sign in.
status, html, hdrs = post(PF + form_action(html),
                          {"pf.username": USER, "pf.pass": PASSWORD, "pf.ok": "clicked"})
title = re.search(r"<title>([^<]*)", html)
print(f"2. sign in as {USER}     -> {status} {title.group(1) if title else hdrs.get('location','')}")

# 3. Approve the consent, echoing back the CSRF token from THIS render.
status, html2, hdrs = post(PF + form_action(html), {
    "check-user-approved-scope": "true",
    "scope": ["accounts.read", "grant_management_evaluate"],
    "cSRFToken": hidden(html, "cSRFToken"),
    "pf.oauth.authz.consent": "allow",
})
location = hdrs.get("location", "") or hdrs.get("Location", "")
print(f"3. approve consent      -> {status}")

if "code=" not in location:
    print("   FAILED, no code in:", location or html2[:300])
    sys.exit(1)

code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
print(f"   got code {code[:18]}...")

# 4. Swap the code for tokens.
status, body, _ = post(PF + "/as/token.oauth2", {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": REDIRECT,
    "client_id": CLIENT,
    "client_secret": SECRET,
})
tok = json.loads(body)
if "access_token" not in tok:
    print("   token exchange FAILED:", body[:300])
    sys.exit(1)
print(f"4. code -> token        -> {status} ({', '.join(tok.keys())})")

payload = tok["access_token"].split(".")[1]
payload += "=" * (-len(payload) % 4)
import base64
claims = json.loads(base64.urlsafe_b64decode(payload))
print("\n=== access token claims ===")
print(json.dumps(claims, indent=2))

open("/private/tmp/claude-501/-Users-davidhyland-Source-idp-gm-api/ba56a2cf-bb6f-4127-a77a-61447d1edaed/scratchpad/alice_token", "w").write(tok["access_token"])
if "agid" in claims:
    open("/private/tmp/claude-501/-Users-davidhyland-Source-idp-gm-api/ba56a2cf-bb6f-4127-a77a-61447d1edaed/scratchpad/alice_grant_id", "w").write(claims["agid"])
    print(f"\n=== grant id (agid): {claims['agid']} ===")
