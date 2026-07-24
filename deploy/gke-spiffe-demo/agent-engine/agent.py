"""Custom Vertex AI Agent Engine agent that authenticates to PingFederate via Client Attestation.

Deployed with a dedicated runtime service account. On query() it runs the five-step chain:
discover the attester → mint a Google-signed ID token for its own service account (the platform
evidence) → bind a fresh instance key with a challenge proof → exchange at /federation/attestation
for a Client Attestation → present attestation + PoP at PF's token endpoint.

Self-contained on stdlib + cryptography + google-auth so Agent Engine can cloudpickle it.
"""


class AttestedAgent:
    def __init__(self, attester_base, client_id, client_secret, sa_email, pf_token_aud):
        self.attester_base = attester_base.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.sa_email = sa_email
        self.pf_token_aud = pf_token_aud
        self._key = None

    def set_up(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.generate_private_key(ec.SECP256R1())

    # ── minimal JOSE ────────────────────────────────────────────────────────────────────────────
    def _b64(self, data):
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _jwk(self):
        import hashlib
        import json
        numbers = self._key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256",
               "x": self._b64(numbers.x.to_bytes(32, "big")),
               "y": self._b64(numbers.y.to_bytes(32, "big"))}
        canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")},
                               separators=(",", ":"), sort_keys=True)
        jwk["kid"] = self._b64(hashlib.sha256(canonical.encode()).digest())
        return jwk

    def _sign(self, header, claims):
        import json
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        signing_input = self._b64(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            self._b64(json.dumps(claims, separators=(",", ":")).encode())
        der = self._key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return signing_input + "." + self._b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def _http(self, method, url, body=None, headers=None, form=None):
        import json
        import urllib.error
        import urllib.parse
        import urllib.request
        data, hdrs = None, dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:  # noqa: BLE001
            return -1, str(e)

    # ── platform evidence: a Google-signed ID token for our own service account ────────────────
    def _google_id_token(self, audience):
        import google.auth
        import google.auth.transport.requests
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
        url = ("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
               + self.sa_email + ":generateIdToken")
        status, body = self._http("POST", url, body={"audience": audience, "includeEmail": True},
                                  headers={"Authorization": "Bearer " + creds.token})
        if status != 200:
            raise RuntimeError(f"generateIdToken failed: HTTP {status} {body}")
        import json
        return json.loads(body)["token"]

    # ── the chain ───────────────────────────────────────────────────────────────────────────────
    def query(self, requested_details=None):
        import json
        import time
        import uuid
        if self._key is None:
            self.set_up()

        # The static, parameterless well-known document — carries the deployment evidence_audience.
        # The agent names no client; the attester maps its identity to one.
        status, body = self._http("GET", self.attester_base + "/.well-known/client-attester")
        if status != 200:
            return {"step": "discovery", "status": status, "body": body}
        doc = json.loads(body)

        evidence = self._google_id_token(doc["evidence_audience"])

        challenge = None
        status, body = self._http("POST", doc["challenge_endpoint"])
        if status == 200:
            challenge = json.loads(body).get("attestation_challenge")

        now = int(time.time())
        proof_claims = {"aud": doc["evidence_audience"], "jti": str(uuid.uuid4()), "iat": now}
        if challenge:
            proof_claims["challenge"] = challenge
        jwk = self._jwk()
        proof = self._sign({"alg": "ES256", "typ": "oauth-attestation-instance-proof+jwt",
                            "kid": jwk["kid"]}, proof_claims)

        # No client_id — only evidence. The attester maps identity → client.
        issuance = {"instance_key": jwk, "svid": evidence, "proof": proof}
        if requested_details:
            issuance["authorization_details"] = requested_details
        mint_status, mint_body = self._http("POST", doc["attestation_endpoint"], body=issuance)
        result = {"evidence": evidence, "mint_status": mint_status, "mint_body": mint_body}
        if mint_status != 200:
            return result

        attestation = json.loads(mint_body)["attestation"]
        # The attester assigned the client_id (attestation sub); the agent only relays it.
        import base64
        p = attestation.split(".")[1]
        client_id = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("sub")
        pop = self._sign({"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": jwk["kid"]},
                         {"iss": client_id, "aud": self.pf_token_aud,
                          "jti": str(uuid.uuid4()), "iat": now})
        pf_status, pf_body = self._http(
            "POST", self.attester_base + "/as/token.oauth2",
            form={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": self.client_secret},
            headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
        result.update({"attestation": attestation, "pop": pop,
                       "pf_status": pf_status, "pf_body": pf_body})
        return result
