/*
 * In-process SSF self-verify: mint a CAEP session-revoked SET with the module's real SetMinter and verify
 * its signature + claims (typ, events, sub_id) — no PingFederate, no network.
 *
 * Ported from pf-oidf-modules (2026-08-18) when that repo was reduced to the demo UI + shell probes.
 * SigningKeyProvider's import updated for the unwound package layout (...oidf.common -> ...oidf.jose);
 * the ssf package itself didn't move.
 *
 * Classpath: jose4j + ssf + oidf-jose. See services/harness/README.md.
 */
package com.pingidentity.ps.oidf.harness;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;

import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.ssf.CaepRiscEvents;
import com.pingidentity.ps.oidf.ssf.SecurityEventToken;
import com.pingidentity.ps.oidf.ssf.SetMinter;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.SubjectId;

public final class SsfSelfVerify {

    public static void main(String[] args) throws Exception {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("ssf-selfverify");
        SigningKeyProvider keys = new SigningKeyProvider() {
            public String keyId() {
                return jwk.getKeyId();
            }

            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) jwk.getRsaPrivateKey();
            }

            public RSAPublicKey publicKey() {
                return jwk.getRsaPublicKey();
            }
        };

        long now = SetMinter.nowSeconds();
        SecurityEventToken set = SecurityEventToken.builder()
                .issuer("https://op.example.com")
                .audience("https://receiver.example.com")
                .jti(SetMinter.newJti())
                .issuedAt(now)
                .subjectId(SubjectId.issSub("https://op.example.com", "user-1"))
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, CaepRiscEvents.sessionRevoked(now, "logout"))
                .build();

        String jws = new SetMinter("RS256", keys).sign(set);

        JsonWebSignature v = new JsonWebSignature();
        v.setCompactSerialization(jws);
        require("secevent+jwt".equals(v.getHeader("typ")), "typ header is secevent+jwt");
        v.setKey(keys.publicKey());
        require(v.verifySignature(), "signature verifies against the transmitter public key");

        Map<String, Object> claims = JsonUtil.parseJson(v.getPayload());
        require("https://op.example.com".equals(claims.get("iss")), "iss");
        require(((Map<?, ?>) claims.get("events")).containsKey(SsfEventTypes.CAEP_SESSION_REVOKED), "events keyed by URI");
        require(claims.containsKey("sub_id"), "sub_id present");
        System.out.println("[PASS] SSF selfverify: minted + verified a CAEP session-revoked SET");
    }

    static void require(boolean cond, String what) {
        if (!cond) {
            System.out.println("[FAIL] " + what);
            System.exit(1);
        }
    }
}
