/*
 * Verifies SET minting: RFC 8417 claims, secevent+jwt typ, sub_id formats, and a valid signature.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

class SetMinterTest {

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("test-set-key");
    private final SetMinter minter = new SetMinter("RS256", keys);

    @Test
    void mintsSignedSetWithRequiredClaimsAndTyp() throws Exception {
        SecurityEventToken set = SecurityEventToken.builder()
                .issuer("https://op.example.com")
                .audience("https://receiver.example.com")
                .jti(SetMinter.newJti())
                .issuedAt(SetMinter.nowSeconds())
                .subjectId(SubjectId.issSub("https://op.example.com", "user-123"))
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("event_timestamp", SetMinter.nowSeconds()))
                .build();

        String jws = minter.sign(set);

        // Header: alg, kid, typ
        JsonWebSignature verify = new JsonWebSignature();
        verify.setCompactSerialization(jws);
        assertEquals("secevent+jwt", verify.getHeader("typ"));
        assertEquals("test-set-key", verify.getKeyIdHeaderValue());
        assertEquals("RS256", verify.getAlgorithmHeaderValue());

        // Signature verifies against the public key
        verify.setKey(keys.publicKey());
        assertTrue(verify.verifySignature(), "SET signature must verify with the transmitter public key");

        // Payload: RFC 8417 claims
        Map<String, Object> claims = JsonUtil.parseJson(verify.getPayload());
        assertEquals("https://op.example.com", claims.get("iss"));
        assertEquals("https://receiver.example.com", claims.get("aud"));
        assertNotNull(claims.get("iat"));
        assertNotNull(claims.get("jti"));

        @SuppressWarnings("unchecked")
        Map<String, Object> subId = (Map<String, Object>) claims.get("sub_id");
        assertEquals("iss_sub", subId.get("format"));
        assertEquals("user-123", subId.get("sub"));

        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) claims.get("events");
        assertTrue(events.containsKey(SsfEventTypes.CAEP_SESSION_REVOKED), "events keyed by event-type URI");
    }

    @Test
    void carriesEmailSubjectAndTxnWhenSet() throws Exception {
        SecurityEventToken set = SecurityEventToken.builder()
                .issuer("https://op.example.com")
                .audience("https://receiver.example.com")
                .jti(SetMinter.newJti())
                .issuedAt(SetMinter.nowSeconds())
                .subjectId(SubjectId.email("alice@example.com"))
                .event(SsfEventTypes.RISC_ACCOUNT_DISABLED, Map.of())
                .txn("txn-42")
                .build();

        String jws = minter.sign(set);
        JsonWebSignature verify = new JsonWebSignature();
        verify.setCompactSerialization(jws);
        verify.setKey(keys.publicKey());
        assertTrue(verify.verifySignature());
        Map<String, Object> claims = JsonUtil.parseJson(verify.getPayload());
        assertEquals("txn-42", claims.get("txn"));
        @SuppressWarnings("unchecked")
        Map<String, Object> subId = (Map<String, Object>) claims.get("sub_id");
        assertEquals("email", subId.get("format"));
        assertEquals("alice@example.com", subId.get("email"));
    }
}
