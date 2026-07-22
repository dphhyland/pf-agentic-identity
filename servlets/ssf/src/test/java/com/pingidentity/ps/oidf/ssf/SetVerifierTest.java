/*
 * Receiver-side SET verification: signature, typ, iss/aud enforcement, kid rotation refresh.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;

class SetVerifierTest {

    private static final String ISS = "https://transmitter.example.com";
    private static final String AUD = "https://receiver.example.com";

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");
    private final SetMinter minter = new SetMinter("RS256", keys);

    private SetVerifier.JwksSource sourceOf(TestSigningKeyProvider provider) {
        return refresh -> {
            org.jose4j.jwk.RsaJsonWebKey jwk = new org.jose4j.jwk.RsaJsonWebKey(provider.publicKey());
            jwk.setKeyId(provider.keyId());
            return List.<JsonWebKey>of(jwk);
        };
    }

    private String mint(String iss, String aud, SubjectId subject) throws Exception {
        return minter.sign(SecurityEventToken.builder()
                .issuer(iss).audience(aud).jti(SetMinter.newJti()).issuedAt(SetMinter.nowSeconds())
                .subjectId(subject)
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("event_timestamp", 1L))
                .build());
    }

    @Test
    void validSetVerifiesAndParses() throws Exception {
        SetVerifier v = new SetVerifier(ISS, AUD, sourceOf(keys));
        ReceivedSet r = v.verify(mint(ISS, AUD, SubjectId.email("alice@example.com")));
        assertEquals(ISS, r.issuer());
        assertEquals(SubjectId.email("alice@example.com"), r.subjectId());
        assertTrue(r.hasEvent(SsfEventTypes.CAEP_SESSION_REVOKED));
    }

    @Test
    void subjectlessVerificationEventIsAccepted() throws Exception {
        SetVerifier v = new SetVerifier(ISS, AUD, sourceOf(keys));
        String jws = minter.sign(SecurityEventToken.builder()
                .issuer(ISS).audience(AUD).jti(SetMinter.newJti()).issuedAt(SetMinter.nowSeconds())
                .event(SsfEventTypes.VERIFICATION, Map.of("state", "s")).build());
        assertNull(v.verify(jws).subjectId());
    }

    @Test
    void wrongSignerRejectedWithInvalidKey() throws Exception {
        TestSigningKeyProvider other = new TestSigningKeyProvider("other-key");
        SetVerifier v = new SetVerifier(ISS, AUD, sourceOf(other)); // trusts a DIFFERENT key
        SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                () -> v.verify(mint(ISS, AUD, SubjectId.opaque("x"))));
        assertEquals("invalid_key", e.errorCode());
    }

    @Test
    void wrongIssuerAndAudienceRejected() throws Exception {
        SetVerifier v = new SetVerifier(ISS, AUD, sourceOf(keys));
        assertEquals("invalid_issuer", assertThrows(SetVerifier.SetVerificationException.class,
                () -> v.verify(mint("https://evil.example.com", AUD, SubjectId.opaque("x")))).errorCode());
        assertEquals("invalid_audience", assertThrows(SetVerifier.SetVerificationException.class,
                () -> v.verify(mint(ISS, "https://other-receiver.example.com", SubjectId.opaque("x")))).errorCode());
    }

    @Test
    void garbageRejectedWithInvalidRequest() {
        SetVerifier v = new SetVerifier(ISS, AUD, sourceOf(keys));
        assertEquals("invalid_request", assertThrows(SetVerifier.SetVerificationException.class,
                () -> v.verify("not-a-jws")).errorCode());
    }

    @Test
    void unknownKidTriggersRefresh() throws Exception {
        // First call (no refresh) returns no keys; the refresh call returns the right key.
        AtomicInteger refreshes = new AtomicInteger();
        SetVerifier.JwksSource rotating = refresh -> {
            if (!refresh) {
                return List.of();
            }
            refreshes.incrementAndGet();
            return sourceOf(keys).keys(true);
        };
        SetVerifier v = new SetVerifier(ISS, AUD, rotating);
        v.verify(mint(ISS, AUD, SubjectId.opaque("x")));
        assertEquals(1, refreshes.get(), "verification succeeded via the refresh path");
    }
}
