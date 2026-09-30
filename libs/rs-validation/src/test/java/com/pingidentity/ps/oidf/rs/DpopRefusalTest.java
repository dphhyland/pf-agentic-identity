package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The DPoP proof: replay, the header count, the nonce, and the key and token it is bound to. Each refusal carries the
 * RFC sentence it enforces, quoted from the RFC.
 */
class DpopRefusalTest {
    private Fixture f;
    private InMemoryReplayStore store;
    private DelegatedTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        this.f = new Fixture();
        this.store = new InMemoryReplayStore();
        this.validator = this.f.builder(this.store).build();
    }

    private DelegatedTokenValidator.RsException refused(DelegatedTokenValidator v,
                                                        DelegatedTokenValidator.Presentation p) {
        return assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(p));
    }

    /**
     * U-0011's test. RFC 9449 §11.1: "In the context of the target URI, servers can store the jti value of each DPoP
     * proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of
     * the same DPoP proof. HTTP requests to the same URI for which the jti value has been seen before would be
     * declined."
     */
    @Test
    @Requirement("RFC9449 §11.1")
    void aReplayedProofIsRefused() throws Exception {
        String token = this.f.token();
        String proof = this.f.proof(token);
        DelegatedTokenValidator.Result first = this.validator.validate(Fixture.dpop(token, List.of(proof)));
        assertEquals(Fixture.INSTANCE, first.actingInstance().orElseThrow());

        DelegatedTokenValidator.RsException e = this.refused(this.validator, Fixture.dpop(token, List.of(proof)));
        assertEquals("invalid_dpop_proof", e.error());
        assertEquals(401, e.status());
        assertTrue(e.getMessage().contains("used before"), e.getMessage());
    }

    /** The same proof is refused by a second validator that shares the store: the store, not the object, remembers. */
    @Test
    @Requirement("RFC9449 §11.1")
    void aProofReplayedAtAnotherNodeSharingTheStoreIsRefused() throws Exception {
        DelegatedTokenValidator otherNode = this.f.builder(this.store).build();
        String token = this.f.token();
        String proof = this.f.proof(token);
        this.validator.validate(Fixture.dpop(token, List.of(proof)));
        assertEquals("invalid_dpop_proof", this.refused(otherNode, Fixture.dpop(token, List.of(proof))).error());
    }

    /** The window the proof is remembered for is how much longer it would pass the freshness check. */
    @Test
    void theReplayWindowIsTheProofsRemainingAcceptance() {
        long iat = 1_000_000L;
        // Accepted until iat + 300 + 60 s; a second more for iat's rounding.
        assertEquals(Duration.ofSeconds(361), DelegatedTokenValidator.replayWindow(iat, iat * 1000L, 300, 60));
        assertEquals(Duration.ofSeconds(1), DelegatedTokenValidator.replayWindow(iat, (iat + 400) * 1000L, 300, 60));
        assertEquals(Duration.ofSeconds(1), DelegatedTokenValidator.replayWindow(iat, (iat + 361) * 1000L, 300, 60));
    }

    /**
     * RFC 9449 §11.1: "a server that is tracking jti values should reject DPoP proof JWTs with unnecessarily large
     * jti values or store only a hash thereof." The key is a hash, whatever the jti's size, and depends on the key
     * as well as the jti.
     */
    @Test
    @Requirement("RFC9449 §11.1")
    void theReplayKeyIsAHashScopedToTheProofKey() {
        String big = "j".repeat(100_000);
        assertEquals(43, DelegatedTokenValidator.replayKey("jkt-a", big).length());
        assertTrue(!DelegatedTokenValidator.replayKey("jkt-a", "same").equals(
                DelegatedTokenValidator.replayKey("jkt-b", "same")));
    }

    /** A store that cannot answer refuses the request as unavailable: a proof is never accepted unasked. */
    @Test
    void aReplayStoreThatCannotAnswerIsA503() throws Exception {
        DelegatedTokenValidator v = this.f.builder((key, window) -> {
            throw new IOException("redis is down");
        }).build();
        String token = this.f.token();
        DelegatedTokenValidator.RsException e = this.refused(v, Fixture.dpop(token, List.of(this.f.proof(token))));
        assertEquals(503, e.status());
        assertNull(e.error());
    }

    @Test
    void aReplayStoreIsRequired() throws Exception {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                        .keys(List.of(Fixture.publicOnly(this.f.asKey))).build());
        assertTrue(e.getMessage().contains("replay store is required"), e.getMessage());
    }

    /** RFC 9449 §4.3, item 1: "There is not more than one DPoP HTTP request header field." */
    @Test
    @Requirement("RFC9449 §4.3")
    void twoDpopHeadersAreRefused() throws Exception {
        String token = this.f.token();
        DelegatedTokenValidator.RsException e = this.refused(this.validator,
                Fixture.dpop(token, List.of(this.f.proof(token), this.f.proof(token))));
        assertEquals("invalid_dpop_proof", e.error());
    }

    /**
     * RFC 9449 §7.1: "For such an access token, a resource server MUST check that a DPoP proof was also received in
     * the DPoP header field of the HTTP request".
     */
    @Test
    @Requirement("RFC9449 §7.1")
    void aDpopTokenWithoutAProofIsRefused() throws Exception {
        DelegatedTokenValidator.RsException e = this.refused(this.validator, Fixture.dpop(this.f.token(), List.of()));
        assertEquals("invalid_token", e.error());
    }

    /** RFC 9449 §4.3, item 8: "The htm claim matches the HTTP method of the current request." */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofForAnotherMethodIsRefused() throws Exception {
        String token = this.f.token();
        String proof = this.f.proof(token, "POST", Fixture.URL, c -> { });
        assertEquals("invalid_dpop_proof", this.refused(this.validator, Fixture.dpop(token, List.of(proof))).error());
    }

    /**
     * RFC 9449 §4.3, item 9: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was
     * received, ignoring any query and fragment parts."
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofForAnotherUriIsRefused() throws Exception {
        String token = this.f.token();
        String proof = this.f.proof(token, "GET", "https://other.example.com/orders", c -> { });
        assertEquals("invalid_dpop_proof", this.refused(this.validator, Fixture.dpop(token, List.of(proof))).error());
    }

    /**
     * RFC 9449 §4.3, item 11: "The creation time of the JWT, as determined by either the iat claim or a server managed
     * timestamp via the nonce claim, is within an acceptable window (see Section 11.1)." And §11.1: "servers MUST only
     * accept DPoP proofs for a limited time after their creation".
     */
    @Test
    @Requirement({"RFC9449 §4.3", "RFC9449 §11.1"})
    void aStaleProofIsRefused() throws Exception {
        String token = this.f.token();
        String proof = this.f.proof(token, "GET", Fixture.URL,
                c -> c.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - 3600)));
        DelegatedTokenValidator.RsException e = this.refused(this.validator, Fixture.dpop(token, List.of(proof)));
        assertEquals("invalid_dpop_proof", e.error());
        assertTrue(e.getMessage().contains("stale"), e.getMessage());
    }

    /** RFC 9449 §4.3, item 4: "The typ JOSE Header Parameter has the value dpop+jwt." A token is not a proof. */
    @Test
    @Requirement("RFC9449 §4.3")
    void anAccessTokenSentAsItsOwnProofIsRefused() throws Exception {
        String token = this.f.token();
        assertEquals("invalid_dpop_proof", this.refused(this.validator, Fixture.dpop(token, List.of(token))).error());
    }

    /**
     * RFC 9449 §4.3, item 12: "confirm that the public key to which the access token is bound matches the public key
     * from the DPoP proof." Figure 16 answers it with error="invalid_token".
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofByAnotherKeyIsRefused() throws Exception {
        String token = this.f.token();
        String proof = Fixture.proof(new Fixture().clientKey, token, "GET", Fixture.URL, c -> { });
        assertEquals("invalid_token", this.refused(this.validator, Fixture.dpop(token, List.of(proof))).error());
    }

    /**
     * RFC 9449 §4.3, item 12: "ensure that the value of the ath claim equals the hash of that access token". And
     * §4.2: "When the DPoP proof is used in conjunction with the presentation of an access token in protected
     * resource access (see Section 7), the DPoP proof MUST also contain the following claim: ath".
     */
    @Test
    @Requirement({"RFC9449 §4.2", "RFC9449 §4.3"})
    void aProofWithoutOrWithAnotherAthIsRefused() throws Exception {
        String token = this.f.token();
        String none = this.f.proof(null, "GET", Fixture.URL, c -> { });
        String other = this.f.proof(this.f.token(), "GET", Fixture.URL, c -> { });
        assertEquals("invalid_dpop_proof", this.refused(this.validator, Fixture.dpop(token, List.of(none))).error());
        assertEquals("invalid_dpop_proof", this.refused(this.validator, Fixture.dpop(token, List.of(other))).error());
        String blank = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("ath", " "));
        assertTrue(this.refused(this.validator, Fixture.dpop(token, List.of(blank))).getMessage().contains("no 'ath'"));
    }

    /**
     * RFC 9449 §7.1: "For such an access token" - one sent under the DPoP scheme - the resource server must "check
     * that the public key of the DPoP proof matches the public key to which the access token is bound per Section
     * 6"; a token with no jkt is bound to no DPoP key.
     */
    @Test
    @Requirement("RFC9449 §7.1")
    void aTokenWithoutJktSentAsDpopIsRefused() throws Exception {
        var claims = this.f.claims();
        claims.setClaim("cnf", java.util.Map.of("x5t#S256", "abc"));
        String token = this.f.token(claims);
        DelegatedTokenValidator.RsException e = this.refused(this.validator,
                Fixture.dpop(token, List.of(this.f.proof(token))));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("not DPoP-bound"), e.getMessage());
    }

    /**
     * RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access token received as a bearer token per
     * [RFC6750]."
     */
    @Test
    @Requirement("RFC9449 §7.2")
    void aDpopBoundTokenSentAsBearerIsRefused() throws Exception {
        DelegatedTokenValidator v = this.f.builder(this.store).mtls(true).build();
        DelegatedTokenValidator.RsException e = this.refused(v, new DelegatedTokenValidator.Presentation(
                DelegatedTokenValidator.Scheme.BEARER, this.f.token(), List.of(), "GET", Fixture.URL, null));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("sent as a bearer token"), e.getMessage());
    }

    // ---- resource-server nonces -----------------------------------------------------------------------------------

    private static final byte[] SECRET = new byte[32];

    private DelegatedTokenValidator withNonces(Clock clock) throws Exception {
        return this.f.builder(this.store).nonces(new DpopNonces(SECRET, Duration.ofMinutes(1), clock)).build();
    }

    /**
     * RFC 9449 §9: "Resource servers use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate:
     * DPoP value and DPoP-Nonce value to accomplish this." And §11.3: "A server MUST NOT accept any DPoP proofs
     * without the nonce claim when a DPoP nonce has been provided to the client."
     */
    @Test
    @Requirement({"RFC9449 §9", "RFC9449 §11.3"})
    void withNoncesOnAProofWithoutOneIsAskedForOne() throws Exception {
        DelegatedTokenValidator v = this.withNonces(Clock.systemUTC());
        String token = this.f.token();
        DelegatedTokenValidator.RsException e = this.refused(v, Fixture.dpop(token, List.of(this.f.proof(token))));
        assertEquals("use_dpop_nonce", e.error());
        assertEquals(401, e.status());
        assertEquals(v.currentNonce().orElseThrow(), e.dpopNonce());
        assertEquals("Resource server requires nonce in DPoP proof", e.getMessage());

        String retried = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("nonce", e.dpopNonce()));
        DelegatedTokenValidator.Result result = v.validate(Fixture.dpop(token, List.of(retried)));
        assertNull(result.nextDpopNonce(), "a current nonce needs no replacement");
    }

    /**
     * RFC 9449 §4.3, item 10: "If the server provided a nonce value to the client, the nonce claim matches the
     * server-provided nonce value." §8: "This same error code is used when supplying a new nonce value when there was
     * a nonce mismatch."
     */
    @Test
    @Requirement({"RFC9449 §4.3", "RFC9449 §8"})
    void withNoncesOnAWrongOrExpiredNonceIsAskedForTheCurrentOne() throws Exception {
        Instant start = Instant.parse("2026-09-28T00:00:10Z");
        MutableClock clock = new MutableClock(start);
        DelegatedTokenValidator v = this.withNonces(clock);
        String issued = v.currentNonce().orElseThrow();
        String token = this.f.token();

        String forged = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("nonce", "not-ours"));
        assertEquals("use_dpop_nonce", this.refused(v, Fixture.dpop(token, List.of(forged))).error());

        clock.now = start.plusSeconds(60);  // the next window: last window's nonce still passes, and is replaced
        String previous = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("nonce", issued));
        DelegatedTokenValidator.Result result = v.validate(Fixture.dpop(token, List.of(previous)));
        assertNotNull(result.nextDpopNonce());
        assertTrue(!issued.equals(result.nextDpopNonce()));

        clock.now = start.plusSeconds(120);  // two windows on: expired
        String expired = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("nonce", issued));
        DelegatedTokenValidator.RsException e = this.refused(v, Fixture.dpop(token, List.of(expired)));
        assertEquals("use_dpop_nonce", e.error());
        assertEquals(v.currentNonce().orElseThrow(), e.dpopNonce());
    }

    @Test
    void withoutNoncesThereIsNoCurrentNonce() {
        assertTrue(this.validator.currentNonce().isEmpty());
    }

    /** A settable clock for the nonce windows. */
    static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }
    }
}
