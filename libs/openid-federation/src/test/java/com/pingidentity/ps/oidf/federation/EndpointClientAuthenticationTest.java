package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * A client authenticating at a federation endpoint (OpenID Federation 1.0 §8.8): {@code private_key_jwt} as OpenID Connect
 * Core §9 has it, signed with one of the client's Federation Entity Keys - the ones its Entity Configuration publishes once
 * its chain validates to an anchor this entity trusts - and addressed to this entity alone.
 */
class EndpointClientAuthenticationTest {
    private static final String PF = "https://pf.example.com";
    private static final String TA = "https://ta.example.com";
    private static final String CLIENT = "https://client.example.com";
    private static final String STRANGER = "https://stranger.example.com";
    private static final String TYPE = EndpointClientAuthentication.ASSERTION_TYPE;

    private final MutableClock clock = MutableClock.startingNow();
    private final Set<String> spent = new HashSet<>();
    private final List<Long> windows = new ArrayList<>();
    private final PublicJsonWebKey rpKey = Keys.ec("client-rp-1");
    private final Federation federation = Federation.builder(this.clock).anchor(TA).leaf(CLIENT, TA)
            .metadata(CLIENT, "openid_relying_party", Map.of("jwks", Keys.publicJwks(this.rpKey)))
            .build();
    private final EndpointClientAuthentication authentication = new EndpointClientAuthentication(Set.of("ES256", "RS256"), this.clock,
            (client, jti, ttl) -> {
                this.windows.add(ttl);
                return this.spent.add(client + " " + jti);
            });

    private Statements.Spec assertion() {
        return Statements.spec(null).claim("iss", CLIENT).claim("sub", CLIENT).claim("aud", PF).claim("jti", "jti-1")
                .exp(this.clock.instant().getEpochSecond() + 60);
    }

    private String signed(Consumer<Statements.Spec> change) {
        Statements.Spec spec = this.assertion();
        change.accept(spec);
        return spec.sign(this.federation.key(CLIENT), this.clock);
    }

    private TrustChainValidator validator() {
        return this.federation.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
    }

    private String authenticate(String assertion) {
        return this.authentication.authenticate(this.validator(), TYPE, assertion, PF);
    }

    private FederationException refused(String assertion) {
        FederationException e = assertThrows(FederationException.class, () -> this.authenticate(assertion));
        assertEquals(FederationError.INVALID_CLIENT, e.error(), e.description());
        assertEquals(401, e.error().httpStatus());
        return e;
    }

    @Test
    @Requirement({"OIDFED §8.8(2)", "OIDC-CORE §9"})
    void aClientSigningWithItsFederationKeyForThisEntityAloneIsWhoItSaysItIs() {
        assertEquals(CLIENT, this.authenticate(this.signed(s -> { })));
        assertEquals(CLIENT, this.authenticate(this.signed(s -> s.claim("aud", List.of(PF)).claim("jti", "jti-2"))),
                "an audience of one, in an array");
        assertEquals(CLIENT, this.authenticate(this.signed(s -> s.claim("aud", PF + "/").claim("jti", "jti-3"))),
                "the same Entity Identifier, with its trailing slash");
    }

    @Test
    @Requirement("OIDC-CORE §9")
    void aJtiIsSpentOnceAndRememberedAsLongAsTheAssertionCouldBeUsed() {
        String assertion = this.signed(s -> { });
        this.authenticate(assertion);

        assertTrue(this.refused(assertion).description().contains("used before"));
        assertEquals(List.of(120L, 120L), this.windows, "its life left, plus the skew allowed on exp");

        long now = this.clock.instant().getEpochSecond();
        this.authenticate(this.signed(s -> s.claim("jti", "longest").exp(now + EndpointClientAuthentication.MAX_LIFETIME_SECONDS)));
        this.authenticate(this.signed(s -> s.claim("jti", "stale").exp(now - 30)));
        assertEquals(List.of(120L, 120L, 660L, EndpointClientAuthentication.CLOCK_SKEW_SECONDS), this.windows,
                "never shorter than the skew");
    }

    @Test
    void anAssertionThatWouldOutliveTheRecordOfItsJtiIsRefused() {
        long now = this.clock.instant().getEpochSecond();
        assertTrue(this.refused(this.signed(s -> s.exp(now + EndpointClientAuthentication.MAX_LIFETIME_SECONDS + 1))).description()
                .contains("10 minutes"));
        assertTrue(this.spent.isEmpty());
    }

    @Test
    void onlySoManyClientsAreLookedUpAtOnce() throws Exception {
        java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        TrustChainValidator slow = new TrustChainValidator(new HttpTrustControllerGateway((url, accept) -> {
            entered.countDown();
            release.await(10, java.util.concurrent.TimeUnit.SECONDS);
            return this.federation.http().get(url, accept);
        }, TA), this.federation.trustAnchors(), Set.of(), ValidatorOptions.defaults().withClock(this.clock));
        EndpointClientAuthentication one = new EndpointClientAuthentication(Set.of("ES256"), this.clock, (client, jti, ttl) -> true, 1);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            java.util.concurrent.Future<String> first = pool.submit(() -> one.authenticate(slow, TYPE, this.signed(s -> { }), PF));
            assertTrue(entered.await(10, java.util.concurrent.TimeUnit.SECONDS));

            FederationException busy = assertThrows(FederationException.class,
                    () -> one.authenticate(this.validator(), TYPE, this.signed(s -> s.claim("jti", "second")), PF));
            assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, busy.error());

            release.countDown();
            assertEquals(CLIENT, first.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(CLIENT, one.authenticate(this.validator(), TYPE, this.signed(s -> s.claim("jti", "third")), PF),
                    "the look-up is given back when it ends");
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    @Requirement("OIDC-CORE §9")
    void theAssertionTypeIsTheJwtBearerOne() {
        FederationException e = assertThrows(FederationException.class, () -> this.authentication.authenticate(this.validator(),
                "urn:ietf:params:oauth:client-assertion-type:saml2-bearer", this.signed(s -> { }), PF));
        assertEquals(FederationError.INVALID_CLIENT, e.error());
        assertThrows(FederationException.class, () -> this.authentication.authenticate(this.validator(), null,
                this.signed(s -> { }), PF));
    }

    @Test
    void somethingThatIsNotASignedJwtIsRefused() {
        this.refused("not-a-jwt");
        this.refused(null);
        this.refused(this.signed(s -> s.kid(null)));
        this.refused(this.signed(s -> s.kid("")));
    }

    @Test
    @Requirement({"OIDC-CORE §9", "OIDFED §8.8(2)"})
    void issAndSubAreBothTheClientsEntityIdentifier() {
        this.refused(this.signed(s -> s.claim("sub", STRANGER)));
        this.refused(this.signed(s -> s.remove("sub")));
        this.refused(this.signed(s -> s.remove("iss")));
        this.refused(this.signed(s -> s.claim("iss", "http://client.example.com").claim("sub", "http://client.example.com")));
        this.refused(this.signed(s -> s.claim("iss", 7)));
    }

    @Test
    @Requirement("OIDFED §8.8(2)")
    void theAudienceIsThisEntityAndNothingElse() {
        assertTrue(this.refused(this.signed(s -> s.claim("aud", STRANGER))).description().contains("nothing else"));
        this.refused(this.signed(s -> s.claim("aud", List.of(PF, STRANGER))));
        this.refused(this.signed(s -> s.claim("aud", List.of(STRANGER))));
        this.refused(this.signed(s -> s.claim("aud", PF + "/federation/fetch")));
        this.refused(this.signed(s -> s.claim("aud", List.of())));
        this.refused(this.signed(s -> s.claim("aud", List.of(7))));
        this.refused(this.signed(s -> s.claim("aud", 7)));
        this.refused(this.signed(s -> s.remove("aud")));
    }

    @Test
    @Requirement("OIDC-CORE §9")
    void expIsRequiredAndNotPastWhileIatIsOptionalButNotInTheFuture() {
        this.refused(this.signed(s -> s.withoutExp()));
        this.refused(this.signed(s -> s.exp(this.clock.instant().getEpochSecond() - EndpointClientAuthentication.CLOCK_SKEW_SECONDS)));
        this.refused(this.signed(s -> s.claim("exp", "tomorrow")));
        this.refused(this.signed(s -> s.iat(this.clock.instant().getEpochSecond() + EndpointClientAuthentication.CLOCK_SKEW_SECONDS + 1)));
        this.refused(this.signed(s -> s.claim("iat", "yesterday")));
        assertEquals(CLIENT, this.authenticate(this.signed(s -> s.withoutIat())));
    }

    @Test
    @Requirement("OIDC-CORE §9")
    void aJtiIsRequired() {
        this.refused(this.signed(s -> s.remove("jti")));
        this.refused(this.signed(s -> s.claim("jti", " ")));
        this.refused(this.signed(s -> s.claim("jti", 7)));
    }

    @Test
    @Requirement("OIDFED §8.8(2)")
    void aKeyThatIsNotOneOfTheClientsFederationEntityKeysDoesNotAuthenticateIt() {
        String rpSigned = this.assertion().sign(this.rpKey, this.clock);
        assertTrue(this.refused(rpSigned).description().contains("Federation Entity Keys"),
                "its openid_relying_party key is for OpenID Connect, not for the federation");
        this.refused(this.signed(s -> s.signWith(Keys.ec(this.federation.key(CLIENT).getKeyId()))));
        this.refused(this.signed(s -> s.kid("another")));
        this.refused(this.signed(s -> s.unsigned().header("kid", this.federation.key(CLIENT).getKeyId())));
    }

    @Test
    void anAlgorithmThisEntityDoesNotAcceptIsRefused() {
        EndpointClientAuthentication rsaOnly = new EndpointClientAuthentication(Set.of("RS256"), this.clock, (client, jti, ttl) -> true);
        FederationException e = assertThrows(FederationException.class,
                () -> rsaOnly.authenticate(this.validator(), TYPE, this.signed(s -> { }), PF));
        assertEquals(FederationError.INVALID_CLIENT, e.error());
    }

    @Test
    @Requirement({"OIDFED §8.8(2)", "OIDFED §10.2(1)"})
    void aClientWhoseChainDoesNotReachATrustedAnchorIsNotAuthenticated() {
        Federation elsewhere = Federation.builder(this.clock).anchor("https://other-ta.example.com").leaf(STRANGER, "https://other-ta.example.com")
                .build();
        this.federation.http().put(STRANGER + "/.well-known/openid-federation", elsewhere.entityConfiguration(STRANGER));
        String assertion = this.assertion().claim("iss", STRANGER).claim("sub", STRANGER).sign(elsewhere.key(STRANGER), this.clock);

        assertTrue(this.refused(assertion).description().contains("does not validate"));
    }

    @Test
    @Requirement("OIDFED §10.5(1)")
    void aClientWhoseFederationCannotBeReachedIsNotRefusedButCannotBeCheckedNow() {
        this.federation.http().failing(CLIENT + "/.well-known/openid-federation", new IOException("connection refused"));

        FederationException e = assertThrows(FederationException.class, () -> this.authenticate(this.signed(s -> { })));

        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, e.error());
        assertTrue(this.spent.isEmpty(), "a jti is spent only by an assertion that verified");
    }
}
