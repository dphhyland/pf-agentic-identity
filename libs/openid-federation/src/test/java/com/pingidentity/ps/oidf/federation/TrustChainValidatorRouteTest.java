package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * Finding and validating a route to an anchor (OpenID Federation 1.0 §10.1-§10.4): presented statements
 * before fetches, several anchors, the returned chain's shape and expiry, loops, the hint cap, the fetch
 * budget, and a failed route not ending the search.
 */
class TrustChainValidatorRouteTest {
    private static final String TA = "https://ta.example";
    private static final String TA2 = "https://ta2.example";
    private static final String INT = "https://int.example";
    private static final String INT2 = "https://int2.example";
    private static final String LEAF = "https://rp.example";
    private static final String OP = "https://op.example";

    private static Federation threeLevels() {
        return Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).build();
    }

    private static ValidationRequest.Builder request() {
        return ValidationRequest.forSubject(LEAF).opIssuer(OP);
    }

    // ---- presented before fetched, and the chain that comes back ---------------------------------------

    @Test
    @Requirement({"OIDFED §4(3)", "OIDFED §10.2(3.5)", "OIDFED §18.1(5)"})
    void aPresentedChainInSection4ShapeValidatesWithoutAFetch() {
        Federation f = threeLevels();
        List<String> presented = f.chain(LEAF, TA);

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(List.of(), f.http().requests(), "a complete presented chain needs no network");
        assertEquals(presented, result.trustChain());
        assertEquals(presented, result.presentedTrustChain());
        assertEquals(TA, result.trustAnchorIssuer());
        assertEquals(0, result.fetchesUsed());
    }

    @Test
    @Requirement({"OIDFED §4(3)", "OIDFED §4(6.1)", "OIDFED §4(6.2)", "OIDFED §4(6.3)", "OIDFED §4(6.4)"})
    void aDiscoveredChainComesBackInSection4ShapeWithoutTheIntermediatesConfiguration() {
        Federation f = threeLevels();

        TrustChainValidationResult bare = f.validator(TA).validate(request().build());
        TrustChainValidationResult withAnchor = f.validator(TA).validate(request().includeAnchorConfiguration(true).build());

        assertEquals(f.chain(LEAF, TA), bare.trustChain(), "leaf configuration, then the statements about the leaf and the intermediate");
        assertEquals(f.chainWithAnchor(LEAF, TA), withAnchor.trustChain(), "ending with the anchor's configuration when asked");
        assertFalse(bare.trustChain().contains(f.entityConfiguration(INT)));
        assertTrue(bare.fetchesUsed() >= 3);
    }

    @Test
    @Requirement({"OIDFED §10.2(3.6)", "OIDFED §10.2(3.7)"})
    void aPresentedAnchorConfigurationIsPartOfTheChainAndMustVerifyWithThePinnedKeys() {
        Federation f = threeLevels();
        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(f.chainWithAnchor(LEAF, TA)).build());
        assertEquals(f.entityConfiguration(TA), result.trustChain().get(3));

        PublicJsonWebKey impostor = Keys.ec("impostor-1");
        Federation forged = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .entityConfiguration(TA, s -> s.signWith(impostor).kid(f.key(TA).getKeyId()))
                .build();
        List<String> chain = new ArrayList<>(f.chain(LEAF, TA));
        chain.add(forged.entityConfiguration(TA));
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().presentedChain(chain).build()));
        assertEquals(Kind.SIGNATURE, e.kind(), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §10.4(1)")
    void theChainExpiresWithItsEarliestStatement() {
        long soon = java.time.Instant.now().getEpochSecond() + 1800;
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .subordinate(INT, LEAF, s -> s.exp(soon)).build();

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(f.chain(LEAF, TA)).build());

        assertEquals(soon, result.expEpochSeconds());
        assertEquals(java.time.Instant.ofEpochSecond(soon), result.expiresAt().orElseThrow());
    }

    // ---- several anchors ------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §10(1)", "OIDFED §10.3(1)"})
    void aSubjectInTwoFederationsResolvesThroughWhicheverValidates() {
        PublicJsonWebKey wrong = Keys.ec("wrong-1");
        Federation f = Federation.builder().anchor(TA).anchor(TA2).leaf(LEAF, TA, TA2)
                .subordinate(TA, LEAF, s -> s.signWith(wrong)).build();

        TrustChainValidationResult result = f.validator(ValidatorOptions.defaults(), TA, TA2).validate(request().build());

        assertEquals(TA2, result.trustAnchorIssuer(), "the first anchor's statement is forged, so the second federation is used");
        assertEquals(f.chain(LEAF, TA2), result.trustChain());
    }

    @Test
    @Requirement("OIDFED §10.1(2)")
    void requestedAnchorsNarrowTheSetAndNeverWidenIt() {
        Federation f = Federation.builder().anchor(TA).anchor(TA2).leaf(LEAF, TA, TA2).build();
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults(), TA, TA2);

        assertEquals(TA, validator.resolve(LEAF, List.of()).trustAnchorIssuer(), "configuration order is preference order");
        assertEquals(TA2, validator.resolve(LEAF, List.of(TA2)).trustAnchorIssuer());
        assertEquals(TA2, validator.resolve(LEAF, List.of("https://unknown.example", TA2 + "/")).trustAnchorIssuer());

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> validator.resolve(LEAF, List.of("https://unknown.example")));
        assertEquals(Kind.ANCHOR, e.kind());
        assertEquals(FederationError.INVALID_TRUST_ANCHOR, e.error());
    }

    @Test
    @Requirement({"OIDFED §4.1(3)", "OIDFED §4.1(4)"})
    void aConfiguredAnchorEndsTheRouteEvenWhenItHasSuperiorsOfItsOwn() {
        String top = "https://top.example";
        Federation f = Federation.builder().anchor(top).intermediate(TA, top).leaf(LEAF, TA).build();
        TrustChainValidator validator = new TrustChainValidator(f.gateway(TA), f.trustAnchor(TA));

        TrustChainValidationResult result = validator.validate(request().build());

        assertEquals(TA, result.trustAnchorIssuer());
        assertEquals(List.of(f.entityConfiguration(LEAF), f.subordinateStatement(TA, LEAF)), result.trustChain());
        assertEquals(0, f.http().hitsStartingWith(top), "nothing above the configured anchor is fetched");
    }

    @Test
    @Requirement({"OIDFED §4.1(1)", "OIDFED §4.1(3)"})
    void theSubjectMayBeTheAnchorItself() {
        Federation f = threeLevels();

        TrustChainValidationResult result = f.validator(TA).resolve(TA, List.of());

        assertEquals(List.of(f.entityConfiguration(TA)), result.trustChain());
        assertEquals(TA, result.trustAnchorIssuer());
        assertEquals(TA, result.leafSubject());
    }

    // ---- search bounds ------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §10.1(4)")
    void aLoopInTheHintsIsNotFollowedAndTheOtherHintIs() {
        Federation f = Federation.builder().anchor(TA)
                .intermediate(INT, INT2)
                .intermediate(INT2, INT, TA)
                .leaf(LEAF, INT).build();

        TrustChainValidationResult result = f.validator(TA).validate(request().build());

        assertEquals(List.of(f.entityConfiguration(LEAF), f.subordinateStatement(INT, LEAF),
                f.subordinateStatement(INT2, INT), f.subordinateStatement(TA, INT2)), result.trustChain());
    }

    @Test
    @Requirement("OIDFED §10.1(4)")
    void aLoopWithNoWayOutEndsWithNoRoute() {
        Federation f = Federation.builder().anchor(TA)
                .intermediate(INT, INT2)
                .intermediate(INT2, INT)
                .leaf(LEAF, INT).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.ROUTE, e.kind());
        assertTrue(f.http().requests().size() < 10, "the loop is walked once: " + f.http().requests().size());
    }

    @Test
    @Requirement("OIDFED §18.1(4)")
    void onlyTheFirstHintsAreFollowedAndConfiguredAnchorsGoFirst() {
        Federation.Builder builder = Federation.builder().anchor(TA);
        List<String> hints = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            String decoy = "https://decoy-" + i + ".example";
            builder.intermediate(decoy);
            hints.add(decoy);
        }
        hints.add(TA);
        Federation f = builder.leaf(LEAF, hints.toArray(new String[0])).build();

        TrustChainValidationResult viaAnchor = f.validator(TA).validate(request().build());
        assertEquals(TA, viaAnchor.trustAnchorIssuer(), "the anchor is the thirteenth hint and is tried first");
        assertEquals(0, f.http().hitsStartingWith("https://decoy-"));

        Federation.Builder noAnchor = Federation.builder().anchor(TA);
        List<String> decoys = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            String decoy = "https://decoy-" + i + ".example";
            noAnchor.intermediate(decoy);
            decoys.add(decoy);
        }
        Federation g = noAnchor.leaf(LEAF, decoys.toArray(new String[0])).build();
        assertThrows(TrustChainValidationException.class,
                () -> g.validator(ValidatorOptions.defaults().withMaxAuthorityHints(3), TA).validate(request().build()));
        assertEquals(3, decoys.stream().filter(d -> g.http().hitsStartingWith(d) > 0).count(), "three hints followed, no more");
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theFetchBudgetStopsTheWholeValidation() {
        Federation.Builder builder = Federation.builder().anchor(TA);
        List<String> hints = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            String decoy = "https://decoy-" + i + ".example";
            builder.intermediate(decoy);
            hints.add(decoy);
        }
        Federation f = builder.leaf(LEAF, hints.toArray(new String[0])).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(ValidatorOptions.defaults().withMaxFetches(3), TA).validate(request().build()));

        assertEquals(Kind.BUDGET, e.kind(), e.getMessage());
        assertEquals(FederationError.INVALID_TRUST_CHAIN, e.error());
    }

    // ---- a failed route does not end the search -----------------------------------------------------

    @Test
    @Requirement("OIDFED §10(1)")
    void aRouteThatFailsValidationDoesNotStopTheSearch() {
        PublicJsonWebKey wrong = Keys.ec("wrong-1");
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).intermediate(INT2, TA).leaf(LEAF, INT, INT2)
                .subordinate(INT, LEAF, s -> s.signWith(wrong)).build();

        TrustChainValidationResult result = f.validator(TA).validate(request().build());

        assertEquals(f.subordinateStatement(INT2, LEAF), result.trustChain().get(1));
    }

    @Test
    void whenNoRouteValidatesTheFirstFailureIsReportedNotNoRoute() {
        PublicJsonWebKey wrong = Keys.ec("wrong-1");
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).intermediate(INT2, TA).leaf(LEAF, INT, INT2)
                .subordinate(INT, LEAF, s -> s.signWith(wrong))
                .subordinate(INT2, LEAF, s -> s.signWith(wrong)).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.KID, e.kind(), "the forged statement names a key its superior never asserted: " + e.getMessage());
        assertEquals(INT, e.issuer(), "the first route tried");
    }

    @Test
    @Requirement("OIDFED §3.2(2.6)")
    void aPresentedStatementByAnAuthorityTheSubjectDoesNotNameIsPassedOver() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).intermediate(INT2, TA).leaf(LEAF, INT).build();
        // A genuine statement by INT2 about the leaf - but the leaf never named INT2 as a superior.
        String stray = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", INT2).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).sign(f.key(INT2), f.clock());
        List<String> presented = List.of(f.entityConfiguration(LEAF), stray, f.subordinateStatement(TA, INT2));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(f.subordinateStatement(INT, LEAF), result.trustChain().get(1), "the route runs through the named superior");
    }

    // ---- the checks that need the whole route --------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void anIntermediateMaySignOnlyWithAKeyInItsOwnConfiguration() {
        PublicJsonWebKey a = Keys.ec("int-a");
        PublicJsonWebKey b = Keys.ec("int-b");
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .keys(INT, a, b)
                .entityConfiguration(INT, s -> s.claim("jwks", Keys.publicJwks(a)))
                .subordinate(INT, LEAF, s -> s.signWith(b)).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.KID, e.kind(), e.getMessage());
        assertTrue(e.getMessage().contains("own Entity Configuration"), e.getMessage());
    }

    @Test
    @Requirement({"OIDFED §10.2(3.3)", "OIDFED §4(8.1)"})
    void theSubjectsConfigurationMustAlsoVerifyWithItsOwnKeys() {
        PublicJsonWebKey other = Keys.ec("other-1");
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .entityConfiguration(LEAF, s -> s.claim("jwks", Keys.publicJwks(other))).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().presentedChain(f.chain(LEAF, TA)).build()));

        assertEquals(Kind.KID, e.kind(), e.getMessage());
        assertEquals(LEAF, e.subject());
    }

    // ---- presented statements: stale, broken, ambiguous ------------------------------------------------

    @Test
    void anExpiringPresentedStatementIsFetchedAfresh() {
        Federation f = threeLevels();
        long now = java.time.Instant.now().getEpochSecond();
        String expiring = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", INT).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).exp(now + 120).sign(f.key(INT), f.clock());
        List<String> presented = List.of(f.entityConfiguration(LEAF), expiring, f.subordinateStatement(TA, INT));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(f.subordinateStatement(INT, LEAF), result.trustChain().get(1), "the fresh copy replaces the expiring one");
    }

    @Test
    void aRefreshThatFailsKeepsThePresentedStatement() {
        Federation f = threeLevels();
        long now = java.time.Instant.now().getEpochSecond();
        String expiring = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", INT).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).exp(now + 120).sign(f.key(INT), f.clock());
        f.http().failing(INT + "/.well-known/openid-federation", new IOException("down"));
        List<String> presented = List.of(f.entityConfiguration(LEAF), expiring, f.subordinateStatement(TA, INT));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(expiring, result.trustChain().get(1));
        assertEquals(now + 120, result.expEpochSeconds());
    }

    @Test
    void presentedStatementsOlderThanTheCallerAllowsAreDroppedAndDiscovered() {
        Federation f = threeLevels();
        long now = java.time.Instant.now().getEpochSecond();
        String old = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", INT).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).iat(now - 7200).sign(f.key(INT), f.clock());
        List<String> presented = List.of(f.entityConfiguration(LEAF), old, f.subordinateStatement(TA, INT));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented)
                .maxPresentedEntryAgeSeconds(3600).build());

        assertEquals(f.subordinateStatement(INT, LEAF), result.trustChain().get(1));
        assertTrue(f.http().hitsStartingWith(INT + "/fetch") >= 1);
    }

    @Test
    void aStatementThatIsNotAJwtRefusesThePresentedChain() {
        Federation f = threeLevels();
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().presentedChain(List.of("not.a.jwt", f.entityConfiguration(LEAF))).build()));
        assertEquals(Kind.SYNTAX, e.kind());
    }

    @Test
    void twoPresentedConfigurationsOfAnIntermediateLeaveItToDiscovery() {
        Federation f = threeLevels();
        String second = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", INT).claim("sub", INT)
                .claim("jwks", f.publicJwks(INT)).claim("authority_hints", List.of(TA)).sign(f.key(INT), f.clock());
        List<String> presented = List.of(f.entityConfiguration(LEAF), f.entityConfiguration(INT), second);

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(f.chain(LEAF, TA), result.trustChain());
    }

    @Test
    @Requirement("OIDFED §10.5(1)")
    void aSubjectThatCannotBeReachedIsTemporarilyUnavailable() {
        Federation f = threeLevels();
        f.http().failing(LEAF + "/.well-known/openid-federation", new IOException("connection refused"));

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.TRANSPORT, e.kind());
        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, e.error());
    }

    @Test
    void anAuthorityThatCannotBeReachedIsTemporarilyUnavailableWhenNoOtherRouteExists() {
        Federation f = threeLevels();
        f.http().failing(INT + "/.well-known/openid-federation", new IOException("timed out"));

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.TRANSPORT, e.kind());
    }

    @Test
    @Requirement("OIDFED §8.9")
    void aSubjectThatAnswersWithSomethingElseIsNotFound() {
        Federation f = threeLevels();
        f.http().put(LEAF + "/.well-known/openid-federation", f.entityConfiguration(INT));

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(request().build()));

        assertEquals(Kind.SUBJECT, e.kind());
        assertEquals(FederationError.NOT_FOUND, e.error());
    }

    // ---- peer_trust_chain -----------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §4.4(1)", "OIDFED §3.2(2.25)"})
    void aPeerTrustChainAboutTheOpValidatesAlongside() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).leaf(OP, TA).build();

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(f.chain(LEAF, TA))
                .peerTrustChain(f.chain(OP, TA)).build());

        assertEquals(OP, result.peerChain().orElseThrow().leafSubject());
    }

    @Test
    @Requirement("OIDFED §4.4(1)")
    void aPeerTrustChainEndingAtAnotherAnchorIsRefusedUnlessAllowed() {
        Federation f = Federation.builder().anchor(TA).anchor(TA2).leaf(LEAF, TA).leaf(OP, TA2).build();
        ValidationRequest withPeer = request().presentedChain(f.chain(LEAF, TA)).peerTrustChain(f.chain(OP, TA2)).build();

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(ValidatorOptions.defaults(), TA, TA2).validate(withPeer));
        assertEquals(Kind.PEER_CHAIN, e.kind());

        TrustChainValidationResult relaxed = f.validator(ValidatorOptions.defaults().withRequirePeerChainSameAnchor(false), TA, TA2)
                .validate(withPeer);
        assertEquals(TA2, relaxed.peerChain().orElseThrow().trustAnchorIssuer());
    }

    @Test
    void aPeerTrustChainNeedsTheOpItIsAbout() {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA).leaf(OP, TA).build();
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(ValidationRequest.forSubject(LEAF).peerTrustChain(f.chain(OP, TA)).build()));
        assertEquals(Kind.PEER_CHAIN, e.kind());
    }

    // ---- construction ---------------------------------------------------------------------------------

    @Test
    void aValidatorNeedsAnAnchorAndSensibleLimits() {
        Federation f = threeLevels();
        assertThrows(IllegalArgumentException.class,
                () -> new TrustChainValidator(f.gateway(TA), TrustAnchorSet.empty(), null, null));
        assertThrows(IllegalArgumentException.class, () -> ValidatorOptions.defaults().withMaxFetches(0));
        assertThrows(IllegalArgumentException.class, () -> ValidatorOptions.defaults().withMaxAuthorityHints(0));
        assertThrows(IllegalArgumentException.class, () -> ValidatorOptions.defaults().withClockSkewSeconds(-1));
        assertThrows(IllegalArgumentException.class, () -> ValidatorOptions.defaults().withMaxRouteAttempts(0));
        assertEquals(java.time.Clock.systemUTC().getZone(), ValidatorOptions.defaults().withClock(null).clock().getZone());
        TrustChainValidator validator = new TrustChainValidator(f.gateway(TA), f.trustAnchors(), null, null);
        assertEquals(ValidatorOptions.defaults().maxFetches(), validator.options().maxFetches());
        assertEquals(List.of(TA), validator.trustAnchors().entityIds());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(ValidationRequest.forSubject(" ").build()));
        assertEquals(Map.of(), new TrustChainValidationResult.Builder().build().resolvedMetadata());
    }
}
