package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The validator's handling of what a hostile or broken federation hands it: statements that are not what
 * they claim, authorities that do not answer or answer with something else, stale statements, a route too
 * deep to follow, and the budget running out part way.
 */
class TrustChainValidatorEdgeTest {
    private static final String TA = "https://ta.example";
    private static final String INT = "https://int.example";
    private static final String LEAF = "https://rp.example";
    private static final String OP = "https://op.example";
    private static final String EVIL = "http://evil.example";

    private static Federation threeLevels() {
        return Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).build();
    }

    private static ValidationRequest.Builder request() {
        return ValidationRequest.forSubject(LEAF).opIssuer(OP);
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static String fetchUrl(Federation f, String issuer, String subject) {
        return f.fetchEndpoint(issuer) + "?sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8);
    }

    private static String statement(Federation f, String iss, String sub, java.util.function.Consumer<Statements.Spec> change) {
        Statements.Spec spec = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", iss).claim("sub", sub)
                .claim("jwks", f.publicJwks(LEAF));
        change.accept(spec);
        return spec.sign(f.key(iss), f.clock());
    }

    private static TrustChainValidationException refused(TrustChainValidator validator, ValidationRequest request) {
        return assertThrows(TrustChainValidationException.class, () -> validator.validate(request));
    }

    // ---- depth, budget -----------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aRouteDeeperThanTheLimitIsNotFollowed() {
        Federation.Builder builder = Federation.builder().anchor(TA);
        String superior = TA;
        for (int i = TrustChainValidator.MAX_ROUTE_STATEMENTS; i >= 0; i--) {
            String intermediate = "https://int-" + i + ".example";
            builder.intermediate(intermediate, superior);
            superior = intermediate;
        }
        Federation f = builder.leaf(LEAF, superior).build();

        TrustChainValidationException e = refused(f.validator(ValidatorOptions.defaults().withMaxFetches(200), TA),
                request().presentedChain(f.chain(LEAF, TA)).build());

        assertEquals(Kind.ROUTE, e.kind());
    }

    @Test
    void aBudgetSpentOnThePeerChainEndsTheWholeValidation() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).leaf(OP, TA).build();

        TrustChainValidationException e = refused(f.validator(ValidatorOptions.defaults().withMaxFetches(1), TA),
                request().presentedChain(f.chain(LEAF, TA)).peerTrustChain(List.of(f.entityConfiguration(TA))).build());

        assertEquals(Kind.BUDGET, e.kind(), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void onlySoManyRoutesAreVerifiedBeforeTheFirstFailureIsReported() {
        Federation.Builder builder = Federation.builder().anchor(TA);
        List<String> intermediates = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            String intermediate = "https://int" + i + ".example";
            builder.intermediate(intermediate, TA);
            intermediates.add(intermediate);
        }
        builder.leaf(LEAF, intermediates.toArray(new String[0]));
        for (String intermediate : intermediates) {
            builder.subordinate(intermediate, LEAF, s -> s.signWith(com.pingidentity.ps.oidf.federation.testkit.Keys.ec("forger")));
        }
        Federation f = builder.build();

        TrustChainValidationException e = refused(f.validator(ValidatorOptions.defaults().withMaxRouteAttempts(2), TA), request().build());

        assertEquals("https://int1.example", e.issuer(), "the first route's failure");
        assertEquals(0, f.http().hitsStartingWith("https://int3.example/fetch"), "the third route is never fetched: "
                + f.http().requests());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void presentedStatementsCannotMakeTheSearchUnbounded() {
        Federation.Builder builder = Federation.builder().anchor(TA);
        List<String> dead = new ArrayList<>();
        for (int i = 0; i <= TrustChainValidator.MAX_SEARCH_STEPS; i++) {
            String intermediate = "https://dead-end-" + i + ".example";
            builder.intermediate(intermediate);
            dead.add(intermediate);
        }
        Federation f = builder.leaf(LEAF, dead.toArray(new String[0])).build();
        List<String> presented = new ArrayList<>();
        presented.add(f.entityConfiguration(LEAF));
        for (String intermediate : dead) {
            presented.add(f.subordinateStatement(intermediate, LEAF));
            presented.add(f.entityConfiguration(intermediate));
        }

        TrustChainValidationException e = refused(f.validator(TA), request().presentedChain(presented).build());

        assertEquals(Kind.BUDGET, e.kind(), e.getMessage());
        assertEquals(List.of(), f.http().requests(), "no fetch was needed to get there");
    }

    // ---- authorities that do not answer, or answer with something else -------------------------------

    @Test
    void anIntermediateWhoseConfigurationCannotBeFetchedEndsThatRoute() {
        Federation f = threeLevels();
        f.http().failing(INT + "/.well-known/openid-federation", new IOException("down"));

        TrustChainValidationException e = refused(f.validator(TA),
                request().presentedChain(List.of(f.entityConfiguration(LEAF), f.subordinateStatement(INT, LEAF))).build());

        assertEquals(Kind.TRANSPORT, e.kind());
    }

    @Test
    void aTransportFailureWrappedInAnotherExceptionIsStillTransport() {
        Federation f = threeLevels();
        f.http().failing(LEAF + "/.well-known/openid-federation", new IllegalStateException(new IOException("reset")));

        assertEquals(Kind.TRANSPORT, refused(f.validator(TA), request().build()).kind());
    }

    @Test
    @Requirement("OIDFED §1.2(3.4)")
    void aHintThatIsNotAnEntityIdentifierIsNeverFetched() {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA)
                .entityConfiguration(LEAF, s -> s.claim("authority_hints", List.of(EVIL))).build();

        assertEquals(Kind.ROUTE, refused(f.validator(TA), request().build()).kind());
        assertEquals(0, f.http().hitsStartingWith(EVIL));

        String byEvil = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", EVIL).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).sign(f.key(LEAF), f.clock());
        assertEquals(Kind.ROUTE, refused(f.validator(TA), request().presentedChain(List.of(f.entityConfiguration(LEAF), byEvil))
                .build()).kind());
        assertEquals(0, f.http().hitsStartingWith(EVIL), "a presented statement by it does not get it fetched either");
    }

    @Test
    void aSubjectConfigurationUrlThatServesSomethingElseIsNotAConfiguration() {
        for (String body : new String[] {"", "garbage", null}) {
            Federation f = threeLevels();
            if (body == null) {
                f.http().put(LEAF + "/.well-known/openid-federation", f.subordinateStatement(INT, LEAF));
            } else {
                f.http().put(LEAF + "/.well-known/openid-federation", body);
            }
            TrustChainValidationException e = refused(f.validator(TA), request().build());
            assertEquals(Kind.SUBJECT, e.kind(), String.valueOf(body));
            assertEquals(FederationError.NOT_FOUND, e.error());
        }
    }

    @Test
    void aFetchEndpointThatAnswersWithTheWrongStatementIsNotUsed() {
        for (int variant = 0; variant < 3; variant++) {
            Federation f = threeLevels();
            String answer = switch (variant) {
                case 0 -> "";
                case 1 -> f.subordinateStatement(TA, INT);
                default -> statement(f, INT, OP, s -> s.claim("jwks", f.publicJwks(LEAF)));
            };
            f.http().put(fetchUrl(f, INT, LEAF), answer);

            assertEquals(Kind.ROUTE, refused(f.validator(TA), request().build()).kind(), "variant " + variant);
        }
    }

    // ---- presented statements: duplicates, stale, broken -------------------------------------------

    @Test
    void aSecondPresentedStatementFromTheSameSuperiorIsNotTriedAgain() {
        Federation f = threeLevels();
        List<String> presented = List.of(f.entityConfiguration(LEAF), f.subordinateStatement(INT, LEAF),
                f.subordinateStatement(INT, LEAF), f.subordinateStatement(TA, INT));

        assertEquals(TA, f.validator(TA).validate(request().presentedChain(presented).build()).trustAnchorIssuer());
    }

    @Test
    void onlyTheFirstPresentedStatementFromASuperiorIsTried() {
        Federation f = threeLevels();
        String forged = statement(f, INT, LEAF, s -> s.signWith(f.key(LEAF)).kid(f.key(INT).getKeyId()));
        List<String> presented = List.of(f.entityConfiguration(LEAF), forged, f.subordinateStatement(INT, LEAF),
                f.subordinateStatement(TA, INT));

        TrustChainValidationException e = refused(f.validator(TA), request().presentedChain(presented).build());

        assertEquals(Kind.SIGNATURE, e.kind(), "the genuine second copy is not tried after the first failed: " + e.getMessage());
    }

    @Test
    void aPresentedStatementWithoutIatIsRefused() {
        Federation f = threeLevels();
        String noIat = statement(f, INT, LEAF, Statements.Spec::withoutIat);

        TrustChainValidationException e = refused(f.validator(ValidatorOptions.defaults().withMaxFetches(1), TA), request()
                .presentedChain(List.of(f.entityConfiguration(LEAF), noIat, f.subordinateStatement(TA, INT))).build());

        assertEquals(Kind.MISSING_CLAIM, e.kind(), e.getMessage());
    }

    @Test
    void aGatewayThatAnswersWithNothingHasNoConfiguration() {
        Federation f = threeLevels();
        TrustControllerGateway silent = new DelegatingGateway(f.gateway(TA)) {
            @Override
            public String fetchEntityStatement(String issuer, long maxAge, SubordinateStatementCache.PendingWrites pending) {
                return null;
            }
        };

        assertEquals(Kind.SUBJECT, refused(new TrustChainValidator(silent, f.trustAnchor(TA)), request().build()).kind());
    }

    @Test
    void aPresentedConfigurationWithoutExpIsFetchedAfresh() {
        Federation f = threeLevels();
        String noExp = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", LEAF).claim("sub", LEAF)
                .claim("jwks", f.publicJwks(LEAF)).claim("authority_hints", List.of(INT)).withoutExp().sign(f.key(LEAF), f.clock());
        List<String> presented = List.of(noExp, f.subordinateStatement(INT, LEAF), f.subordinateStatement(TA, INT));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented).build());

        assertEquals(f.entityConfiguration(LEAF), result.trustChain().get(0));
    }

    @Test
    void aPresentedStatementOlderThanTheCallerAllowsIsFetchedAfresh() {
        Federation f = threeLevels();
        String old = statement(f, INT, LEAF, s -> s.iat(now() - 600));
        List<String> presented = List.of(f.entityConfiguration(LEAF), old, f.subordinateStatement(TA, INT));

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(presented)
                .maxLeafAgeSeconds(300).maxAnchorAgeSeconds(300).build());

        assertEquals(f.subordinateStatement(INT, LEAF), result.trustChain().get(1));
    }

    @Test
    void whenNoBudgetIsLeftAnExpiringStatementIsValidatedAsPresented() {
        Federation f = threeLevels();
        String expiring = statement(f, INT, LEAF, s -> s.exp(now() + 120));

        TrustChainValidationResult result = f.validator(ValidatorOptions.defaults().withMaxFetches(1), TA)
                .validate(request().presentedChain(List.of(expiring, f.subordinateStatement(TA, INT))).build());

        assertEquals(expiring, result.trustChain().get(1));
    }

    @Test
    void aRefreshThatReturnsSomethingElseKeepsThePresentedStatement() {
        for (int variant = 0; variant < 3; variant++) {
            Federation f = threeLevels();
            String expiring = statement(f, INT, LEAF, s -> s.exp(now() + 120));
            String answer = switch (variant) {
                case 0 -> "";
                case 1 -> statement(f, INT, OP, s -> s.claim("jwks", f.publicJwks(LEAF)));
                default -> f.subordinateStatement(TA, INT);
            };
            f.http().put(fetchUrl(f, INT, LEAF), answer);

            TrustChainValidationResult result = f.validator(TA).validate(request()
                    .presentedChain(List.of(f.entityConfiguration(LEAF), expiring, f.subordinateStatement(TA, INT))).build());

            assertEquals(expiring, result.trustChain().get(1), "variant " + variant);
        }
    }

    @Test
    @Requirement({"OIDFED §3.2(2.8)", "OIDFED §10.2(3.1.2.3)"})
    void anExpiredStatementThatCannotBeRefreshedIsRefused() {
        Federation f = threeLevels();
        String expired = statement(f, INT, LEAF, s -> s.iat(now() - 7200).exp(now() - 3600));
        f.http().failing(fetchUrl(f, INT, LEAF), new IOException("down"));

        TrustChainValidationException e = refused(f.validator(TA), request()
                .presentedChain(List.of(f.entityConfiguration(LEAF), expired, f.subordinateStatement(TA, INT))).build());

        assertEquals(Kind.EXP, e.kind(), e.getMessage());
    }

    @Test
    @Requirement({"OIDFED §3.2(2.7)", "OIDFED §10.2(3.1.2.2)"})
    void aStatementIssuedInTheFutureIsRefused() {
        Federation f = threeLevels();
        String early = statement(f, INT, LEAF, s -> s.iat(now() + 3600).exp(now() + 7200));

        TrustChainValidationException e = refused(f.validator(TA), request()
                .presentedChain(List.of(f.entityConfiguration(LEAF), early, f.subordinateStatement(TA, INT))).build());

        assertEquals(Kind.IAT, e.kind(), e.getMessage());
    }

    @Test
    void aPresentedStatementWithoutASubjectOrWithAMalformedIatIsNotAnEntityStatement() {
        Federation f = threeLevels();
        String noSub = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", LEAF).sign(f.key(LEAF), f.clock());
        String stringIat = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", LEAF).claim("sub", LEAF)
                .claim("iat", "yesterday").sign(f.key(LEAF), f.clock());

        for (String broken : List.of(noSub, stringIat)) {
            TrustChainValidationException e = refused(f.validator(TA), request().presentedChain(List.of(broken)).build());
            assertEquals(Kind.SYNTAX, e.kind());
            assertTrue(e.getMessage().contains("Entity Statement"), e.getMessage());
        }
    }

    @Test
    @Requirement("OIDFED §3.2(2.14)")
    void aHintThatIsNotAStringIsSkippedOnTheWayAndRefusedAtValidation() {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA)
                .entityConfiguration(LEAF, s -> s.claim("authority_hints", Arrays.asList(7, TA))).build();

        assertEquals(Kind.SYNTAX, refused(f.validator(TA), request().build()).kind());
    }

    @Test
    void aRepeatedAnchorHintIsFollowedOnce() {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA)
                .entityConfiguration(LEAF, s -> s.claim("authority_hints", List.of(TA, TA))).build();

        assertEquals(TA, f.validator(TA).validate(request().build()).trustAnchorIssuer());
        assertEquals(1, f.http().hitsStartingWith(f.fetchEndpoint(TA)));
    }

    // ---- the anchor ---------------------------------------------------------------------------------

    @Test
    void aLiveAnchorVerifiesWithTheKeysItReadsNowAndRefusesWhenTheyAreNotUsable() {
        Federation f = threeLevels();
        TrustChainValidator live = new TrustChainValidator(f.gateway(TA), TrustAnchor.live(TA, () -> f.publicJwks(TA)));
        assertEquals(TA, live.validate(request().presentedChain(f.chain(LEAF, TA)).build()).trustAnchorIssuer());

        TrustChainValidator broken = new TrustChainValidator(f.gateway(TA), TrustAnchor.live(TA, () -> Map.of("keys", List.of())));
        TrustChainValidationException e = refused(broken, request().presentedChain(f.chain(LEAF, TA)).build());
        assertEquals(Kind.ANCHOR, e.kind());
    }

    @Test
    @Requirement("OIDFED §4(3)")
    void anAnchorConfigurationThatCannotBeHadIsLeftOut() {
        Federation budgetless = threeLevels();
        TrustChainValidationResult noBudget = budgetless.validator(ValidatorOptions.defaults().withMaxFetches(1), TA)
                .validate(request().includeAnchorConfiguration(true)
                        .presentedChain(List.of(budgetless.subordinateStatement(INT, LEAF), budgetless.subordinateStatement(TA, INT))).build());
        assertEquals(3, noBudget.trustChain().size(), "the one fetch went on the subject's configuration");

        Federation down = threeLevels();
        down.http().failing(TA + "/.well-known/openid-federation", new IOException("down"));
        TrustChainValidationResult unreachable = down.validator(TA).validate(request().includeAnchorConfiguration(true)
                .presentedChain(down.chain(LEAF, TA)).build());
        assertEquals(3, unreachable.trustChain().size());
    }

    @Test
    void aGatewayThatAnswersForTheAnchorWithAnotherStatementHasItLeftOut() {
        Federation f = threeLevels();
        for (String wrong : List.of(f.subordinateStatement(TA, INT), f.entityConfiguration(INT))) {
            TrustControllerGateway gateway = new DelegatingGateway(f.gateway(TA)) {
                @Override
                public String anchorConfiguration(TrustAnchor anchor, Set<String> algorithms,
                        SubordinateStatementCache.PendingWrites pendingWrites) {
                    return wrong;
                }
            };
            TrustChainValidationResult result = new TrustChainValidator(gateway, f.trustAnchor(TA))
                    .validate(request().includeAnchorConfiguration(true).presentedChain(f.chain(LEAF, TA)).build());
            assertEquals(3, result.trustChain().size());
        }
    }

    @Test
    void aPresentedAnchorConfigurationIsUsedWithoutAFetchWhenAskedFor() {
        Federation f = threeLevels();
        TrustChainValidationResult result = f.validator(TA).validate(request().includeAnchorConfiguration(true)
                .presentedChain(f.chainWithAnchor(LEAF, TA)).build());

        assertEquals(f.entityConfiguration(TA), result.trustChain().get(3));
        assertEquals(List.of(), f.http().requests());
    }

    // ---- policy and peer chain edges ------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.2(4)")
    void aPolicyThatSaysNothingDoesNotCountAsPolicing() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .metadata(LEAF, "openid_relying_party", Map.of("client_name", "rp"))
                .metadataPolicy(TA, INT, "openid_relying_party", Map.of("client_name", Map.of("regexp", "^rp$"))).build();

        TrustChainValidationResult result = f.validator(TA).validate(request().presentedChain(f.chain(LEAF, TA)).build());

        assertEquals(Set.of(), result.policedEntityTypes());
    }

    @Test
    void aPeerChainNeedsANonBlankOpAndAFailureSaysWhatWasRequired() {
        Federation f = Federation.builder().anchor(TA).anchor("https://ta2.example").leaf(LEAF, TA)
                .leaf(OP, "https://ta2.example").build();

        TrustChainValidationException blank = refused(f.validator(TA), ValidationRequest.forSubject(LEAF).opIssuer("  ")
                .presentedChain(f.chain(LEAF, TA)).peerTrustChain(f.chain(OP, "https://ta2.example")).build());
        assertEquals(Kind.PEER_CHAIN, blank.kind());

        TrustChainValidationException relaxed = refused(f.validator(ValidatorOptions.defaults().withRequirePeerChainSameAnchor(false), TA),
                request().presentedChain(f.chain(LEAF, TA)).peerTrustChain(f.chain(OP, "https://ta2.example")).build());
        assertEquals(Kind.PEER_CHAIN, relaxed.kind());
        assertFalse(relaxed.getMessage().contains("same trust anchor"), relaxed.getMessage());
    }

    // ---- the request and the legacy entry points ----------------------------------------------------

    @Test
    void nullAndBlankRequestEntriesAreNothingPresented() {
        ValidationRequest request = ValidationRequest.forSubject(LEAF)
                .presentedChain(Arrays.asList(null, " ", "a.b.c"))
                .requestedAnchors(null)
                .peerTrustChain(null)
                .build();
        assertEquals(List.of("a.b.c"), request.presentedChain());
        assertEquals(List.of(), request.requestedAnchors());
        assertEquals(List.of(), request.peerTrustChain());
        assertEquals(ValidationRequest.forSubject(LEAF).presentedChain(null).build().presentedChain(), List.of());
    }

    @Test
    void theLegacyOverloadsBehaveAsTheRequest() throws Exception {
        Federation f = threeLevels();
        TrustChainValidator validator = f.validator(TA);
        assertEquals(TA, validator.validate(f.chain(LEAF, TA), LEAF, OP).trustAnchorIssuer());
        assertEquals(TA, validator.validate(f.chain(LEAF, TA), LEAF, OP, -1L, -1L).trustAnchorIssuer());
        assertThrows(IllegalArgumentException.class, () -> validator.validate(f.chain(LEAF, TA), LEAF, " "));
        TrustChainValidationResult result = validator.validate(new ArrayList<>(f.chain(LEAF, TA)), LEAF, OP, -1L, -1L, -1L);
        assertEquals(f.entityConfiguration(LEAF), result.trustChain().get(0));
    }

    /** A gateway that forwards everything to another, for tests that override one answer. */
    private static class DelegatingGateway implements TrustControllerGateway {
        private final TrustControllerGateway delegate;

        DelegatingGateway(TrustControllerGateway delegate) {
            this.delegate = delegate;
        }

        @Override
        public org.jose4j.jwt.JwtClaims fetchEntityConfiguration() throws Exception {
            return this.delegate.fetchEntityConfiguration();
        }

        @Override
        public List<String> fetchMembers() throws Exception {
            return this.delegate.fetchMembers();
        }

        @Override
        public String fetchEntityStatement(String issuer) throws Exception {
            return this.delegate.fetchEntityStatement(issuer);
        }

        @Override
        public String fetchEntityStatement(String issuer, long maxAge, SubordinateStatementCache.PendingWrites pending) throws Exception {
            return this.delegate.fetchEntityStatement(issuer, maxAge, pending);
        }

        @Override
        public String fetchSubordinateStatement(String issuer, String subject) throws Exception {
            return this.delegate.fetchSubordinateStatement(issuer, subject);
        }

        @Override
        public String fetchSubordinateStatement(String issuer, String subject, long maxAge,
                SubordinateStatementCache.PendingWrites pending) throws Exception {
            return this.delegate.fetchSubordinateStatement(issuer, subject, maxAge, pending);
        }

        @Override
        public void bindTrustAnchor(TrustAnchor anchor, Set<String> algorithms) {
            this.delegate.bindTrustAnchor(anchor, algorithms);
        }
    }
}
