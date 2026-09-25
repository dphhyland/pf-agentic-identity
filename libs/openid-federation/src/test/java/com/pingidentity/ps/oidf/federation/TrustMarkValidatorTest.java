package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * OpenID Federation 1.0 §7.3: which Trust Marks an Entity carries are valid, against the anchor its chain reached - and
 * that a mark that is not never costs the Entity its chain.
 */
class TrustMarkValidatorTest {
    private static final String TA = "https://ta.example.com";
    private static final String RP = "https://rp.example.com";
    private static final String TMI = "https://tmi.example.com";
    private static final String OWNER = "https://owner.example.com";
    private static final String TYPE = "https://ta.example.com/marks/certified";

    private final MutableClock clock = MutableClock.startingNow();
    private final PublicJsonWebKey tmiKey = Keys.ec("tmi-1");
    private final PublicJsonWebKey rpKey = Keys.ec("rp-1");
    private final PublicJsonWebKey ownerKey = Keys.ec("owner-1");
    private EventCapture events;

    @BeforeEach
    void capture() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void release() {
        this.events.close();
    }

    /** A mark from {@code issuer} about the RP, as §7.1 wants it, then changed. */
    private String mark(PublicJsonWebKey signer, String issuer, Consumer<Statements.Spec> change) {
        Statements.Spec spec = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP)
                .claim("iss", issuer).claim("sub", RP).claim("trust_mark_type", TYPE);
        change.accept(spec);
        return spec.sign(signer, this.clock);
    }

    private String mark(Consumer<Statements.Spec> change) {
        return this.mark(this.tmiKey, TMI, change);
    }

    private String delegation(Consumer<Statements.Spec> change) {
        Statements.Spec spec = Statements.spec(TrustMarkValidator.DELEGATION_TYP)
                .claim("iss", OWNER).claim("sub", TMI).claim("trust_mark_type", TYPE);
        change.accept(spec);
        return spec.sign(this.ownerKey, this.clock);
    }

    /** {@code jwt} with its protected header replaced; what is tested fails before the signature is looked at. */
    private static String reheadered(String jwt, String headerJson) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + jwt.substring(jwt.indexOf('.'));
    }

    private static Map<String, Object> issuers(Object... typeThenIssuers) {
        Map<String, Object> claim = new LinkedHashMap<>();
        for (int i = 0; i + 1 < typeThenIssuers.length; i += 2) {
            claim.put((String) typeThenIssuers[i], typeThenIssuers[i + 1]);
        }
        return claim;
    }

    private Map<String, Object> owners() {
        return Map.of(TYPE, Map.of("sub", OWNER, "jwks", Keys.publicJwks(this.ownerKey)));
    }

    private static List<Map<String, Object>> entries(List<String> marks) {
        List<Map<String, Object>> entries = new ArrayList<>();
        for (String mark : marks) {
            Object type;
            try {
                type = JwtCodec.parseUnverifiedClaims(mark).getClaimValue("trust_mark_type");
            } catch (Exception e) {
                type = TYPE;
            }
            entries.add(Map.of("trust_mark_type", type, "trust_mark", mark));
        }
        return entries;
    }

    /** A federation in which the RP carries {@code marks} and the anchor's configuration carries {@code anchorClaims}. */
    private Federation federation(List<String> marks, Map<String, Object> anchorClaims) {
        return Federation.builder(this.clock).anchor(TA).leaf(RP, TA).leaf(TMI, TA)
                .keys(RP, this.rpKey).keys(TMI, this.tmiKey)
                .entityConfiguration(TA, s -> anchorClaims.forEach(s::claim))
                .entityConfiguration(RP, s -> s.claim("trust_marks", entries(marks)))
                .build();
    }

    private Federation federation(List<String> marks) {
        return this.federation(marks, Map.of("trust_mark_issuers", issuers(TYPE, List.of(TMI))));
    }

    private TrustMarkValidator.Result validate(Federation f, HttpPostClient status) {
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult chain = validator.validate(ValidationRequest.forSubject(RP).includeAnchorConfiguration(true).build());
        return new TrustMarkValidator(validator, Set.of(), this.clock, status).validate(chain);
    }

    private TrustMarkValidator.Result validate(Federation f) {
        return this.validate(f, null);
    }

    private TrustMarkValidator.Result validate(String mark) {
        return this.validate(this.federation(List.of(mark)));
    }

    /**
     * The RP's validated chain with its configuration changed afterwards - for marks and keys the statement checks
     * would refuse before a chain ever reached the validator.
     */
    private TrustMarkValidator.Result doctored(Map<String, Object> anchorClaims, Consumer<JwtClaims> change) {
        Federation f = this.federation(List.of(), anchorClaims);
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult real = validator.validate(ValidationRequest.forSubject(RP).includeAnchorConfiguration(true).build());
        JwtClaims leaf = real.leafEntityStatement();
        change.accept(leaf);
        return new TrustMarkValidator(validator, Set.of(), this.clock).validate(new TrustChainValidationResult.Builder()
                .trustAnchorIssuer(TA).leafSubject(RP).trustChain(real.trustChain()).leafEntityStatement(leaf).build());
    }

    private TrustMarkValidator.Result doctored(Consumer<JwtClaims> change) {
        return this.doctored(Map.of("trust_mark_issuers", issuers(TYPE, List.of(TMI))), change);
    }

    private void assertRejected(TrustMarkValidator.Result result, String mentioning) {
        assertEquals(List.of(), result.verified(), result.rejected().toString());
        assertEquals(1, result.rejected().size());
        assertTrue(result.rejected().get(0).reason().contains(mentioning), result.rejected().get(0).reason());
    }

    // ---- what validates ------------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §7.3(2)", "OIDFED §7.3(5.7)", "OIDFED §7(2)", "OIDFED §7(3)"})
    void aMarkFromAnIssuerTheAnchorRecognisesValidates() {
        String mark = this.mark(s -> { });

        TrustMarkValidator.Result result = this.validate(mark);

        assertEquals(1, result.verified().size(), result.rejected().toString());
        TrustMarkValidator.Verified verified = result.verified().get(0);
        assertEquals(TYPE, verified.type());
        assertEquals(TMI, verified.issuer());
        assertEquals(RP, verified.subject());
        assertEquals(mark, verified.jwt());
        assertTrue(result.has(TYPE));
        assertFalse(result.has("https://other.example/type"));
        assertEquals(List.of(Map.of("trust_mark_type", TYPE, "trust_mark", mark)), result.asClaim());
        assertEquals(TMI, this.events.only(FederationEvents.TRUST_MARK_VERIFIED).partner());
    }

    @Test
    @Requirement({"OIDFED §7(5)", "OIDFED §3.1.2(1.8)"})
    void anEntityMaySignItsOwnMarkWhereAnyoneMayIssueTheType() {
        String selfSigned = this.mark(this.rpKey, RP, s -> { });

        TrustMarkValidator.Result result = this.validate(this.federation(List.of(selfSigned),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of()))));

        assertEquals(RP, result.verified().get(0).issuer());
    }

    @Test
    @Requirement("OIDFED §7.1(2.12)")
    void aMarkWithoutExpDoesNotExpire() {
        TrustMarkValidator.Result result = this.validate(this.mark(Statements.Spec::withoutExp));

        assertEquals(-1L, result.verified().get(0).expiresAt());
        assertEquals(-1L, result.earliestExpiry());
    }

    @Test
    void theEarliestExpiryIsTheSoonestMark() {
        long soon = this.clock.epochSecond() + 600;
        String first = this.mark(s -> s.exp(soon));
        String second = this.mark(s -> s.claim("trust_mark_type", "https://ta.example.com/marks/other"));

        TrustMarkValidator.Result result = this.validate(this.federation(List.of(first, second),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of(TMI), "https://ta.example.com/marks/other", List.of(TMI)))));

        assertEquals(2, result.verified().size());
        assertEquals(soon, result.earliestExpiry());
    }

    @Test
    void anEntityWithoutMarksHasNone() {
        TrustMarkValidator.Result result = this.validate(Federation.builder(this.clock).anchor(TA).leaf(RP, TA).build());

        assertEquals(List.of(), result.verified());
        assertEquals(List.of(), result.rejected());
        assertEquals(List.of(), this.validate(this.federation(List.of())).verified(), "an empty trust_marks is none");
        assertEquals(List.of(), this.validate(this.federation(List.of())).rejected());
    }

    // ---- what the anchor recognises (§7, §3.1.2) ------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §7(2)", "OIDFED §3.1.2(1.8)"})
    void aTypeTheAnchorDoesNotListIsNotRecognised() {
        String mark = this.mark(s -> { });

        this.assertRejected(this.validate(this.federation(List.of(mark), Map.of("trust_mark_issuers",
                issuers("https://ta.example.com/marks/other", List.of(TMI))))), "does not recognise");
        this.assertRejected(this.validate(this.federation(List.of(mark), Map.of())), "does not recognise");
    }

    @Test
    @Requirement("OIDFED §3.1.2(1.8)")
    void anIssuerTheAnchorDoesNotNameForTheTypeIsRefused() {
        this.assertRejected(this.validate(this.federation(List.of(this.mark(s -> { })),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of("https://someone-else.example"))))), "not an issuer");
    }

    @Test
    @Requirement("OIDFED §7.3(2)")
    void anIssuerThatDoesNotValidateToTheSameAnchorIsNotTrusted() {
        PublicJsonWebKey stranger = Keys.ec("stranger-1");
        String mark = this.mark(stranger, "https://stranger.example.com", s -> { });

        this.assertRejected(this.validate(this.federation(List.of(mark),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of())))), "does not validate to the same trust anchor");
    }

    /** The anchor's configuration is where it says whose marks it recognises; a chain without it has it resolved. */
    @Test
    @Requirement("OIDFED §7.3(3)")
    void aChainWithoutTheAnchorsConfigurationHasItResolved() {
        Federation f = this.federation(List.of(this.mark(s -> { })));
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult chain = validator.validate(ValidationRequest.forSubject(RP).build());
        assertEquals(2, chain.trustChain().size(), "the chain stops at the anchor's statement about the RP");

        assertEquals(1, new TrustMarkValidator(validator, Set.of(), this.clock).validate(chain).verified().size());
    }

    @Test
    void withoutTheAnchorsConfigurationNoMarkIsRecognised() {
        Federation f = this.federation(List.of(this.mark(s -> { })));
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult real = validator.validate(ValidationRequest.forSubject(RP).build());
        TrustChainValidationResult elsewhere = new TrustChainValidationResult.Builder().trustAnchorIssuer("https://unpinned-ta.example.com")
                .leafSubject(RP).trustChain(real.trustChain()).leafEntityStatement(real.leafEntityStatement()).build();

        this.assertRejected(new TrustMarkValidator(validator, Set.of(), this.clock).validate(elsewhere), "could not be read");
    }

    // ---- the mark itself (§7.3 steps 1-7) ----------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §7(6)", "OIDFED §7.3(5.2)"})
    void aMarkMustBeTypedAsOne() {
        this.assertRejected(this.validate(this.mark(s -> s.typ("JWT"))), "not typed trust-mark+jwt");
        this.assertRejected(this.validate(this.mark(s -> s.typ(null))), "not typed trust-mark+jwt");
    }

    @Test
    @Requirement({"OIDFED §7.3(5.1)", "OIDFED §7.3(5.3)"})
    void aMarkMustBeSignedWithAnAcceptableAlgorithm() {
        this.assertRejected(this.validate(this.mark(Statements.Spec::unsigned)), "alg is not acceptable");
        this.assertRejected(this.validate(reheadered(this.mark(s -> { }), "{\"alg\":\"HS256\",\"typ\":\"trust-mark+jwt\",\"kid\":\"tmi-1\"}")),
                "alg is not acceptable");
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String jwe = b64.encodeToString("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\",\"typ\":\"trust-mark+jwt\"}"
                .getBytes(StandardCharsets.UTF_8)) + ".a.b.c.d";
        this.assertRejected(this.doctored(leaf -> leaf.setClaim("trust_marks", List.of(Map.of("trust_mark_type", TYPE, "trust_mark", jwe)))),
                "not a signed JWT");

        Federation f = this.federation(List.of(this.mark(s -> { })));
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult chain = validator.validate(ValidationRequest.forSubject(RP).includeAnchorConfiguration(true).build());
        this.assertRejected(new TrustMarkValidator(validator, Set.of("PS256"), this.clock).validate(chain), "alg is not acceptable");
        assertEquals(1, new TrustMarkValidator(validator, Set.of("ES256"), this.clock).validate(chain).verified().size(), "one it accepts");

        String algless = reheadered(this.mark(s -> { }), "{\"typ\":\"trust-mark+jwt\",\"kid\":\"tmi-1\"}");
        this.assertRejected(this.doctored(leaf -> leaf.setClaim("trust_marks", List.of(Map.of("trust_mark_type", TYPE, "trust_mark", algless)))),
                "alg is not acceptable");
    }

    @Test
    @Requirement("OIDFED §7(4)")
    void aMarkMustNameItsKey() {
        this.assertRejected(this.validate(this.mark(s -> s.kid(null))), "no kid");
        this.assertRejected(this.validate(this.mark(s -> s.kid(""))), "no kid");
    }

    @Test
    @Requirement({"OIDFED §7.1(2.2)", "OIDFED §7.1(2.4)", "OIDFED §7.1(2.8)"})
    void aMarkCarriesItsRequiredClaims() {
        this.assertRejected(this.validate(this.mark(s -> s.remove("iss"))), "no iss");
        this.assertRejected(this.validate(this.mark(s -> s.claim("iss", " "))), "no iss");
        this.assertRejected(this.validate(this.mark(s -> s.remove("sub"))), "no sub");
        this.assertRejected(this.validate(this.mark(Statements.Spec::withoutIat)), "no iat");
    }

    @Test
    @Requirement("OIDFED §7.3(5.4)")
    void aMarkAboutAnotherEntityIsRefused() {
        this.assertRejected(this.validate(this.mark(s -> s.claim("sub", "https://other.example.com"))), "about another entity");
    }

    @Test
    @Requirement({"OIDFED §7.3(5.5)", "OIDFED §7.3(5.6)"})
    void aMarkIsCurrent() {
        this.assertRejected(this.validate(this.mark(s -> s.iat(this.clock.epochSecond() + 120))), "issued in the future");
        this.assertRejected(this.validate(this.mark(s -> s.exp(this.clock.epochSecond() - 61))), "expired");
        this.assertRejected(this.validate(this.mark(s -> s.claim("exp", "tomorrow"))), "exp is not a number");
        assertEquals(1, this.validate(this.mark(s -> s.exp(this.clock.epochSecond() - 30))).verified().size(), "within the skew");
    }

    @Test
    @Requirement("OIDFED §7.3(5.7)")
    void aMarkMustBeSignedByTheIssuersKey() {
        PublicJsonWebKey impostor = Keys.ec("tmi-1");
        this.assertRejected(this.validate(this.mark(impostor, TMI, s -> { })), "signature");
    }

    @Test
    void anIssuerWithUnusableKeysVerifiesNothing() {
        String selfSigned = this.mark(this.rpKey, RP, s -> { });

        for (Object unusable : List.of(Map.of("keys", List.of()), "not a key set")) {
            this.assertRejected(this.doctored(Map.of("trust_mark_issuers", issuers(TYPE, List.of())), leaf -> {
                leaf.setClaim("trust_marks", entries(List.of(selfSigned)));
                leaf.setClaim("jwks", unusable);
            }), "not a usable set");
        }
    }

    @Test
    @Requirement("OIDFED §3.1.2(1.6)")
    void aListedTypeTheMarkDoesNotCarryIsRefused() {
        String mark = this.mark(s -> { });

        this.assertRejected(this.doctored(leaf -> leaf.setClaim("trust_marks",
                List.of(Map.of("trust_mark_type", "https://ta.example.com/marks/other", "trust_mark", mark)))), "not the one it is listed under");
    }

    @Test
    @Requirement("OIDFED §7.3(5.1)")
    void aMarkThatIsNotAJwtIsRejectedAndNamesNoIssuer() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String headerOnly = b64.encodeToString("{\"alg\":\"ES256\",\"typ\":\"trust-mark+jwt\",\"kid\":\"k\"}"
                .getBytes(StandardCharsets.UTF_8)) + ".not-json.sig";

        TrustMarkValidator.Result result = this.doctored(leaf -> leaf.setClaim("trust_marks",
                List.of(Map.of("trust_mark_type", TYPE, "trust_mark", "garbage"), Map.of("trust_mark_type", TYPE, "trust_mark", headerOnly))));

        assertEquals(2, result.rejected().size());
        for (TrustMarkValidator.Rejected rejected : result.rejected()) {
            assertNull(rejected.issuer());
            assertTrue(rejected.reason().contains("not a signed JWT"), rejected.reason());
        }
    }

    @Test
    void aChainThatIsNotOneHasNoAnchorConfiguration() {
        for (List<String> notAChain : List.of(List.<String>of(), List.of("not a statement"))) {
            assertNull(TrustMarkValidator.anchorConfiguration(new TrustChainValidationResult.Builder().trustAnchorIssuer(TA).leafSubject(RP)
                    .trustChain(notAChain).build()));
        }
    }

    @Test
    void aSubjectThatIsTheAnchorReadsItsOwnConfiguration() throws Exception {
        Federation f = Federation.builder(this.clock).anchor(TA).leaf(TMI, TA).keys(TMI, this.tmiKey)
                .entityConfiguration(TA, s -> s.claim("trust_mark_issuers", issuers(TYPE, List.of(TMI))))
                .build();
        TrustChainValidator validator = f.validator(ValidatorOptions.defaults().withClock(this.clock), TA);
        TrustChainValidationResult anchor = validator.validate(ValidationRequest.forSubject(TA).build());

        assertEquals(TA, TrustMarkValidator.anchorConfiguration(anchor).getSubject(), "a one-statement chain is the anchor's own");
    }

    @Test
    void anIssuerIsResolvedOnceHoweverManyOfItsMarksTheEntityCarries() throws Exception {
        String first = this.mark(s -> { });
        String second = this.mark(s -> s.claim("trust_mark_type", "https://ta.example.com/marks/other"));
        Federation f = this.federation(List.of(first, second),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of(TMI), "https://ta.example.com/marks/other", List.of(TMI))));
        List<String> asked = new ArrayList<>();
        LocalStatementSource counting = new LocalStatementSource() {
            @Override
            public String entityConfiguration(String entityId) {
                asked.add(entityId);
                return null;
            }

            @Override
            public String subordinateStatement(String issuer, String subject) {
                return null;
            }
        };
        TrustChainValidator validator = new TrustChainValidator(new LocalFirstTrustControllerGateway(f.gateway(TA), counting),
                f.trustAnchors(), Set.of(), ValidatorOptions.defaults().withClock(this.clock));
        TrustChainValidationResult chain = validator.validate(ValidationRequest.forSubject(RP).includeAnchorConfiguration(true).build());
        asked.clear();

        assertEquals(2, new TrustMarkValidator(validator, Set.of(), this.clock).validate(chain).verified().size());
        assertEquals(1, java.util.Collections.frequency(asked, TMI), "the issuer's chain is walked once: " + asked);
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void onlyTheFirstMarksAreExamined() {
        List<String> marks = new ArrayList<>();
        for (int i = 0; i <= TrustMarkValidator.MAX_MARKS_EXAMINED; i++) {
            marks.add(this.mark(s -> { }));
        }

        TrustMarkValidator.Result result = this.validate(this.federation(marks));

        assertEquals(TrustMarkValidator.MAX_MARKS_EXAMINED, result.verified().size());
        assertEquals(1, result.rejected().size());
        assertTrue(result.rejected().get(0).reason().startsWith("not examined"), result.rejected().get(0).reason());
        assertEquals(TMI, result.rejected().get(0).issuer());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void onlySoManyIssuersAreResolved() {
        Federation.Builder builder = Federation.builder(this.clock).anchor(TA).leaf(RP, TA).keys(RP, this.rpKey)
                .entityConfiguration(TA, s -> s.claim("trust_mark_issuers", issuers(TYPE, List.of())));
        List<String> marks = new ArrayList<>();
        for (int i = 0; i <= TrustMarkValidator.MAX_ISSUERS_RESOLVED; i++) {
            String issuer = "https://tmi-" + i + ".example.com";
            PublicJsonWebKey key = Keys.ec("tmi-" + i);
            builder.leaf(issuer, TA).keys(issuer, key);
            marks.add(this.mark(key, issuer, s -> { }));
        }
        Federation f = builder.entityConfiguration(RP, s -> s.claim("trust_marks", entries(marks))).build();

        TrustMarkValidator.Result result = this.validate(f);

        assertEquals(TrustMarkValidator.MAX_ISSUERS_RESOLVED, result.verified().size());
        assertTrue(result.rejected().get(0).reason().contains("resolves at most"), result.rejected().get(0).reason());
    }

    /** A failed resolution counts too, or a run of failing issuers would cost a chain walk each. */
    @Test
    void anIssuerThatFailedIsNotResolvedAgain() {
        PublicJsonWebKey stranger = Keys.ec("stranger-1");
        String first = this.mark(stranger, "https://stranger.example.com", s -> { });
        String second = this.mark(stranger, "https://stranger.example.com", s -> { });
        Federation f = this.federation(List.of(first, second), Map.of("trust_mark_issuers", issuers(TYPE, List.of())));

        TrustMarkValidator.Result result = this.validate(f);

        assertEquals(2, result.rejected().size());
        assertEquals(1, f.http().hits("https://stranger.example.com/.well-known/openid-federation"));
    }

    // ---- delegation (§7.2.2) ----------------------------------------------------------------------------------

    private TrustMarkValidator.Result delegated(String delegation) {
        String mark = this.mark(s -> {
            if (delegation != null) {
                s.claim("delegation", delegation);
            }
        });
        return this.validate(this.federation(List.of(mark),
                Map.of("trust_mark_issuers", issuers(TYPE, List.of(TMI)), "trust_mark_owners", this.owners())));
    }

    @Test
    @Requirement({"OIDFED §7.3(5.8)", "OIDFED §7.3(5.9)"})
    void aTypeWithAnOwnerNeedsADelegationFromIt() {
        assertEquals(1, this.delegated(this.delegation(s -> { })).verified().size());
        this.assertRejected(this.delegated(null), "needs a delegation");
    }

    @Test
    @Requirement({"OIDFED §7.2.2(4.1)", "OIDFED §7.2.2(4.2)", "OIDFED §7.2.2(4.3)", "OIDFED §7.2.1(2)", "OIDFED §7.2.1(3)"})
    void aDelegationIsASignedTypedJwtThatNamesItsKey() {
        this.assertRejected(this.delegated(this.delegation(s -> s.typ("JWT"))), "not typed trust-mark-delegation+jwt");
        this.assertRejected(this.delegated(this.delegation(Statements.Spec::unsigned)), "alg");
        this.assertRejected(this.delegated(this.delegation(s -> s.kid(null))), "no kid");
        this.assertRejected(this.delegated("not a jwt"), "not a signed JWT");
    }

    @Test
    @Requirement({"OIDFED §7.2.2(4.4)", "OIDFED §7.2.2(4.5)", "OIDFED §7.2.2(4.8)"})
    void aDelegationIsFromTheOwnerToThisIssuerForThisType() {
        this.assertRejected(this.delegated(this.delegation(s -> s.claim("sub", "https://another-issuer.example"))), "not to this issuer");
        this.assertRejected(this.delegated(this.delegation(s -> s.claim("iss", "https://not-the-owner.example"))), "not from the type's owner");
        this.assertRejected(this.delegated(this.delegation(s -> s.claim("trust_mark_type", "https://other/type"))), "for another type");
    }

    @Test
    @Requirement({"OIDFED §7.2.2(4.6)", "OIDFED §7.2.2(4.7)", "OIDFED §7.2.1(5.8)", "OIDFED §7.2.1(5.10)"})
    void aDelegationIsCurrent() {
        this.assertRejected(this.delegated(this.delegation(s -> s.iat(this.clock.epochSecond() + 120))), "issued in the future");
        this.assertRejected(this.delegated(this.delegation(s -> s.exp(this.clock.epochSecond() - 61))), "has expired");
        this.assertRejected(this.delegated(this.delegation(s -> s.claim("exp", "never"))), "has expired");
        this.assertRejected(this.delegated(this.delegation(Statements.Spec::withoutIat)), "no iat");
        assertEquals(1, this.delegated(this.delegation(Statements.Spec::withoutExp)).verified().size(), "exp is OPTIONAL");
    }

    @Test
    @Requirement("OIDFED §7.2.2(4.9)")
    void aDelegationMustBeSignedByTheOwnersKey() {
        String forged = Statements.spec(TrustMarkValidator.DELEGATION_TYP).claim("iss", OWNER).claim("sub", TMI).claim("trust_mark_type", TYPE)
                .sign(Keys.ec("owner-1"), this.clock);
        this.assertRejected(this.delegated(forged), "signature");
    }

    @Test
    @Requirement("OIDFED §7.3(5.9)")
    void aDelegationForATypeWithNoOwnerCannotValidate() {
        String mark = this.mark(s -> s.claim("delegation", this.delegation(d -> { })));

        this.assertRejected(this.validate(mark), "names no owner");
    }

    // ---- the issuer's status endpoint (§8.4) --------------------------------------------------------------------

    private Federation withStatusEndpoint(String mark) {
        return Federation.builder(this.clock).anchor(TA).leaf(RP, TA).leaf(TMI, TA)
                .keys(RP, this.rpKey).keys(TMI, this.tmiKey)
                .metadata(TMI, "federation_entity", Map.of("federation_trust_mark_status_endpoint", TMI + "/status"))
                .entityConfiguration(TA, s -> s.claim("trust_mark_issuers", issuers(TYPE, List.of(TMI))))
                .entityConfiguration(RP, s -> s.claim("trust_marks", entries(List.of(mark))))
                .build();
    }

    private String statusResponse(PublicJsonWebKey signer, String about, String status, Consumer<Statements.Spec> change) {
        Statements.Spec spec = Statements.spec(TrustMarkValidator.STATUS_RESPONSE_TYP)
                .claim("iss", TMI).claim("trust_mark", about).claim("status", status).withoutExp();
        change.accept(spec);
        return spec.sign(signer, this.clock);
    }

    private HttpPostClient answering(int status, String body, List<String> asked) {
        return (url, contentType, requestBody, headers, accept) -> {
            asked.add(url + " " + requestBody);
            return new HttpPostClient.Response(status, body, Map.of());
        };
    }

    @Test
    @Requirement({"OIDFED §7.3(7)", "OIDFED §8.4(2)", "OIDFED §8.4.1(1)", "OIDFED §8.4.2(5.8)"})
    void anActiveMarkPassesItsIssuersStatusCheck() {
        String mark = this.mark(s -> { });
        List<String> asked = new ArrayList<>();

        TrustMarkValidator.Result result = this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(this.tmiKey, mark, "active", s -> { }), asked));

        assertEquals(1, result.verified().size(), result.rejected().toString());
        assertEquals(1, asked.size());
        assertTrue(asked.get(0).startsWith(TMI + "/status trust_mark="), asked.get(0));
    }

    @Test
    @Requirement({"OIDFED §8.4.2(5.8)", "OIDFED §8.4.2(12)"})
    void anythingButActiveIsARejection() {
        String mark = this.mark(s -> { });
        for (String state : List.of("revoked", "expired", "invalid")) {
            this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                    this.answering(200, this.statusResponse(this.tmiKey, mark, state, s -> { }), new ArrayList<>())), "says it is " + state);
        }
        this.assertRejected(this.validate(this.withStatusEndpoint(mark), this.answering(404, "", new ArrayList<>())), "does not know it");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark), this.answering(500, "", new ArrayList<>())), "answered 500");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark), (u, c, b, h, a) -> {
            throw new java.io.IOException("down");
        }), "could not be reached");
    }

    @Test
    @Requirement({"OIDFED §8.4.2(2)", "OIDFED §8.4.2(3)", "OIDFED §8.4.2(5.2)", "OIDFED §8.4.2(5.6)"})
    void aStatusResponseMustBeTheIssuersSignedAnswerAboutThisMark() {
        String mark = this.mark(s -> { });
        this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(Keys.ec("tmi-1"), mark, "active", s -> { }), new ArrayList<>())), "signature");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(this.tmiKey, mark, "active", s -> s.typ("JWT")), new ArrayList<>())), "typed");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(this.tmiKey, mark, "active", s -> s.kid(null)), new ArrayList<>())), "no kid");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(this.tmiKey, "another mark", "active", s -> { }), new ArrayList<>())), "not its issuer's answer");
        this.assertRejected(this.validate(this.withStatusEndpoint(mark),
                this.answering(200, this.statusResponse(this.tmiKey, mark, "active", s -> s.claim("iss", RP)), new ArrayList<>())), "not its issuer's answer");
    }

    @Test
    void anIssuerWithoutAStatusEndpointIsNotAsked() {
        List<String> asked = new ArrayList<>();

        assertEquals(1, this.validate(this.federation(List.of(this.mark(s -> { }))), this.answering(500, "", asked)).verified().size());
        assertEquals(List.of(), asked);
    }
}
