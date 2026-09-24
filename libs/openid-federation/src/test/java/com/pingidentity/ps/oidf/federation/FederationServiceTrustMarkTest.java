package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.ServingMap;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.trustmark.InMemoryTrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkIssuer;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * This entity as a Trust Mark Issuer (OpenID Federation 1.0 §7, §8.4-§8.6): the marks it mints and publishes, the
 * three endpoints, the list filters, and - as a trust anchor - whose marks it says the federation accepts.
 */
class FederationServiceTrustMarkTest {
    private static final String PF = "https://pf.example";
    private static final String RP = "https://rp.example";
    private static final String HOSTED = "https://pf.example/federation/agents/a1";
    private static final String OPEN = "https://pf.example/marks/open";
    private static final String HOSTED_ONLY = "https://pf.example/marks/hosted";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");
    private static final PublicJsonWebKey RP_KEY = Keys.ec("rp-1");

    private final MutableClock clock = MutableClock.startingNow();
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);
    private final ServingMap http = new ServingMap();
    private EventCapture events;

    @BeforeEach
    void capture() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void release() {
        this.events.close();
    }

    private static FederationConfiguration configuration(List<String> authorityHints) {
        return new FederationConfiguration(authorityHints, List.of(RP), null, false, false, null, null, null, 0, "RS256",
                AttestationMetadataConfig.defaults(), null, null, FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES,
                FederationConfiguration.ResolveDiscovery.KNOWN);
    }

    private TrustMarkIssuer issuer() {
        Map<String, TrustMarkType> types = new LinkedHashMap<>();
        types.put(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, null, null, null));
        types.put(HOSTED_ONLY, new TrustMarkType(HOSTED_ONLY, 3600, TrustMarkType.Subjects.HOSTED, null, null, null));
        return new TrustMarkIssuer(types, this.registry, HOSTED::equals, this.clock);
    }

    /** PF, its own trust anchor, with RP as a configured subordinate and HOSTED hosted here. */
    private FederationService.Builder pf(List<String> authorityHints) {
        this.http.entityConfiguration(RP, this.rpConfiguration(List.of()));
        return FederationService.builder(configuration(authorityHints), Keys.signingKeys(PF_KEY))
                .subordinateFetcher(this.http)
                .hostedSubordinateIds(type -> List.of(HOSTED))
                .hosting(() -> true)
                .trustMarkIssuing(this.issuer())
                .clock(this.clock);
    }

    private FederationService pf() {
        return this.pf(List.of(PF)).build();
    }

    private String rpConfiguration(List<Map<String, Object>> trustMarks) {
        Statements.Spec spec = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", RP).claim("sub", RP)
                .claim("jwks", Keys.publicJwks(RP_KEY)).claim("authority_hints", List.of(PF))
                .claim("metadata", Map.of("openid_relying_party", Map.of("client_name", "RP")));
        if (!trustMarks.isEmpty()) {
            spec.claim("trust_marks", trustMarks);
        }
        return spec.sign(RP_KEY, this.clock);
    }

    private static JwtClaims claims(String jwt) throws Exception {
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    private static Map<?, ?> federationEntity(FederationService service) throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) claims(service.createEntityConfigurationJwt(PF)).getClaimValue("metadata")).get("federation_entity");
    }

    private static FederationException refusal(FederationError expected, org.junit.jupiter.api.function.Executable call) {
        FederationException e = assertThrows(FederationException.class, call);
        assertEquals(expected, e.error(), e.getMessage());
        return e;
    }

    // ---- advertising (§5.1.1) -------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §5.1.1(3.8)", "OIDFED §5.1.1(3.10)", "OIDFED §5.1.1(3.12)", "OIDFED §8.4(2)", "OIDFED §8.5(2)", "OIDFED §8.6(2)"})
    void anEntityThatIssuesTrustMarksAdvertisesItsThreeEndpoints() throws Exception {
        Map<?, ?> advertised = federationEntity(this.pf());

        assertEquals(PF + "/federation/trust_mark", advertised.get("federation_trust_mark_endpoint"));
        assertEquals(PF + "/federation/trust_mark_status", advertised.get("federation_trust_mark_status_endpoint"));
        assertEquals(PF + "/federation/trust_marked_list", advertised.get("federation_trust_mark_list_endpoint"));

        Map<?, ?> without = federationEntity(this.pf(List.of(PF)).trustMarkIssuing(null).build());
        assertFalse(without.containsKey("federation_trust_mark_endpoint"), "an entity that issues none advertises none");
        assertFalse(this.pf(List.of(PF)).trustMarkIssuing(new TrustMarkIssuer(Map.of(), this.registry, id -> true, this.clock)).build()
                .issuesTrustMarks(), "nor does one configured with no types");
    }

    // ---- the Trust Mark endpoint (§8.6) --------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §8.6.1(2.2)", "OIDFED §8.6.1(2.4)", "OIDFED §8.6.2(1)", "OIDFED §7(3)", "OIDFED §7(4)", "OIDFED §7(6)"})
    void theTrustMarkEndpointAnswersAMarkSignedWithThisEntitysKey() throws Exception {
        this.registry.grant(OPEN, RP, null, "admin:test");
        FederationService service = this.pf();

        String mark = service.trustMark(OPEN, RP, PF);

        assertEquals(TrustMarkValidator.TRUST_MARK_TYP, JwtCodec.getJwtHeaders(mark).get("typ"));
        assertEquals("pf-1", JwtCodec.getJwtHeaders(mark).get("kid"));
        JwtClaims verified = JwtCodec.verifySignature(mark, List.of(PF_KEY), Set.of());
        assertEquals(PF, verified.getIssuer());
        assertEquals(RP, verified.getSubject());
        assertEquals(OPEN, verified.getClaimValue("trust_mark_type"));
        assertEquals(mark, service.trustMark(OPEN, RP, PF), "the same mark while it is fresh");
        assertEquals(1, this.events.withCode(FederationEvents.TRUST_MARK_ISSUED).size(), "one mark minted, one audit line");
        assertEquals(RP, this.events.only(FederationEvents.TRUST_MARK_ISSUED).subject());
        this.events.assertNoJwtIn();
    }

    @Test
    void aMarkIsMintedAgainOnceHalfItsLifeIsGoneOrItsGrantIsGivenAgain() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        FederationService service = this.pf();
        String first = service.trustMark(OPEN, RP, PF);

        this.clock.advance(Duration.ofMinutes(29));
        assertEquals(first, service.trustMark(OPEN, RP, PF));
        this.clock.advance(Duration.ofMinutes(2));
        String second = service.trustMark(OPEN, RP, PF);
        assertNotEquals(first, second, "past half its life");

        this.clock.advance(Duration.ofSeconds(1));
        this.registry.grant(OPEN, RP, null, null);
        assertNotEquals(second, service.trustMark(OPEN, RP, PF), "a grant given again");
    }

    @Test
    @Requirement({"OIDFED §8.6.2(2)", "OIDFED §8.9(2.2.4.1)"})
    void theTrustMarkEndpointRefusesWhatItCannotAnswer() {
        FederationService service = this.pf();

        refusal(FederationError.INVALID_REQUEST, () -> service.trustMark(null, RP, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMark(" ", RP, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMark(OPEN, null, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMark(OPEN, " ", PF));
        refusal(FederationError.NOT_FOUND, () -> service.trustMark(OPEN, RP, PF));
        refusal(FederationError.NOT_FOUND, () -> service.trustMark(HOSTED_ONLY, RP, PF));
        refusal(FederationError.NOT_FOUND, () -> this.pf(List.of(PF)).trustMarkIssuing(null).build().trustMark(OPEN, RP, PF));
    }

    // ---- the status endpoint (§8.4) --------------------------------------------------------------------

    private static JwtClaims statusOf(String response) throws Exception {
        assertEquals(TrustMarkValidator.STATUS_RESPONSE_TYP, JwtCodec.getJwtHeaders(response).get("typ"));
        assertEquals("pf-1", JwtCodec.getJwtHeaders(response).get("kid"));
        return JwtCodec.verifySignature(response, List.of(PF_KEY), Set.of());
    }

    @Test
    @Requirement({"OIDFED §8.4.1(2.2)", "OIDFED §8.4.2(1)", "OIDFED §8.4.2(2)", "OIDFED §8.4.2(3)", "OIDFED §8.4.2(5.2)", "OIDFED §8.4.2(5.4)",
            "OIDFED §8.4.2(5.6)", "OIDFED §8.4.2(5.8)"})
    void theStatusEndpointAnswersASignedStatusResponse() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        FederationService service = this.pf();
        String mark = service.trustMark(OPEN, RP, PF);

        JwtClaims status = statusOf(service.trustMarkStatus(mark, PF));

        assertEquals(PF, status.getIssuer());
        assertEquals(this.clock.epochSecond(), status.getIssuedAt().getValue());
        assertEquals(mark, status.getClaimValue("trust_mark"));
        assertEquals("active", status.getClaimValue("status"));

        this.registry.revoke(OPEN, RP, "withdrawn", null);
        assertEquals("revoked", statusOf(service.trustMarkStatus(mark, PF)).getClaimValue("status"));
    }

    @Test
    @Requirement("OIDFED §8.4.2(5.8.2.8)")
    void aMarkNamingThisEntityThatItDidNotSignIsInvalid() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        FederationService service = this.pf();
        String forged = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", PF).claim("sub", RP).claim("trust_mark_type", OPEN)
                .sign(Keys.rsa("pf-1"), this.clock);
        String untyped = Statements.spec("JWT").claim("iss", PF).claim("sub", RP).claim("trust_mark_type", OPEN).sign(PF_KEY, this.clock);

        assertEquals("invalid", statusOf(service.trustMarkStatus(forged, PF)).getClaimValue("status"));
        assertEquals("invalid", statusOf(service.trustMarkStatus(untyped, PF)).getClaimValue("status"));
    }

    @Test
    @Requirement({"OIDFED §8.4.2(11)", "OIDFED §8.4.2(12)"})
    void theStatusEndpointRefusesWhatItCannotAnswer() {
        FederationService service = this.pf();
        String unknown = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", PF).claim("sub", RP).claim("trust_mark_type", OPEN)
                .sign(PF_KEY, this.clock);
        String someoneElses = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", "https://tmi.example").claim("sub", RP)
                .claim("trust_mark_type", OPEN).sign(PF_KEY, this.clock);

        refusal(FederationError.INVALID_REQUEST, () -> service.trustMarkStatus(null, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMarkStatus(" ", PF));
        String anonymous = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).remove("iss").claim("sub", RP).claim("trust_mark_type", OPEN)
                .sign(PF_KEY, this.clock);
        refusal(FederationError.NOT_FOUND, () -> service.trustMarkStatus(anonymous, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMarkStatus("not a jwt", PF));
        refusal(FederationError.NOT_FOUND, () -> service.trustMarkStatus(someoneElses, PF));
        refusal(FederationError.NOT_FOUND, () -> service.trustMarkStatus(unknown, PF));
        refusal(FederationError.NOT_FOUND, () -> this.pf(List.of(PF)).trustMarkIssuing(null).build().trustMarkStatus(unknown, PF));
    }

    // ---- the Trust Marked Entities Listing (§8.5) and the list filters (§8.2.1) ------------------------------------

    @Test
    @Requirement({"OIDFED §8.5.1(2.2)", "OIDFED §8.5.1(2.4)", "OIDFED §8.5.2(1)"})
    void theTrustMarkedListNamesTheEntitiesHoldingAValidMarkOfTheType() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        this.registry.grant(OPEN, HOSTED, null, null);
        this.registry.grant(OPEN, "https://gone.example", null, null);
        this.registry.revoke(OPEN, "https://gone.example", "withdrawn", null);
        FederationService service = this.pf();

        assertEquals(List.of(RP, HOSTED), service.trustMarkedEntities(OPEN, null));
        assertEquals(List.of(HOSTED), service.trustMarkedEntities(OPEN, HOSTED));
        assertEquals(List.of(RP, HOSTED), service.trustMarkedEntities(OPEN, " "));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMarkedEntities(null, RP));
        refusal(FederationError.INVALID_REQUEST, () -> service.trustMarkedEntities(" ", RP));
        refusal(FederationError.NOT_FOUND, () -> this.pf(List.of(PF)).trustMarkIssuing(null).build().trustMarkedEntities(OPEN, null));
    }

    @Test
    @Requirement({"OIDFED §8.2.1(2.4)", "OIDFED §8.2.1(2.6)"})
    void theListEndpointKeepsTheSubordinatesThisEntityHasMarked() throws Exception {
        this.registry.grant(HOSTED_ONLY, HOSTED, null, null);
        FederationService service = this.pf();

        assertEquals(List.of(RP, HOSTED), service.listSubordinates(new ListRequest(List.of(), null, null, null)));
        assertEquals(List.of(HOSTED), service.listSubordinates(new ListRequest(List.of(), true, null, null)));
        assertEquals(List.of(RP, HOSTED), service.listSubordinates(new ListRequest(List.of(), false, null, null)), "false filters nothing");
        assertEquals(List.of(HOSTED), service.listSubordinates(new ListRequest(List.of(), null, HOSTED_ONLY, null)));
        assertEquals(List.of(), service.listSubordinates(new ListRequest(List.of(), null, OPEN, null)));
        assertEquals(List.of(), service.listSubordinates(new ListRequest(List.of(), null, "https://pf.example/marks/unissued", null)),
                "a type this entity does not issue marks nobody");
    }

    // ---- the marks this entity publishes (§3.1.2) ------------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.1.2(1.6)")
    void thisEntityCarriesTheMarksConfiguredFromOtherIssuersAndThoseItIssuesItself() throws Exception {
        String fromElsewhere = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", "https://tmi.example").claim("sub", PF)
                .claim("trust_mark_type", "https://tmi.example/marks/audited").sign(Keys.ec("tmi-1"), this.clock);
        Map<String, Object> carried = Map.of("trust_mark_type", "https://tmi.example/marks/audited", "trust_mark", fromElsewhere);
        this.registry.grant(OPEN, PF, null, null);
        FederationService service = this.pf(List.of(PF)).ownTrustMarks(List.of(carried)).build();

        List<?> marks = (List<?>) claims(service.createEntityConfigurationJwt(PF)).getClaimValue("trust_marks");

        assertEquals(2, marks.size());
        assertEquals(carried, marks.get(0));
        assertEquals(OPEN, ((Map<?, ?>) marks.get(1)).get("trust_mark_type"));
        assertEquals(marks, claims(service.createEntityStatement(PF, null, PF)).getClaimValue("trust_marks"), "the self statement says the same");
        assertFalse(claims(this.pf(List.of(PF)).trustMarkIssuing(null).build().createEntityConfigurationJwt(PF)).hasClaim("trust_marks"));
    }

    @Test
    @Requirement({"OIDFED §3.1.2(1.8)", "OIDFED §3.1.2(1.10)", "OIDFED §7(2)", "OIDFED §7.2(3)"})
    void asATrustAnchorItSaysWhoseMarksTheFederationAccepts() throws Exception {
        Map<String, Object> owners = Map.of("https://owner.example/marks/owned", Map.of("sub", "https://owner.example", "jwks",
                Keys.publicJwks(Keys.ec("owner-1"))));
        Map<String, List<String>> configured = new LinkedHashMap<>();
        configured.put("https://tmi.example/marks/audited", List.of("https://tmi.example"));
        configured.put(HOSTED_ONLY, List.of("https://tmi.example"));
        configured.put("https://anyone.example/marks/open", List.of());
        FederationService anchor = this.pf(List.of(PF)).trustMarkIssuers(configured).trustMarkOwners(owners).build();

        JwtClaims configuration = claims(anchor.createEntityConfigurationJwt(PF));

        Map<?, ?> issuers = (Map<?, ?>) configuration.getClaimValue("trust_mark_issuers");
        assertEquals(List.of("https://tmi.example"), issuers.get("https://tmi.example/marks/audited"));
        assertEquals(List.of("https://tmi.example", PF), issuers.get(HOSTED_ONLY), "this entity added for a type it issues");
        assertEquals(List.of(PF), issuers.get(OPEN), "and named for one nobody configured");
        assertEquals(List.of(), issuers.get("https://anyone.example/marks/open"));
        assertEquals(owners, configuration.getClaimValue("trust_mark_owners"));

        Map<String, List<String>> listsItself = Map.of(OPEN, List.of(PF), HOSTED_ONLY, List.of());
        Map<?, ?> unchanged = (Map<?, ?>) claims(this.pf(List.of(PF)).trustMarkIssuers(listsItself).build().createEntityConfigurationJwt(PF))
                .getClaimValue("trust_mark_issuers");
        assertEquals(List.of(PF), unchanged.get(OPEN));
        assertEquals(List.of(), unchanged.get(HOSTED_ONLY), "anyone may issue it, this entity included");
    }

    @Test
    void anEntityThatIsNotAnAnchorSaysNothingOfWhoseMarksCount() throws Exception {
        FederationService intermediate = this.pf(List.of("https://ta.example")).trustMarkIssuers(Map.of(OPEN, List.of(PF)))
                .trustMarkOwners(Map.of(OPEN, Map.of("sub", PF))).build();
        JwtClaims configuration = claims(intermediate.createEntityConfigurationJwt(PF));

        assertFalse(configuration.hasClaim("trust_mark_issuers"));
        assertFalse(configuration.hasClaim("trust_mark_owners"));
        FederationService quietAnchor = this.pf(List.of(PF)).trustMarkIssuing(null).build();
        assertFalse(claims(quietAnchor.createEntityConfigurationJwt(PF)).hasClaim("trust_mark_issuers"), "nothing to say");
    }

    @Test
    void theMarksAHostedEntityHoldsAreIssuedAsTheAuthority() throws Exception {
        this.registry.grant(HOSTED_ONLY, HOSTED, null, null);
        FederationService service = this.pf();

        List<Map<String, Object>> marks = service.issuedTrustMarks(HOSTED, PF);

        assertEquals(1, marks.size());
        assertEquals(HOSTED_ONLY, marks.get(0).get("trust_mark_type"));
        assertEquals(HOSTED, claims((String) marks.get(0).get("trust_mark")).getSubject());
        assertEquals(List.of(), service.issuedTrustMarks(RP, PF));
        assertEquals(List.of(), this.pf(List.of(PF)).trustMarkIssuing(null).build().issuedTrustMarks(HOSTED, PF));
    }

    // ---- end to end ---------------------------------------------------------------------------------------

    /**
     * What this entity issues, another entity validates: a mark minted here for a subordinate, carried in the
     * subordinate's configuration, checked by {@link TrustMarkValidator} through the chain to this entity as anchor and
     * through this entity's own status endpoint - and refused there once its grant is revoked.
     */
    @Test
    @Requirement({"OIDFED §7.3(2)", "OIDFED §7.3(7)"})
    void aMarkThisEntityIssuesValidatesAtAnotherEntity() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        FederationService pf = this.pf();
        String mark = pf.trustMark(OPEN, RP, PF);
        this.http.entityConfiguration(RP, this.rpConfiguration(List.of(Map.of("trust_mark_type", OPEN, "trust_mark", mark))));
        this.http.entityConfiguration(PF, pf.createEntityConfigurationJwt(PF));
        this.http.subordinateStatement(pf.fetchEndpoint(PF), RP, pf.fetchSubordinateStatement(null, RP, PF));
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(this.http, PF), TrustAnchor.of(PF, Keys.publicJwks(PF_KEY)));
        List<String> asked = new ArrayList<>();
        HttpPostClient statusEndpoint = (url, contentType, body, headers, accept) -> {
            asked.add(url);
            String about = URLDecoder.decode(body.substring("trust_mark=".length()), StandardCharsets.UTF_8);
            return new HttpPostClient.Response(200, pf.trustMarkStatus(about, PF), Map.of());
        };
        TrustChainValidationResult chain = validator.validate(ValidationRequest.forSubject(RP).includeAnchorConfiguration(true).build());

        TrustMarkValidator.Result result = new TrustMarkValidator(validator, Set.of(), this.clock, statusEndpoint).validate(chain);

        assertTrue(result.has(OPEN), result.rejected().toString());
        assertEquals(List.of(PF + "/federation/trust_mark_status"), asked);

        this.registry.revoke(OPEN, RP, "withdrawn", null);
        TrustMarkValidator.Result afterRevocation = new TrustMarkValidator(validator, Set.of(), this.clock, statusEndpoint).validate(chain);
        assertFalse(afterRevocation.has(OPEN));
        assertTrue(afterRevocation.rejected().get(0).reason().contains("revoked"), afterRevocation.rejected().get(0).reason());
    }
}
