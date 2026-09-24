package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.ServingMap;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.io.IOException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The federation endpoints this deployment answers, against OpenID Federation 1.0 §8: fetch (§8.1), list
 * (§8.2) and resolve (§8.3), and what its Entity Configuration advertises (§5.1).
 */
class FederationServiceEndpointsTest {
    private static final String PF = "https://pf.example";
    private static final String HOSTED = "https://pf.example/agents/a1";
    private static final String FOREIGN = "https://foreign.example";
    private static final String OTHER_TA = "https://other-ta.example";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");
    private static final PublicJsonWebKey HOSTED_KEY = Keys.ec("a1-1");
    private static final PublicJsonWebKey FOREIGN_KEY = Keys.ec("foreign-1");

    private static FederationConfiguration configuration(List<String> subordinates, List<String> registrationTypes,
                                                         FederationConfiguration.ResolveDiscovery discovery, String organization) {
        return new FederationConfiguration(List.of(PF), subordinates, null, false, false, null, null, null, 0, "RS256",
                AttestationMetadataConfig.defaults(), null, organization, registrationTypes, discovery);
    }

    private static FederationConfiguration configuration() {
        return configuration(List.of(FOREIGN), FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES,
                FederationConfiguration.ResolveDiscovery.KNOWN, null);
    }

    private static String hostedConfiguration(Map<String, Object> metadata) {
        return Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", HOSTED).claim("sub", HOSTED)
                .claim("jwks", Keys.publicJwks(HOSTED_KEY)).claim("authority_hints", List.of(PF)).claim("metadata", metadata)
                .sign(HOSTED_KEY, Clock.systemUTC());
    }

    private static String foreignConfiguration(Map<String, Object> metadata) {
        return Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", FOREIGN).claim("sub", FOREIGN)
                .claim("jwks", Keys.publicJwks(FOREIGN_KEY)).claim("authority_hints", List.of(PF)).claim("metadata", metadata)
                .sign(FOREIGN_KEY, Clock.systemUTC());
    }

    /** The whole federation seen from PF: it hosts HOSTED, has FOREIGN as a configured subordinate, and anchors both. */
    private static FederationService.Builder pf(FederationConfiguration configuration, ServingMap http) {
        String hostedEc = hostedConfiguration(Map.of("oauth_client", Map.of("client_name", "agent"),
                "openid_relying_party", Map.of("client_name", "agent rp")));
        return FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .subordinateFetcher(http)
                .hostedSubordinateLookup(sub -> HOSTED.equals(sub) ? Map.of("jwks", Keys.publicJwks(HOSTED_KEY)) : null)
                .hostedSubordinateIds(type -> type == null || "oauth_client".equals(type) || "openid_relying_party".equals(type)
                        ? List.of(HOSTED) : List.of())
                .hostedConfiguration(id -> HOSTED.equals(id) ? hostedEc : null)
                .hosting(() -> true)
                .resolver(TrustAnchorSet.of(TrustAnchor.of(PF, Keys.publicJwks(PF_KEY))), new HttpTrustControllerGateway(http, PF),
                        Set.of(), ValidatorOptions.defaults());
    }

    private static JwtClaims claims(String jwt) throws Exception {
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    private static FederationException refusal(FederationError expected, org.junit.jupiter.api.function.Executable call) {
        FederationException e = assertThrows(FederationException.class, call);
        assertEquals(expected, e.error(), e.getMessage());
        return e;
    }

    // ---- fetch (§8.1) --------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §8.1.1(2.2)", "OIDFED §3.1.3(1.8)", "OIDFED §8(2)"})
    void aSubordinateStatementIsIssuedForSubAloneAndNamesItsSourceEndpoint() throws Exception {
        FederationService service = pf(configuration(), new ServingMap()).federationBasePath("/oidf").build();

        String jwt = service.fetchSubordinateStatement(null, HOSTED, PF);
        String withIss = service.fetchSubordinateStatement(PF + "/", HOSTED, PF);

        JwtClaims claims = JwtCodec.verifyAgainstKeys(jwt, List.of(PF_KEY), PF, Set.of());
        assertEquals(HOSTED, claims.getSubject());
        assertEquals(Keys.publicJwks(HOSTED_KEY), claims.getClaimValue("jwks"), "the subordinate's keys, not this entity's");
        assertEquals(PF + "/oidf/federation/fetch", claims.getClaimValue("source_endpoint"));
        assertEquals("entity-statement+jwt", JwtCodec.getJwtHeaders(jwt).get("typ"));
        assertEquals("pf-1", JwtCodec.getJwtHeaders(jwt).get("kid"));
        assertEquals(HOSTED, claims(withIss).getSubject(), "a draft-era iss naming this entity is accepted");
    }

    @Test
    @Requirement({"OIDFED §8.1.2(1)", "OIDFED §8.9(2.2.4.3)", "OIDFED §8.9(2.2.4.13)"})
    void fetchRefusesWithTheCodesSection8Recommends() {
        FederationService service = pf(configuration(), new ServingMap()).build();

        refusal(FederationError.INVALID_REQUEST, () -> service.fetchSubordinateStatement(null, null, PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.fetchSubordinateStatement(null, " ", PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.fetchSubordinateStatement(null, PF, PF));
        refusal(FederationError.INVALID_ISSUER, () -> service.fetchSubordinateStatement(OTHER_TA, HOSTED, PF));
        refusal(FederationError.NOT_FOUND, () -> service.fetchSubordinateStatement(null, "https://stranger.example", PF));
    }

    @Test
    void aForeignSubordinateWhoseConfigurationCannotBeFetchedYetIsTemporarilyUnavailable() {
        ServingMap http = new ServingMap();
        http.failing(FOREIGN + "/.well-known/openid-federation", new IOException("down"));
        FederationService service = pf(configuration(), http).build();

        refusal(FederationError.TEMPORARILY_UNAVAILABLE, () -> service.fetchSubordinateStatement(null, FOREIGN, PF));
    }

    @Test
    void aSubordinateStatementNeedsAFetcherForAForeignSubordinate() {
        FederationService service = FederationService.builder(configuration(), Keys.signingKeys(PF_KEY)).build();

        assertThrows(IllegalStateException.class, () -> service.fetchSubordinateStatement(null, FOREIGN, PF));
    }

    @Test
    void theNonStandardEntityEndpointNeverSignsAsAnotherIssuer() throws Exception {
        FederationService service = pf(configuration(), new ServingMap()).build();

        assertEquals(PF, claims(service.createEntityStatement(HOSTED, OTHER_TA, PF)).getIssuer());
        JwtClaims self = claims(service.createEntityStatement(PF, OTHER_TA, PF));
        assertEquals(PF, self.getIssuer());
        assertTrue(self.hasClaim("metadata"));
    }

    // ---- list (§8.2) ---------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §8.2.2(1)", "OIDFED §8.2.1(2.2)"})
    void entityTypeFiltersToSubordinatesThatHaveEveryRequestedType() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of("openid_provider", Map.of())));
        FederationService service = pf(configuration(), http).build();

        assertEquals(List.of(FOREIGN, HOSTED), service.listSubordinates(ListRequest.all()));
        assertEquals(List.of(HOSTED), service.listSubordinates(new ListRequest(List.of("oauth_client"), null, null, null)),
                "a foreign subordinate whose types are not yet known is left out of a filtered list");

        service.fetchSubordinateStatement(null, FOREIGN, PF);
        assertEquals(List.of(FOREIGN), service.listSubordinates(new ListRequest(List.of("openid_provider"), null, null, null)));
        assertEquals(List.of(HOSTED), service.listSubordinates(new ListRequest(List.of("oauth_client", "openid_relying_party"), null, null, null)));
        assertEquals(List.of(), service.listSubordinates(new ListRequest(List.of("oauth_client", "openid_provider"), null, null, null)));
        assertEquals(List.of(FOREIGN, HOSTED), service.listSubordinates(new ListRequest(java.util.Arrays.asList(" ", null), null, null, null)));
    }

    @Test
    @Requirement("OIDFED §8.2.1(2.8)")
    void intermediateListsOnlySubordinatesKnownToHaveSubordinatesOfTheirOwn() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of(
                "federation_entity", Map.of("federation_fetch_endpoint", FOREIGN + "/fetch"))));
        FederationService service = pf(configuration(), http).build();
        assertEquals(List.of(), service.listSubordinates(new ListRequest(List.of(), null, null, true)), "nothing is known yet");

        service.fetchSubordinateStatement(null, FOREIGN, PF);

        assertEquals(List.of(FOREIGN), service.listSubordinates(new ListRequest(List.of(), null, null, true)));
        assertEquals(List.of(FOREIGN, HOSTED), service.listSubordinates(new ListRequest(List.of(), false, null, false)));
    }

    @Test
    @Requirement({"OIDFED §8.2.1(2.4)", "OIDFED §8.2.1(2.6)", "OIDFED §8.9(2.2.4.15)"})
    void trustMarkFiltersAreUnsupportedUntilThisEntityIssuesTrustMarks() {
        FederationService service = pf(configuration(), new ServingMap()).build();

        refusal(FederationError.UNSUPPORTED_PARAMETER, () -> service.listSubordinates(new ListRequest(List.of(), true, null, null)));
        refusal(FederationError.UNSUPPORTED_PARAMETER,
                () -> service.listSubordinates(new ListRequest(List.of(), null, "https://marks.example/t", null)));
    }

    @Test
    void theSingleTypeListStillWorks() {
        FederationService service = pf(configuration(), new ServingMap()).build();
        assertEquals(List.of(HOSTED), service.listSubordinates("oauth_client"));
        assertEquals(List.of(FOREIGN, HOSTED), service.listSubordinates(" "));
        assertEquals(List.of(FOREIGN), FederationService.builder(configuration(), Keys.signingKeys(PF_KEY)).build()
                .listSubordinates(ListRequest.all()));
    }

    // ---- resolve (§8.3) ------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §8.3(1)", "OIDFED §8.3.2(1)", "OIDFED §8.3.2(2)", "OIDFED §8.3.2(3)", "OIDFED §8.3.2(4)",
            "OIDFED §8.3.2(9.8)", "OIDFED §8.3.2(9.12)"})
    void aResolveResponseIsASignedChainEndingAtTheAnchorsConfiguration() throws Exception {
        ServingMap http = new ServingMap();
        FederationService service = pf(configuration(), http).build();

        String jwt = service.resolve(new ResolveRequest(HOSTED, List.of(PF), List.of()), PF);

        assertEquals("resolve-response+jwt", JwtCodec.getJwtHeaders(jwt).get("typ"));
        assertEquals("pf-1", JwtCodec.getJwtHeaders(jwt).get("kid"));
        JwtClaims response = JwtCodec.verifyAgainstKeys(jwt, List.of(PF_KEY), PF, Set.of());
        assertEquals(HOSTED, response.getSubject());
        @SuppressWarnings("unchecked")
        List<String> chain = (List<String>) response.getClaimValue("trust_chain");
        assertEquals(3, chain.size());
        assertEquals(HOSTED, claims(chain.get(0)).getSubject());
        assertEquals(PF, claims(chain.get(1)).getIssuer());
        assertEquals(PF, claims(chain.get(2)).getSubject(), "the chain ends with the anchor's Entity Configuration");
        long earliest = Long.MAX_VALUE;
        for (String statement : chain) {
            earliest = Math.min(earliest, claims(statement).getExpirationTime().getValue());
        }
        assertEquals(earliest, response.getExpirationTime().getValue());
        assertEquals(Set.of("oauth_client", "openid_relying_party"), ((Map<?, ?>) response.getClaimValue("metadata")).keySet());
        assertFalse(response.hasClaim("trust_marks"), "only verified Trust Marks may appear, and none are verified yet");
        assertEquals(List.of(), http.requests(), "this entity's own statements are produced in-process, not fetched");
    }

    @Test
    @Requirement("OIDFED §8.3.1(2.6)")
    void entityTypeNarrowsTheResolvedMetadata() throws Exception {
        FederationService service = pf(configuration(), new ServingMap()).build();

        String jwt = service.resolve(new ResolveRequest(HOSTED, List.of(PF), List.of("oauth_client", "openid_provider")), PF);

        assertEquals(Set.of("oauth_client"), ((Map<?, ?>) claims(jwt).getClaimValue("metadata")).keySet());
    }

    @Test
    void thisEntityResolvesItselfAsTheAnchor() throws Exception {
        FederationService service = pf(configuration(), new ServingMap()).build();

        @SuppressWarnings("unchecked")
        List<String> chain = (List<String>) claims(service.resolve(new ResolveRequest(PF, List.of(PF), List.of()), PF))
                .getClaimValue("trust_chain");

        assertEquals(1, chain.size());
        assertEquals(PF, claims(chain.get(0)).getSubject());
    }

    @Test
    @Requirement({"OIDFED §8.3.1(2.2)", "OIDFED §8.3.1(2.4)", "OIDFED §8.9(2.2.4.7)"})
    void resolveNeedsASubjectAndAnAnchorItTrusts() {
        FederationService service = pf(configuration(), new ServingMap()).build();

        refusal(FederationError.INVALID_REQUEST, () -> service.resolve(new ResolveRequest(null, List.of(PF), null), PF));
        refusal(FederationError.INVALID_REQUEST, () -> service.resolve(new ResolveRequest(HOSTED, null, null), PF));
        refusal(FederationError.INVALID_TRUST_ANCHOR, () -> service.resolve(new ResolveRequest(HOSTED, List.of(OTHER_TA), null), PF));
        refusal(FederationError.INVALID_TRUST_ANCHOR, () -> FederationService.builder(configuration(), Keys.signingKeys(PF_KEY)).build()
                .resolve(new ResolveRequest(HOSTED, List.of(PF), null), PF));
    }

    @Test
    @Requirement({"OIDFED §18.1(7)", "OIDFED §8.9(2.2.4.5)"})
    void anUnauthenticatedResolveDoesNotSendThisEntityDiscoveringStrangers() {
        ServingMap http = new ServingMap();
        FederationService known = pf(configuration(), http).build();

        refusal(FederationError.INVALID_SUBJECT, () -> known.resolve(new ResolveRequest("https://stranger.example", List.of(PF), null), PF));
        assertEquals(List.of(), http.requests());

        FederationService any = pf(configuration(List.of(FOREIGN), FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES,
                FederationConfiguration.ResolveDiscovery.ANY, null), http).build();
        refusal(FederationError.NOT_FOUND, () -> any.resolve(new ResolveRequest("https://stranger.example", List.of(PF), null), PF));
        assertTrue(http.hitsStartingWith("https://stranger.example") > 0, "with discovery on, the stranger is looked up");
    }

    @Test
    void aConfiguredSubordinateIsKnownToTheResolver() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of("openid_provider", Map.of("issuer", FOREIGN))));
        FederationService service = pf(configuration(), http).build();

        assertEquals(FOREIGN, claims(service.resolve(new ResolveRequest(FOREIGN, List.of(PF), null), PF)).getSubject());
    }

    // ---- what the entity configuration advertises (§5.1) ---------------------------------------------

    @Test
    @Requirement({"OIDFED §5.1.1(3.2)", "OIDFED §5.1.1(3.4)", "OIDFED §5.1.1(3.6)", "OIDFED §5.1.1(5)"})
    void aSuperiorAdvertisesFetchAndListAndResolveOnlyWhenEnabled() throws Exception {
        Map<?, ?> superior = federationEntity(pf(configuration(List.of(), FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES,
                FederationConfiguration.ResolveDiscovery.KNOWN, "PF Ltd"), new ServingMap()).federationBasePath("/oidf").build());
        assertEquals(PF + "/oidf/federation/fetch", superior.get("federation_fetch_endpoint"));
        assertEquals(PF + "/oidf/federation/list", superior.get("federation_list_endpoint"));
        assertEquals(PF + "/oidf/federation/resolve", superior.get("federation_resolve_endpoint"));
        assertEquals("PF Ltd", superior.get("organization_name"));

        FederationConfiguration leafOnly = new FederationConfiguration(List.of(OTHER_TA), List.of(), null, false, false, null, null, null, 0,
                "RS256", AttestationMetadataConfig.defaults(), null, null, List.of(), FederationConfiguration.ResolveDiscovery.KNOWN);
        Map<?, ?> leaf = federationEntity(FederationService.builder(leafOnly, Keys.signingKeys(PF_KEY)).build());
        assertNull(leaf.get("federation_fetch_endpoint"), "Leaf Entities MUST NOT publish a fetch endpoint");
        assertNull(leaf.get("federation_list_endpoint"));
        assertNull(leaf.get("federation_resolve_endpoint"));
    }

    @Test
    @Requirement({"OIDFED §5.1.3(3)", "OIDFED §5.1.3(5.2)", "OIDFED §5.1.3(5.4)"})
    void theOpAdvertisesTheRegistrationTypesItAccepts() throws Exception {
        Map<?, ?> both = openidProvider(pf(configuration(), new ServingMap()).build());
        assertEquals(List.of("automatic", "explicit"), both.get("client_registration_types_supported"));
        assertEquals(PF + "/federation/register", both.get("federation_registration_endpoint"));
        assertEquals(PF, both.get("issuer"));

        Map<?, ?> automaticOnly = openidProvider(pf(configuration(List.of(), List.of("automatic"),
                FederationConfiguration.ResolveDiscovery.KNOWN, null), new ServingMap()).build());
        assertEquals(List.of("automatic"), automaticOnly.get("client_registration_types_supported"));
        assertFalse(automaticOnly.containsKey("federation_registration_endpoint"), "no explicit registration, no endpoint");

        Map<?, ?> none = openidProvider(pf(configuration(List.of(), List.of(), FederationConfiguration.ResolveDiscovery.KNOWN, null),
                new ServingMap()).build());
        assertFalse(none.containsKey("client_registration_types_supported"));
    }

    @Test
    void aSelfAnchoredEntityPublishesNoAuthorityHints() throws Exception {
        assertFalse(claims(pf(configuration(), new ServingMap()).build().createEntityConfigurationJwt(PF)).hasClaim("authority_hints"));
        FederationConfiguration underAnother = new FederationConfiguration(List.of(OTHER_TA), List.of(), null, false, false, null, null,
                null, 0, "RS256", AttestationMetadataConfig.defaults(), null);
        assertEquals(List.of(OTHER_TA), claims(FederationService.builder(underAnother, Keys.signingKeys(PF_KEY)).build()
                .createEntityConfigurationJwt(PF)).getStringListClaimValue("authority_hints"));
    }

    // ---- edges ---------------------------------------------------------------------------------------

    @Test
    void edgesOfFetch() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of("openid_provider", Map.of())));
        FederationService service = pf(configuration(), http).build();

        assertEquals(HOSTED, claims(service.fetchSubordinateStatement(" ", HOSTED, PF)).getSubject(), "a blank iss is no iss");
        assertEquals(HOSTED, claims(service.fetchEntityStatement(PF, HOSTED, PF)).getSubject());
        service.fetchSubordinateStatement(null, FOREIGN, PF);
        service.fetchSubordinateStatement(null, FOREIGN, PF);
        assertEquals(1, http.hits(FOREIGN + "/.well-known/openid-federation"), "the second statement uses the cached keys");
    }

    @Test
    void aForeignSubordinateWhoseConfigurationIsNotUsableIsTemporarilyUnavailable() {
        String notSelfSigned = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", PF).claim("sub", FOREIGN)
                .claim("jwks", Keys.publicJwks(FOREIGN_KEY)).sign(FOREIGN_KEY, Clock.systemUTC());
        String noKeys = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", FOREIGN).claim("sub", FOREIGN)
                .claim("jwks", Map.of()).sign(FOREIGN_KEY, Clock.systemUTC());
        String otherSubject = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", FOREIGN).claim("sub", HOSTED)
                .claim("jwks", Keys.publicJwks(FOREIGN_KEY)).sign(FOREIGN_KEY, Clock.systemUTC());
        String unsignedWithoutKeys = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", FOREIGN).claim("sub", FOREIGN)
                .sign(FOREIGN_KEY, Clock.systemUTC());
        for (String body : List.of(notSelfSigned, otherSubject, noKeys, unsignedWithoutKeys, "garbage")) {
            ServingMap http = new ServingMap().entityConfiguration(FOREIGN, body);
            FederationService service = pf(configuration(), http).build();
            refusal(FederationError.TEMPORARILY_UNAVAILABLE, () -> service.fetchSubordinateStatement(null, FOREIGN, PF));
        }
    }

    @Test
    void edgesOfList() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of("openid_provider", Map.of())));
        FederationService service = pf(configuration(), http).build();
        service.fetchSubordinateStatement(null, FOREIGN, PF);

        assertEquals(List.of(), service.listSubordinates(new ListRequest(List.of("openid_provider"), null, null, true)),
                "a subordinate that publishes no fetch endpoint is not an Intermediate");
        assertEquals(List.of(FOREIGN, HOSTED), service.listSubordinates((String) null));
    }

    @Test
    void edgesOfResolve() throws Exception {
        ServingMap http = new ServingMap().entityConfiguration(FOREIGN, foreignConfiguration(Map.of("openid_provider", Map.of("issuer", FOREIGN))));
        FederationService bare = FederationService.builder(configuration(), Keys.signingKeys(PF_KEY))
                .subordinateFetcher(http)
                .resolver(TrustAnchorSet.of(TrustAnchor.of(PF, Keys.publicJwks(PF_KEY))), new HttpTrustControllerGateway(http, PF),
                        null, null)
                .clock(Clock.fixed(java.time.Instant.now(), java.time.ZoneOffset.UTC))
                .build();

        refusal(FederationError.INVALID_REQUEST, () -> bare.resolve(new ResolveRequest(" ", List.of(PF), null), PF));
        refusal(FederationError.INVALID_SUBJECT, () -> bare.resolve(new ResolveRequest(HOSTED, List.of(PF), null), PF));
        assertEquals(FOREIGN, claims(bare.resolve(new ResolveRequest(FOREIGN, List.of(PF), null), PF)).getSubject(),
                "without a hosted lookup the foreign subordinate's configuration is fetched");
        assertNull(bare.localStatements(PF).subordinateStatement(OTHER_TA, FOREIGN), "not this entity's statement to make");
        assertNull(bare.localStatements(PF).entityConfiguration(FOREIGN));

        assertFalse(FederationService.builder(configuration(), Keys.signingKeys(PF_KEY))
                .resolver(TrustAnchorSet.empty(), new HttpTrustControllerGateway(http, PF), null, null).build().resolveEnabled());
        assertFalse(FederationService.builder(configuration(), Keys.signingKeys(PF_KEY))
                .resolver(TrustAnchorSet.of(TrustAnchor.of(PF, Keys.publicJwks(PF_KEY))), null, null, null).build().resolveEnabled());
    }

    @Test
    void theChallengeEndpointIsAdvertisedOnlyWhenEnabled() throws Exception {
        AttestationMetadataConfig noChallenge = new AttestationMetadataConfig(List.of("private_key_jwt"), List.of("ES256"), List.of("ES256"),
                List.of("ES256"), List.of(), List.of(), false);
        FederationConfiguration configuration = new FederationConfiguration(List.of(PF), List.of(), null, false, false, null, null, null,
                0, "RS256", noChallenge, null);

        assertFalse(openidProvider(FederationService.builder(configuration, Keys.signingKeys(PF_KEY)).build()).containsKey("challenge_endpoint"));
        assertTrue(openidProvider(pf(configuration(), new ServingMap()).build()).containsKey("challenge_endpoint"));
    }

    @Test
    void anEntityThatOnlyHostsIsStillASuperior() throws Exception {
        FederationConfiguration hostOnly = new FederationConfiguration(List.of(), List.of(), null, false, false, null, null, null, 0,
                "RS256", AttestationMetadataConfig.defaults(), null);
        FederationService service = FederationService.builder(hostOnly, Keys.signingKeys(PF_KEY)).hosting(() -> true).build();

        assertTrue(service.isSuperior(PF));
        assertFalse(claims(service.createEntityConfigurationJwt(PF)).hasClaim("authority_hints"), "no superiors, no hints");
        assertTrue(federationEntity(service).containsKey("federation_fetch_endpoint"));
    }

    private static Map<?, ?> federationEntity(FederationService service) throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) claims(service.createEntityConfigurationJwt(PF)).getClaimValue("metadata")).get("federation_entity");
    }

    private static Map<?, ?> openidProvider(FederationService service) throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) claims(service.createEntityConfigurationJwt(PF)).getClaimValue("metadata")).get("openid_provider");
    }
}
