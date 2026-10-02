package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.clientattestation.InMemoryEvidenceBindingStore;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.issuer.AssertedContext;
import com.pingidentity.ps.oidf.issuer.AssertedContextResolver;
import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.AttesterSigningKey;
import com.pingidentity.ps.oidf.issuer.EvidencePolicy;
import com.pingidentity.ps.oidf.issuer.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.Omission;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.rar.model.Vectors;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared vector file ({@code libs/rar-model}'s test-jar) run through the attester: the third of the plan's
 * four runners (library, AS, CAS, refresh). The attester asks the model three questions, and each is a surface
 * here:
 * <ul>
 *   <li><b>The mint</b> ({@code authorize} with {@code INHERIT}, and {@code fullCeiling}): the case's ceiling as the
 *       client's {@code attestation_entitlement}, its candidate as the issuance request's
 *       {@code authorization_details}, and the minted attestation's {@code authorization_details} read back and
 *       compared with the case's grant. CAS §7: "effective = requested ∩ ceiling(instance)"; rule 1, "The issued
 *       {@code authorization_details} MUST be a subset of the applicable ceiling"; rule 2, "An empty or absent
 *       {@code authorization_details} request means the instance asks for its full ceiling"; rule 3, ""reject" →
 *       access_denied".</li>
 *   <li><b>The configuration</b> ({@code authorize} with {@code INHERIT}): the candidate as an instance's
 *       {@code entitlement}, the ceiling as the client's, and the binding's kept ceiling compared with the case's
 *       grant - CAS §7's "instances[i].entitlement ⊆ entitlement MUST hold at registration time", and the result
 *       kept (F-0034).</li>
 *   <li><b>The asserted context</b> ({@code intersect}): the case's two lists as the binding's ceiling and an
 *       asserted-context resolver's, an empty request, and the minted details compared with the case's meet.</li>
 * </ul>
 * Every attestation the mint issues is then presented to the authorization server's token gate, with its own
 * details as the request, so what the attester writes is what the gate reads - the numbers included.
 *
 * <p>Three answers differ on purpose, named in {@link #DIVERGENCES} with the text that makes them differ.
 */
@Requirement({"CAS §7(1)", "CAS §7(2)", "CAS §7(3)"})
class CasVectorRunnerTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The cases the attester answers differently from the library, by surface and case name, and why. */
    static final Map<String, String> DIVERGENCES = Map.of(
            "mint: authorize: an empty candidate grants nothing",
            "CAS §7 rule 2: an empty request is a request for the full ceiling",
            "configuration: authorize: an empty candidate grants nothing",
            "an instance with no ceiling of its own takes the client's (CAS §7: \"ceiling(instance) = "
                    + "instances[i].entitlement if present = entitlement (client-level) otherwise\")",
            "configuration: authorize: an empty ceiling refuses any request",
            "CAS §6.1: an instance's entitlement \"MUST be a subset of the client-level entitlement when both are "
                    + "present\", and the client-level one is OPTIONAL; with none, the instance's is kept as written");

    private static PublicJsonWebKey bundleKey;
    private static PublicJsonWebKey attesterKey;
    private static PublicJsonWebKey instanceKey;

    @BeforeAll
    static void keys() throws Exception {
        bundleKey = ec("svid-key-1");
        attesterKey = ec("attester-1");
        instanceKey = ec("instance-1");
    }

    @TestFactory
    Stream<DynamicTest> theAttesterAnswersEveryCaseItIsAsked() {
        List<DynamicTest> tests = new java.util.ArrayList<>();
        for (Vectors.Case c : Vectors.load()) {
            switch (c.op()) {
                case "authorize":
                    if (c.mode() == Omission.INHERIT) {
                        tests.add(DynamicTest.dynamicTest("mint: " + c.name(), () -> mint(c)));
                        tests.add(DynamicTest.dynamicTest("configuration: " + c.name(), () -> configure(c)));
                    }
                    break;
                case "fullCeiling":
                    tests.add(DynamicTest.dynamicTest("mint: " + c.name(), () -> mint(c)));
                    break;
                case "intersect":
                    tests.add(DynamicTest.dynamicTest("asserted context: " + c.name(), () -> narrow(c)));
                    break;
                default:
                    break;
            }
        }
        assertTrue(tests.size() > 80, "the file was read: " + tests.size());
        return tests.stream();
    }

    @Test
    void everyDivergenceNamesACaseInTheFile() {
        Set<String> names = Vectors.load().stream().map(Vectors.Case::name).collect(Collectors.toSet());
        for (String key : DIVERGENCES.keySet()) {
            String name = key.substring(key.indexOf(": ") + 2);
            assertTrue(names.contains(name), "no case named '" + name + "' in the vector file");
        }
    }

    // ---- the mint -----------------------------------------------------------------------------------------

    private static void mint(Vectors.Case c) throws Exception {
        RarModels models = c.models();
        Object ceiling = c.list("ceiling");
        List<Map<String, Object>> candidate = c.op().equals("fullCeiling") ? List.of() : RarModels.details(c.list("candidate"));
        AttestationIssuanceConfig config;
        try {
            config = AttestationIssuanceConfig.fromProperties(props(ceiling, null, false), models);
        } catch (IssuanceException e) {
            assertCeilingRefused(c, models, ceiling, e);
            return;
        }
        AttestationIssuanceServlet servlet = servlet(models, config, null);
        Map<String, Object> body;
        try {
            body = servlet.issue(request(candidate, null));
        } catch (IssuanceException e) {
            RarModelException library = assertThrows(RarModelException.class,
                    () -> models.authorize(candidate, RarModels.details(ceiling), Omission.INHERIT), c.name());
            assertEquals(c.expectedRefusal(), library.reason(), "the library's own answer to '" + c.name() + "'");
            assertEquals(AttestationIssuanceServlet.mapEntitlementError(library).error(), e.error(), c.name());
            assertEquals(AttestationIssuanceServlet.mapEntitlementError(library).getMessage(), e.getMessage(), c.name());
            assertEquals(library.reason() == RarModelException.Reason.EXCEEDS_CEILING ? "access_denied" : "invalid_request",
                    e.error(), c.name());
            return;
        }
        List<Map<String, Object>> minted = mintedDetails((String) body.get("attestation"));
        Object want;
        if (DIVERGENCES.containsKey("mint: " + c.name())) {
            want = models.fullCeiling(RarModels.details(ceiling));
        } else {
            assertEquals(null, c.expectedRefusal(), "'" + c.name() + "' was minted, where the case expects a refusal");
            want = ((Map<?, ?>) c.expect()).get("granted");
        }
        assertEquals(Vectors.canonical(want), Vectors.canonical(minted), c.name());
        assertTheTokenGateReadsIt(models, (String) body.get("attestation"), minted);
    }

    /** The case's refusal when the ceiling itself is what the model refuses: the client's configuration. */
    private static void assertCeilingRefused(Vectors.Case c, RarModels models, Object ceiling, IssuanceException e) {
        assertEquals("invalid_client", e.error(), c.name());
        RarModelException library = assertThrows(RarModelException.class,
                () -> models.validate(RarModels.details(ceiling), "ceiling"), "'" + c.name() + "': " + e.getMessage());
        assertEquals(c.expectedRefusal(), library.reason(), c.name());
    }

    // ---- the configuration ----------------------------------------------------------------------------------

    private static void configure(Vectors.Case c) throws Exception {
        RarModels models = c.models();
        Object ceiling = c.list("ceiling");
        List<Map<String, Object>> candidate = RarModels.details(c.list("candidate"));
        AttestationIssuanceConfig config;
        try {
            config = AttestationIssuanceConfig.fromProperties(props(ceiling, candidate, false), models);
        } catch (IssuanceException e) {
            assertEquals("invalid_client", e.error(), c.name());
            RarModelException.Reason expected = c.expectedRefusal();
            assertNotNull(expected, "'" + c.name() + "' was refused at configuration: " + e.getMessage());
            boolean ceilingFault = refuses(() -> models.validate(RarModels.details(ceiling), "ceiling"));
            assertTrue(e.getMessage().contains(ceilingFault ? AttestationIssuanceConfig.P_ENTITLEMENT
                    : expected == RarModelException.Reason.EXCEEDS_CEILING ? "exceeds the client-level ceiling"
                    : "entitlement is not a valid authorization_details array"), c.name() + ": " + e.getMessage());
            return;
        }
        List<Map<String, Object>> kept = config.bindings().get(0).entitlement();
        if (DIVERGENCES.containsKey("configuration: " + c.name())) {
            if (candidate.isEmpty()) {
                assertEquals(List.of(), kept, "no ceiling of its own");
                assertEquals(Vectors.canonical(RarModels.details(ceiling)),
                        Vectors.canonical(config.effectiveCeiling(config.bindings().get(0))), "the client's applies");
            } else {
                assertEquals(Vectors.canonical(candidate), Vectors.canonical(kept), "kept as written");
            }
            return;
        }
        assertEquals(null, c.expectedRefusal(), "'" + c.name() + "' was configured, where the case expects a refusal");
        assertEquals(Vectors.canonical(((Map<?, ?>) c.expect()).get("granted")), Vectors.canonical(kept), c.name());
    }

    // ---- the asserted context ---------------------------------------------------------------------------------

    private static void narrow(Vectors.Case c) throws Exception {
        RarModels models = c.models();
        Object a = c.list("a");
        List<Map<String, Object>> b = RarModels.details(c.list("b"));
        AttestationIssuanceConfig config;
        try {
            config = AttestationIssuanceConfig.fromProperties(props(a, null, true), models);
        } catch (IssuanceException e) {
            assertCeilingRefused(c, models, a, e);
            return;
        }
        AssertedContextResolver resolver = new AssertedContextResolver() {
            @Override
            public String id() {
                return "vectors";
            }

            @Override
            public AssertedContext resolve(com.pingidentity.ps.oidf.issuer.InstanceIdentity verified, String asserted,
                                           AttestationIssuanceConfig cfg) {
                return new AssertedContext(Map.of(), b);
            }
        };
        AttestationIssuanceServlet servlet = servlet(models, config, resolver);
        Map<String, Object> body;
        try {
            body = servlet.issue(request(List.of(), "an asserted discriminator"));
        } catch (IssuanceException e) {
            assertEquals("server_error", e.error(), "'" + c.name() + "': the two ceilings are both configuration");
            RarModelException library = assertThrows(RarModelException.class,
                    () -> models.intersect(RarModels.details(a), b), c.name());
            assertEquals(c.expectedRefusal(), library.reason(), c.name());
            return;
        }
        assertEquals(null, c.expectedRefusal(), "'" + c.name() + "' was minted, where the case expects a refusal");
        List<Map<String, Object>> minted = mintedDetails((String) body.get("attestation"));
        assertEquals(Vectors.canonical(((Map<?, ?>) c.expect()).get("intersection")), Vectors.canonical(minted), c.name());
        assertTheTokenGateReadsIt(models, (String) body.get("attestation"), minted);
    }

    // ---- what the token gate makes of it -------------------------------------------------------------------------

    /**
     * The authorization server verifies the minted attestation and asks for exactly the details it carries: they
     * must be within themselves as the gate reads them, which fails if the writer and the reader disagree about a
     * value - a decimal written in a form the model reads as another number, say.
     */
    private static void assertTheTokenGateReadsIt(RarModels models, String attestation, List<Map<String, Object>> minted)
            throws Exception {
        if (minted.isEmpty()) {
            return;
        }
        JsonWebKey attesterPublic = JsonWebKey.Factory.newJwk(attesterKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        ClientAttestationVerifier verifier = ClientAttestationVerifier.withRarModels((iss, chain) -> List.of(attesterPublic),
                ClientAttestationConfig.builder().expectedAudience(OP_ISSUER).expectedHtu(TOKEN_ENDPOINT).build(),
                new InMemoryAttestationReplayCache(), null, models);
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId(UUID.randomUUID().toString());
        pop.setIssuedAtToNow();
        ClientAttestationResult result = verifier.verify(attestation,
                signCompact(instanceKey, "oauth-client-attestation-pop+jwt", pop), null, "POST", TOKEN_ENDPOINT,
                CLIENT_ID, JSON.writeValueAsString(minted));
        assertEquals(Vectors.canonical(minted), Vectors.canonical(result.grantedAuthorizationDetails()));
    }

    // ---- fixtures ----------------------------------------------------------------------------------------------

    private static Map<String, String> props(Object clientCeiling, List<Map<String, Object>> instanceCeiling,
                                             boolean asserted) throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE,
                new JsonWebKeySet(JsonWebKey.Factory.newJwk(bundleKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))).toJson());
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                JsonUtil.toJson(attesterKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)));
        // Written by Jackson, which writes a decimal as the case has it; the configuration reads it back with the
        // model's own reader.
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT, JSON.writeValueAsString(clientCeiling));
        Map<String, Object> instance = new LinkedHashMap<>();
        instance.put("spiffe_id", SPIFFE_ID);
        if (instanceCeiling != null) {
            instance.put("entitlement", instanceCeiling);
        }
        props.put(AttestationIssuanceConfig.P_INSTANCES, JSON.writeValueAsString(List.of(instance)));
        if (asserted) {
            props.put(AttestationIssuanceConfig.P_ASSERTED_CONTEXT_RESOLVER, "vectors");
        }
        return props;
    }

    private static AttestationIssuanceServlet servlet(RarModels models, AttestationIssuanceConfig config,
                                                      AssertedContextResolver resolver) {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                return config;
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of(new AttesterClient(CLIENT_ID, config));
            }
        });
        servlet.setAttesterSigningKey(new AttesterSigningKey(null, null));
        servlet.setEvidenceBindingStore(new InMemoryEvidenceBindingStore());
        servlet.setEvidencePolicy(EvidencePolicy.defaults());
        servlet.setReplayCache(new InMemoryAttestationReplayCache());
        servlet.setRarModels(models);
        if (resolver != null) {
            servlet.setAssertedContextResolvers(Map.of(resolver.id(), resolver));
        }
        return servlet;
    }

    private static AttestationIssuanceServlet.IssuanceRequest request(List<Map<String, Object>> details, String asserted)
            throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        JwtClaims svid = new JwtClaims();
        svid.setJwtId(UUID.randomUUID().toString());
        svid.setSubject(SPIFFE_ID);
        svid.setAudience(ISSUER);
        svid.setIssuedAtToNow();
        svid.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        req.svid = signCompact(bundleKey, "JWT", svid);
        JwtClaims proof = new JwtClaims();
        proof.setAudience(ISSUER);
        proof.setJwtId(UUID.randomUUID().toString());
        proof.setIssuedAtToNow();
        proof.setExpirationTime(NumericDate.fromSeconds(proof.getIssuedAt().getValue() + 120L));
        req.proof = signCompact(instanceKey, InstanceKeyProofValidator.TYP, proof);
        req.requestedDetails = details;
        req.assertedContext = asserted;
        return req;
    }

    /** The minted attestation's {@code authorization_details}, read by the model's reader; absent is empty. */
    private static List<Map<String, Object>> mintedDetails(String attestation) throws Exception {
        String payload = new String(Base64.getUrlDecoder().decode(attestation.split("\\.")[1]), StandardCharsets.UTF_8);
        Map<?, ?> claims = (Map<?, ?>) Json.parse(payload);
        return claims.containsKey("authorization_details") ? RarModels.details(claims.get("authorization_details")) : List.of();
    }

    private static boolean refuses(ThrowingCall call) {
        try {
            call.run();
            return false;
        } catch (RarModelException e) {
            return true;
        }
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void run() throws RarModelException;
    }

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static String signCompact(PublicJsonWebKey key, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        jws.setKeyIdHeaderValue(key.getKeyId());
        return jws.getCompactSerialization();
    }
}
