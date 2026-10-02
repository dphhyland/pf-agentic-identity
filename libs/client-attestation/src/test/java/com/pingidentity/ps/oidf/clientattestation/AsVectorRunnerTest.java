package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.rar.model.Vectors;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared vector file ({@code libs/rar-model}'s test-jar) run through the authorization server's token gate:
 * the second of the plan's four runners (library, AS, CAS, refresh). Each case goes through
 * {@link ClientAttestationVerifier#verify} as a token request would - the case's ceiling signed into a Client
 * Attestation's {@code authorization_details}, its candidate sent as the request's {@code authorization_details}
 * text, a proof of possession, the case's models - and the gate's answer is compared with the case's.
 *
 * <p>The gate is CAS §7.1's check, strict: "ensure that any authority granted in issued tokens is a subset of the
 * attestation's {@code authorization_details} (same subset semantics as Section 7 rule 1), and MUST reject requests
 * exceeding it with {@code invalid_authorization_details}". So it answers the cases that ask whether a candidate
 * is within a ceiling ({@code contains}, a {@code STRICT} {@code authorize}), whether a list is well formed
 * ({@code validate}, {@code details}, {@code parse}: the list as the request, within itself when well formed), and
 * what a models document loads to ({@code load}, {@code fingerprint}: through {@link AttestationRarModels} and the
 * environment, as the filter loads it). {@code INHERIT}, {@code fullCeiling} and {@code intersect} are the
 * attester's operations and run through {@code CasVectorRunnerTest} in {@code servlets/attestation-issuer}.
 *
 * <p>How an answer is read: a grant is "within" (the granted list must equal the candidate, or the case's
 * {@code granted}); a refusal with the fixed "exceeds" description is "not within"; every refusal carries the
 * model's reason as its cause, which must be the case's reason ({@code EXCEEDS_CEILING} for "not within"). The error is
 * {@code invalid_client} when the attestation's own details are what the model refuses and
 * {@code invalid_authorization_details} otherwise.
 *
 * <p>Three cases are answered differently on purpose, named in {@link #DIVERGENCES} with the reason, and the
 * gate's own answer to them is asserted instead.
 */
@Requirement({"CAS §7(1)", "CAS §7.1", "RFC9396 §5", "RFC9396 §6.1"})
class AsVectorRunnerTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com/agent";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The cases the token gate answers differently from the library, and why. */
    static final Map<String, String> DIVERGENCES = Map.of(
            "forbidden: _principal_sub in a candidate is refused",
            "the gate takes the BFF's principal marker off before the model is asked, so the rest is compared",
            "forbidden: _agent_id in a candidate is refused",
            "the gate takes the agent marker off before the model is asked; the filter writes the verified one after",
            "lists: a malformed ceiling is refused even when the candidate is empty",
            "a request that asks for nothing is not checked at the token endpoint (what is issued from earlier "
                    + "details is plan item S4d)");

    private static PublicJsonWebKey attesterKey;
    private static PublicJsonWebKey instanceKey;
    private static AttesterKeyResolver resolver;

    @BeforeAll
    static void keys() throws Exception {
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
        JsonWebKey attesterPublic = JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey));
        resolver = (iss, chain) -> List.of(attesterPublic);
    }

    @AfterEach
    void readTheProcessEnvironmentAgain() {
        AttestationRarModels.resetForTest(null);
    }

    @TestFactory
    Stream<DynamicTest> theTokenGateAnswersEveryCaseItIsAsked() {
        List<Vectors.Case> cases = Vectors.load();
        List<Vectors.Case> asked = cases.stream().filter(AsVectorRunnerTest::asked).toList();
        assertTrue(asked.size() > 180, "the file was read and most of it is the gate's to answer: " + asked.size());
        return asked.stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> run(c)));
    }

    /**
     * The {@code authorize} cases under {@code INHERIT}, through the gate's {@code INHERIT} entry point - what the
     * token-endpoint filter asks at PAR, CIBA, the device authorization endpoint and the token endpoint, and then
     * forwards in place of the request's details (plan item S4d). The gate grants what the library grants, and
     * refuses what it refuses with the library's reason; the grant is within the ceiling by the strict check.
     */
    @TestFactory
    @Requirement({"CAS §7(1)", "CAS §7.1", "RFC9396 §5", "RFC9396 §6"})
    Stream<DynamicTest> theInheritGateGrantsWhatTheLibraryGrants() {
        List<Vectors.Case> inherit = Vectors.load().stream()
                .filter(c -> c.op().equals("authorize") && c.mode() == com.pingidentity.ps.oidf.rar.model.Omission.INHERIT)
                .toList();
        assertTrue(inherit.size() >= 20, "the INHERIT cases were read: " + inherit.size());
        return inherit.stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> runInherit(c)));
    }

    private static void runInherit(Vectors.Case c) throws Exception {
        RarModels models = c.models();
        String request = JSON.writeValueAsString(c.list("candidate"));
        Object ceiling = c.list("ceiling");
        Answer answer = ask(models, request, ceiling, com.pingidentity.ps.oidf.rar.model.Omission.INHERIT);
        RarModelException.Reason refusal = c.expectedRefusal();
        if (refusal != null) {
            assertEquals(refusal, answer.reason, "'" + c.name() + "': " + answer.error + ": " + answer.description);
            String error = ceilingIsTheFault(models, request, ceiling)
                    ? ClientAttestationException.INVALID_CLIENT : ClientAttestationException.INVALID_AUTHORIZATION_DETAILS;
            assertEquals(error, answer.error, c.name());
            if (refusal == RarModelException.Reason.EXCEEDS_CEILING) {
                assertEquals(AuthorizationDetailsGate.EXCEEDS, answer.description, c.name());
            }
            return;
        }
        assertNull(answer.error, "'" + c.name() + "' was refused: " + answer.error + ": " + answer.description);
        Object want = ((Map<?, ?>) c.expect()).get("granted");
        assertEquals(Vectors.canonical(want), Vectors.canonical(answer.granted), c.name());
        assertTrue(models.contains(RarModels.details(ceiling), answer.granted), "the grant is within the ceiling: " + c.name());
    }

    /** Every divergence names a case that exists, so renaming one in the file cannot quietly drop the check. */
    @Test
    void everyDivergenceNamesACaseInTheFile() {
        Set<String> names = Vectors.load().stream().map(Vectors.Case::name).collect(Collectors.toSet());
        for (String name : DIVERGENCES.keySet()) {
            assertTrue(names.contains(name), "no case named '" + name + "' in the vector file");
        }
    }

    static boolean asked(Vectors.Case c) {
        switch (c.op()) {
            case "contains":
            case "validate":
            case "details":
            case "parse":
            case "load":
            case "fingerprint":
                return true;
            case "authorize":
                return c.mode() == com.pingidentity.ps.oidf.rar.model.Omission.STRICT;
            default:
                return false;
        }
    }

    private static void run(Vectors.Case c) throws Exception {
        if (c.op().equals("load") || c.op().equals("fingerprint")) {
            runLoad(c);
            return;
        }
        RarModels models = c.models();
        boolean expectsWellFormed = "ok".equals(c.expect());
        String request;
        Object ceiling;
        switch (c.op()) {
            case "parse":
                request = (String) c.raw().get("text");
                // Well formed: within itself, read as the library reads it (blank text is an empty list). Not:
                // against an empty ceiling, which the model validates first.
                ceiling = expectsWellFormed ? RarModels.parseDetails(request) : List.of();
                break;
            case "validate":
            case "details":
                request = JSON.writeValueAsString(c.list("details"));
                ceiling = expectsWellFormed ? c.list("details") : List.of();
                break;
            default:
                request = JSON.writeValueAsString(c.list("candidate"));
                ceiling = c.list("ceiling");
        }
        Answer answer = ask(models, request, ceiling);

        if (DIVERGENCES.containsKey(c.name())) {
            assertNull(answer.error, "'" + c.name() + "': " + DIVERGENCES.get(c.name()) + ", so it is granted");
            for (Map<String, Object> detail : answer.granted) {
                assertTrue(!detail.containsKey("_principal_sub") && !detail.containsKey("_agent_id"),
                        "no marker is granted: " + detail);
            }
            return;
        }

        Object expect = c.expect();
        RarModelException.Reason refusal = c.expectedRefusal();
        if (refusal == RarModelException.Reason.EXCEEDS_CEILING || Boolean.FALSE.equals(expect)) {
            assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, answer.error, c.name());
            assertEquals(AuthorizationDetailsGate.EXCEEDS, answer.description, c.name());
            assertEquals(RarModelException.Reason.EXCEEDS_CEILING, answer.reason, "the log names the detail: " + c.name());
        } else if (refusal != null) {
            assertEquals(refusal, answer.reason, "'" + c.name() + "': the model's reason rides as the cause ("
                    + answer.error + ": " + answer.description + ")");
            String error = ceilingIsTheFault(models, request, ceiling)
                    ? ClientAttestationException.INVALID_CLIENT : ClientAttestationException.INVALID_AUTHORIZATION_DETAILS;
            assertEquals(error, answer.error, c.name());
        } else {
            assertNull(answer.error, "'" + c.name() + "' was refused: " + answer.error + ": " + answer.description
                    + " (" + answer.reason + ")");
            Object want = expect instanceof Map<?, ?> m && m.containsKey("granted") ? m.get("granted")
                    : c.op().equals("contains") ? c.list("candidate") : ceiling;
            assertEquals(Vectors.canonical(want), Vectors.canonical(answer.granted), c.name());
        }
    }

    /**
     * Whether the gate refuses the attestation's details rather than the request's, in the gate's own order: a
     * request that is not a list of objects is refused first, one that asks for nothing is never compared, and
     * the attestation's details are held to the model before the request's are.
     */
    private static boolean ceilingIsTheFault(RarModels models, String request, Object ceiling) {
        try {
            if (RarModels.parseDetails(request).isEmpty()) {
                return false;
            }
        } catch (RarModelException e) {
            return false;
        }
        try {
            models.validate(RarModels.details(ceiling), "ceiling");
            return false;
        } catch (RarModelException e) {
            return true;
        }
    }

    /** A {@code load} or {@code fingerprint} case, through the environment the filter loads its models from. */
    private static void runLoad(Vectors.Case c) {
        Map<String, String> env = new HashMap<>();
        if (c.raw().get("models") instanceof Map<?, ?> spec) {
            if (Boolean.TRUE.equals(spec.get("development"))) {
                env.put(RarModels.ENV_PROFILE, RarModels.DEVELOPMENT_PROFILE);
            }
            if (spec.get("document") != null) {
                env.put(RarModels.ENV_MODELS, Json.write(spec.get("document")));
            }
        }
        AttestationRarModels.resetForTest(env);
        RarModels loaded;
        try {
            loaded = AttestationRarModels.get();
        } catch (RarModelException e) {
            assertEquals(c.expectedRefusal(), e.reason(), "'" + c.name() + "' was refused: " + e.getMessage());
            return;
        }
        assertNull(c.expectedRefusal(), "'" + c.name() + "' loaded, where the case expects a refusal");
        Map<?, ?> expect = (Map<?, ?>) c.expect();
        if (expect.containsKey("fingerprint")) {
            assertEquals(expect.get("fingerprint"), loaded.fingerprint(), c.name());
        } else {
            for (Object type : (List<?>) expect.get("types")) {
                assertTrue(loaded.types().contains(type), "'" + c.name() + "': " + type + " among " + loaded.types());
            }
        }
    }

    /** What the gate answered: a grant, or an error with its description and the model's reason. */
    private record Answer(List<Map<String, Object>> granted, String error, String description, RarModelException.Reason reason) {
    }

    private static Answer ask(RarModels models, String request, Object ceiling) throws Exception {
        return ask(models, request, ceiling, com.pingidentity.ps.oidf.rar.model.Omission.STRICT);
    }

    private static Answer ask(RarModels models, String request, Object ceiling, com.pingidentity.ps.oidf.rar.model.Omission omission)
            throws Exception {
        ClientAttestationVerifier verifier = ClientAttestationVerifier.withRarModels(resolver,
                ClientAttestationConfig.builder().expectedAudience(OP_ISSUER).expectedHtu(TOKEN_ENDPOINT).build(),
                new InMemoryAttestationReplayCache(), null, models);
        try {
            ClientAttestationResult result = verifier.verify(attestation(ceiling), pop(), null, "POST",
                    TOKEN_ENDPOINT, CLIENT_ID, request, omission);
            assertEquals(models.fingerprint(), result.rarModelsFingerprint());
            return new Answer(result.grantedAuthorizationDetails(), null, null, null);
        } catch (ClientAttestationException e) {
            RarModelException.Reason reason = e.getCause() instanceof RarModelException r ? r.reason() : null;
            if (reason == null) {
                fail("refused before the gate was asked: " + e.error() + ": " + e.getMessage());
            }
            return new Answer(List.of(), e.error(), e.getMessage(), reason);
        }
    }

    /**
     * A Client Attestation whose {@code authorization_details} is {@code ceiling} as JSON text, signed. The payload is
     * written here, not by jose4j, so a decimal reaches the gate as the case wrote it; jose4j still reads the
     * whole payload when it verifies the signature, as it does at the token endpoint.
     */
    private static String attestation(Object ceiling) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        long now = NumericDate.now().getValue();
        claims.put("iss", ATTESTER);
        claims.put("sub", CLIENT_ID);
        claims.put("iat", now);
        claims.put("exp", now + 600);
        claims.put("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        claims.put("authorization_details", ceiling);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JSON.writeValueAsString(claims));
        jws.setKey(attesterKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "oauth-client-attestation+jwt");
        return jws.getCompactSerialization();
    }

    private static String pop() throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId(UUID.randomUUID().toString());
        pop.setIssuedAtToNow();
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }
}
