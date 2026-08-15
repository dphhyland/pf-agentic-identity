package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestFixtures;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Drives the real HTTP surface over the wire, standing in for the phone.
 *
 * <p>This is the harness the iOS app is later ported from: it performs the whole ceremony — challenge,
 * App Attest with the enclave-key commitment, enrolment, re-issuance, the time-box refusal and its
 * recovery — against a running {@link EnrolmentHttpServer}, using a software P-256 key where the phone
 * would use the Secure Enclave.
 *
 * <p>It is Java rather than the Python client originally sketched, for two reasons. It runs in CI with
 * no extra runtime, and — the substantive one — it constructs the service directly with the fixture
 * trust root, so no "trust an arbitrary attestation root" configuration switch has to exist. A service
 * whose job is attestation should not ship a flag that makes it accept anyone's root.
 *
 * <p>What it still cannot prove: that Apple's <em>real</em> attestation objects parse. Only hardware
 * can (see {@code docs/unverified.md}).
 */
class EnrolmentHttpEndToEndTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private AppAttestFixtures appAttest;
    private InstanceRegistry registry;
    private FakeIdp idp;
    private EnrolmentHttpServer server;
    private HttpClient http;
    private String baseUrl;

    private PublicJsonWebKey enclaveKey;      // the phone's Secure Enclave key, in software here
    private Map<String, Object> enclavePublicJwk;

    @BeforeEach
    void setUp() throws Exception {
        appAttest = new AppAttestFixtures();
        registry = new InMemoryInstanceRegistry();
        idp = new FakeIdp();

        enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("enclave-1");
        enclavePublicJwk = publicParams(enclaveKey);

        PublicJsonWebKey platformKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        platformKey.setKeyId("platform-1");
        JwsSigner signer = new LocalJwkSigner(privateParams(platformKey));

        // Port 0 so tests can run concurrently without fighting over a fixed port.
        EnrolmentHttpServer bootstrap = new EnrolmentHttpServer(
                new EnrolmentService(
                        new AppAttestVerifier(appAttest.config(EnumSet.of(AppAttestEnvironment.PRODUCTION))),
                        idp, registry, new DeviceAttestationMinter("http://localhost"),
                        new InMemoryAttestationChallengeService(), new InMemoryAttestationReplayCache(),
                        signer, "http://localhost", Duration.ofMinutes(5), false),
                signer, 0);
        bootstrap.start();
        this.server = bootstrap;
        this.baseUrl = "http://localhost:" + bootstrap.port();
        this.http = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        if (this.server != null) {
            this.server.stop();
        }
    }

    // ---- the full ceremony -------------------------------------------------------------------

    @Test
    void thePhoneCanEnrolAndThenKeepMintingUntilTheTimeBoxLapses() throws Exception {
        // 1. Health, before anything else — the readiness probe the deploy config points at.
        assertEquals(200, get("/health").statusCode());

        // 2. A one-time challenge.
        JsonNode challenge = json(post("/enrol/challenge", "{}"));
        String nonce = challenge.get("challenge").asText();
        assertNotNull(nonce);
        assertTrue(challenge.get("expires_in").asLong() > 0);

        // 3. App Attest, committing to the enclave key exactly as the phone would.
        JsonNode enrolled = json(post("/enrol", enrolBody(nonce, enclavePublicJwk)));
        String instanceId = enrolled.get("instance_id").asText();
        String attestation = enrolled.get("attestation").asText();
        assertNotNull(instanceId);
        assertEquals(900L, enrolled.get("expires_in").asLong());

        // The attestation names the instance, not the human.
        JwtClaims claims = parse(attestation);
        assertEquals(instanceId, claims.getSubject());
        assertFalse(attestation.contains("pingone|alice"));

        // 4. Re-mint on the hot path, proving possession of the enclave key.
        String freshChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        JsonNode reissued = json(post("/attestation", reissueBody(instanceId, freshChallenge)));
        assertEquals(900L, reissued.get("expires_in").asLong());

        // 5. Let user verification age out. The key still signs — the server is what refuses.
        registry.recordUserVerification(instanceId, Instant.now().minus(Duration.ofHours(2)));
        String staleChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        HttpResponse<String> refused = post("/attestation", reissueBody(instanceId, staleChallenge));
        assertEquals(401, refused.statusCode());
        assertEquals("user_verification_required", json(refused).get("error").asText());

        // 6. Put the human back in front of the phone, and it resumes.
        assertEquals(200, post("/user-verification",
                "{\"instance_id\":\"" + instanceId + "\",\"user_authentication\":\"ok\"}").statusCode());
        String afterChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        assertEquals(200, post("/attestation", reissueBody(instanceId, afterChallenge)).statusCode());
    }

    @Test
    void theJwksIsServedSoPingFederateCanVerifyWhatWeMint() throws Exception {
        JsonNode jwks = json(get("/.well-known/jwks.json"));
        JsonNode keys = jwks.get("keys");
        assertEquals(1, keys.size());
        assertEquals("platform-1", keys.get(0).get("kid").asText());
        assertEquals("EC", keys.get(0).get("kty").asText());
        // A private key here would hand the attester's signing key to every caller.
        assertTrue(keys.get(0).get("d") == null, "the JWKS must be public only");
    }

    @Test
    void everyResponseIsUncacheable() throws Exception {
        // Challenges are one-time and attestations are bearer-adjacent; a cache would break both.
        assertEquals("no-store", get("/health").headers().firstValue("cache-control").orElse(null));
        assertEquals("no-store",
                post("/enrol/challenge", "{}").headers().firstValue("cache-control").orElse(null));
    }

    // ---- refusals, over the wire ---------------------------------------------------------------

    @Test
    void anAttestationCommittingToAnotherKeyIsRefusedWithAUsableErrorCode() throws Exception {
        PublicJsonWebKey attacker = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        attacker.setKeyId("attacker");
        String nonce = json(post("/enrol/challenge", "{}")).get("challenge").asText();

        // The App Attest object commits to the attacker's key; the body presents ours.
        HttpResponse<String> response = post("/enrol", enrolBody(nonce, publicParams(attacker)));
        assertEquals(401, response.statusCode());
        assertEquals("invalid_attestation", json(response).get("error").asText());
    }

    @Test
    void aReusedChallengeIsRefused() throws Exception {
        String nonce = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        assertEquals(200, post("/enrol", enrolBody(nonce, enclavePublicJwk)).statusCode());

        HttpResponse<String> replay = post("/enrol", enrolBody(nonce, enclavePublicJwk));
        assertEquals(400, replay.statusCode());
        assertEquals("invalid_challenge", json(replay).get("error").asText());
    }

    @Test
    void anUnknownInstanceIsFourOhFourRatherThanAnOpaqueFailure() throws Exception {
        HttpResponse<String> response = post("/attestation",
                "{\"instance_id\":\"ghost\",\"key_proof\":\"x\"}");
        assertEquals(404, response.statusCode());
        assertEquals("unknown_instance", json(response).get("error").asText());
    }

    @Test
    void malformedJsonIsRefusedWithoutLeakingAStackTrace() throws Exception {
        HttpResponse<String> response = post("/enrol", "{not json");
        assertEquals(400, response.statusCode());
        assertEquals("invalid_request", json(response).get("error").asText());
        assertFalse(response.body().contains("Exception"), response.body());
    }

    @Test
    void aComplianceSignalSuspendsTheInstanceOverHttp() throws Exception {
        String nonce = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        String instanceId = json(post("/enrol", enrolBody(nonce, enclavePublicJwk)))
                .get("instance_id").asText();
        String deviceId = registry.findInstance(instanceId).orElseThrow().deviceId();

        assertEquals(200, post("/compliance",
                "{\"device_id\":\"" + deviceId + "\",\"current_status\":\"not-compliant\"}").statusCode());
        assertEquals(ComplianceState.NOT_COMPLIANT,
                registry.findDevice(deviceId).orElseThrow().complianceState());

        String freshChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        HttpResponse<String> response = post("/attestation", reissueBody(instanceId, freshChallenge));
        assertEquals(403, response.statusCode());
        assertEquals("instance_not_active", json(response).get("error").asText());
    }

    // ---- the phone's side of the protocol --------------------------------------------------------

    /** Exactly what the iOS app must build: App Attest committing to the enclave JWK thumbprint. */
    private String enrolBody(String challenge, Map<String, Object> jwkCommittedTo) throws Exception {
        byte[] clientDataHash =
                EnrolmentService.clientDataHash(Jwks.thumbprint(jwkCommittedTo), challenge);
        AppAttestFixtures.Attestation built = appAttest.attestation(clientDataHash,
                AppAttestEnvironment.PRODUCTION, 0L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, true);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("appattest_object", B64URL.encodeToString(built.cbor()));
        body.put("appattest_key_id", B64URL.encodeToString(built.keyId()));
        body.put("enclave_public_jwk", enclavePublicJwk);
        body.put("challenge", challenge);
        body.put("user_authentication", "ok");
        body.put("platform", "ios");
        body.put("model", "iPhone16,2");
        body.put("os_version", "18.5");
        body.put("agent_build", "agent/1.0");
        return JSON.writeValueAsString(body);
    }

    /** The enclave-key proof: a JWS carrying its own public key, thumbprint-matched server side. */
    private String reissueBody(String instanceId, String challenge) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience("http://localhost");
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("challenge", challenge);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", EnclaveKeyProofValidator.TYP);
        jws.getHeaders().setObjectHeaderValue("jwk", enclavePublicJwk);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", instanceId);
        body.put("key_proof", jws.getCompactSerialization());
        return JSON.writeValueAsString(body);
    }

    // ---- plumbing ---------------------------------------------------------------------------------

    private HttpResponse<String> get(String path) throws Exception {
        return this.http.send(HttpRequest.newBuilder(URI.create(this.baseUrl + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return this.http.send(HttpRequest.newBuilder(URI.create(this.baseUrl + path))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static JsonNode json(HttpResponse<String> response) throws Exception {
        return JSON.readTree(response.body());
    }

    private static JwtClaims parse(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    }

    /** Stands in for PingOne so the ceremony runs without a tenant. */
    private static final class FakeIdp implements UserAuthenticationVerifier {
        @Override
        public UserAuthentication verify(String evidence) {
            return new UserAuthentication("pingone|alice", Instant.now(),
                    UserAuthentication.AssuranceLevel.AAL2, "cred-abc", "aaguid-1");
        }
    }
}
