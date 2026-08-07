/*
 * Plays the phone's side of the enrolment ceremony, for real, over the wire.
 */
package com.pingidentity.ps.oidf.demo.phonesim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestFixtures;
import com.pingidentity.ps.oidf.common.Jwks;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;

/**
 * Drives a running {@link DemoServerMain} exactly the way {@code EnrolmentHttpEndToEndTest} drives an
 * in-process one — same ceremony, same synthetic App Attest, same software key standing in for the
 * Secure Enclave — except this one is a real client process talking to a real server process over a
 * real socket, so it can be pointed at {@code docker compose up}'s container instead of a JUnit fixture.
 *
 * <p>What this still cannot prove, same as the test it is modelled on: that Apple's <em>real</em>
 * attestation objects parse. Only a physical device can (see {@code docs/unverified.md}).
 *
 * <p>The one piece this cannot fabricate is a genuine human authentication: {@code --id-token} takes a
 * real PingOne ID token, obtained out of band from an actual passkey ceremony, if the server has
 * {@code PINGONE_ISSUER} configured. Without one, {@code --demo-evidence} sends an evidence string that
 * is honestly labelled as fake — which correctly fails closed against a server wired to a real tenant,
 * and that refusal is itself worth seeing.
 */
public final class PhoneSimulatorCli {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final String TRUST_ROOT_CERT_RESOURCE = "/demo/appattest-root-cert.pem";
    private static final String TRUST_ROOT_KEY_RESOURCE = "/demo/appattest-root-key.pem";
    // Mirrors EnclaveKeyProofValidator.TYP in services/device-enrolment. A real phone has no Java class
    // to import for this — it is the wire contract, restated, not a shortcut taken here.
    private static final String KEY_PROOF_TYP = "oauth-attestation-instance-proof+jwt";
    private static final String DEMO_EVIDENCE = "demo-evidence-not-a-real-idtoken";

    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;

    public static void main(String[] args) throws Exception {
        Options options = Options.parse(args);
        new PhoneSimulatorCli(options.baseUrl).run(options);
    }

    private PhoneSimulatorCli(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    private void run(Options options) throws Exception {
        narrate("target", this.baseUrl);
        HttpResponse<String> health = get("/health");
        if (health.statusCode() != 200) {
            fail("the server is not answering at " + this.baseUrl
                    + " — is `docker compose -f deploy/device-enrolment/docker-compose.yml up` running?");
        }
        narrate("server is up", "/health -> 200");

        AppAttestFixtures appAttest = new AppAttestFixtures(loadRootKeyPair(), loadRootCertificate());
        PublicJsonWebKey enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("phone-sim-" + UUID.randomUUID().toString().substring(0, 8));
        Map<String, Object> enclavePublicJwk = publicParams(enclaveKey);
        narrate("simulated Secure Enclave key", enclaveKey.getKeyId()
                + " (a software P-256 key standing in for the enclave — its private half never leaves"
                + " this process, same discipline the real thing enforces in hardware)");

        String challenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        narrate("challenge issued", challenge);

        String appId = AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID;
        byte[] clientDataHash = AppAttestFixtures.sha256(AppAttestFixtures.concat(
                Jwks.thumbprint(enclavePublicJwk).getBytes(StandardCharsets.UTF_8),
                challenge.getBytes(StandardCharsets.UTF_8)));
        AppAttestFixtures.Attestation built = appAttest.attestation(clientDataHash,
                options.development ? AppAttestEnvironment.DEVELOPMENT : AppAttestEnvironment.PRODUCTION,
                0L, appId, true);
        narrate("App Attest built", (options.development ? "development" : "production")
                + " environment, synthetic chain rooted at demo/appattest-root-cert.pem — the one thing"
                + " this cannot prove is that Apple's real attestation objects parse (docs/unverified.md)");

        Map<String, Object> enrolBody = new LinkedHashMap<>();
        enrolBody.put("appattest_object", B64URL.encodeToString(built.cbor()));
        enrolBody.put("appattest_key_id", B64URL.encodeToString(built.keyId()));
        enrolBody.put("enclave_public_jwk", enclavePublicJwk);
        enrolBody.put("challenge", challenge);
        enrolBody.put("user_authentication", options.userAuthentication());
        enrolBody.put("platform", "ios");
        enrolBody.put("model", "iPhone16,2 (simulated)");
        enrolBody.put("os_version", "18.5");
        enrolBody.put("agent_build", "phone-simulator/0.1.0");

        HttpResponse<String> enrolResponse = post("/enrol", JSON.writeValueAsString(enrolBody));
        if (enrolResponse.statusCode() != 200) {
            JsonNode error = json(enrolResponse);
            narrate("enrolment refused", error.get("error").asText() + " — "
                    + error.get("error_description").asText());
            if ("user_authentication_failed".equals(error.get("error").asText()) && options.demoEvidence) {
                System.out.println();
                System.out.println("That refusal is expected: --demo-evidence sends a string that is not");
                System.out.println("a real PingOne ID token, and the server correctly failed closed rather");
                System.out.println("than guessing. Pass a genuine one with --id-token to see the green path.");
            }
            System.exit(1);
        }
        JsonNode enrolled = json(enrolResponse);
        String instanceId = enrolled.get("instance_id").asText();
        narrate("enrolled", "instance " + instanceId);
        printClaims("Client Attestation", enrolled.get("attestation").asText());

        String reissueChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
        HttpResponse<String> reissued = post("/attestation",
                reissueBody(instanceId, reissueChallenge, enclaveKey, enclavePublicJwk));
        narrate("re-minted on the hot path", "proves possession of the enclave key; no user interaction,"
                + " no App Attest call — that only happens once, at enrolment");
        printClaims("Client Attestation (re-minted)", json(reissued).get("attestation").asText());

        if (options.suspendDeviceId != null) {
            // EnrolmentService.Enrolled deliberately never carries device_id — "the instance identifier
            // is the client's handle from here on; it never learns the device id" — so this cannot be
            // inferred from the enrolment response even by this simulator. The operator supplies it,
            // read from the registry directly (see the README: a one-line psql query against the demo
            // compose stack's Postgres).
            HttpResponse<String> compliance = post("/compliance",
                    JSON.writeValueAsString(Map.of("device_id", options.suspendDeviceId,
                            "current_status", "not-compliant")));
            narrate("CAEP compliance signal applied", compliance.statusCode() + " (device "
                    + options.suspendDeviceId + " treated as not-compliant)");

            String afterChallenge = json(post("/enrol/challenge", "{}")).get("challenge").asText();
            HttpResponse<String> refused = post("/attestation",
                    reissueBody(instanceId, afterChallenge, enclaveKey, enclavePublicJwk));
            JsonNode refusedBody = json(refused);
            narrate("re-mint after the signal", refused.statusCode() + " "
                    + (refused.statusCode() == 200 ? "(unexpected — see below)"
                            : refusedBody.get("error").asText()
                                    + " — suspended with no agent re-authentication and no revocation call"));
        }

        System.out.println();
        System.out.println("Done. Instance " + instanceId + " is enrolled.");
    }

    // ---- HTTP -------------------------------------------------------------------------------------

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

    // ---- the phone's protocol steps -----------------------------------------------------------------

    private static String reissueBody(String instanceId, String challenge, PublicJsonWebKey enclaveKey,
                                      Map<String, Object> enclavePublicJwk) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience("http://localhost");
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("challenge", challenge);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", KEY_PROOF_TYP);
        jws.getHeaders().setObjectHeaderValue("jwk", enclavePublicJwk);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", instanceId);
        body.put("key_proof", jws.getCompactSerialization());
        return JSON.writeValueAsString(body);
    }

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    // ---- narration -----------------------------------------------------------------------------------

    private static void narrate(String step, String detail) {
        System.out.println(String.format("%-28s %s", "[" + step + "]", detail));
    }

    private static void fail(String message) {
        System.err.println("ERROR: " + message);
        System.exit(1);
    }

    /** Decodes and prints the claims of an issued attestation, unverified — this is a demo narration,
     *  not a security check; the CLI has no reason to hold the attester's key. */
    private static void printClaims(String label, String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        JwtClaims claims = JwtClaims.parse(jws.getUnverifiedPayload());
        System.out.println("  " + label + ":");
        System.out.println("    sub (the instance, never the human): " + claims.getSubject());
        System.out.println("    cnf.jwk present: " + (claims.getClaimValue("cnf") != null));
        System.out.println("    exp - iat (seconds): "
                + (claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue()));
        Object workload = claims.getClaimValue("workload");
        if (workload != null) {
            System.out.println("    workload: " + workload);
        }
    }

    // ---- the shared demo trust root -------------------------------------------------------------------

    private static X509Certificate loadRootCertificate() throws Exception {
        try (InputStream in = PhoneSimulatorCli.class.getResourceAsStream(TRUST_ROOT_CERT_RESOURCE)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static KeyPair loadRootKeyPair() throws Exception {
        X509Certificate cert = loadRootCertificate();
        PrivateKey privateKey;
        try (InputStream in = PhoneSimulatorCli.class.getResourceAsStream(TRUST_ROOT_KEY_RESOURCE)) {
            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            String base64 = pem.replaceAll("-----BEGIN [^-]+-----", "")
                    .replaceAll("-----END [^-]+-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        return new KeyPair(cert.getPublicKey(), privateKey);
    }

    // ---- args ------------------------------------------------------------------------------------------

    private static final class Options {
        final String baseUrl;
        final String idToken;
        final boolean demoEvidence;
        final boolean development;
        final String suspendDeviceId;

        private Options(String baseUrl, String idToken, boolean demoEvidence, boolean development,
                        String suspendDeviceId) {
            this.baseUrl = baseUrl;
            this.idToken = idToken;
            this.demoEvidence = demoEvidence;
            this.development = development;
            this.suspendDeviceId = suspendDeviceId;
        }

        String userAuthentication() {
            return this.idToken != null ? this.idToken : DEMO_EVIDENCE;
        }

        static Options parse(String[] args) {
            String baseUrl = "http://localhost:8080";
            String idToken = null;
            boolean demoEvidence = false;
            boolean development = false;
            String suspendDeviceId = null;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--base-url" -> baseUrl = args[++i];
                    case "--id-token" -> idToken = args[++i];
                    case "--demo-evidence" -> demoEvidence = true;
                    case "--development" -> development = true;
                    case "--suspend-device" -> suspendDeviceId = args[++i];
                    default -> {
                        System.err.println("unknown argument: " + args[i]);
                        System.err.println("usage: phone-simulator [--base-url URL] "
                                + "(--id-token JWT | --demo-evidence) [--development]"
                                + " [--suspend-device DEVICE_ID]");
                        System.exit(2);
                    }
                }
            }
            if (idToken == null && !demoEvidence) {
                System.err.println("one of --id-token <real PingOne ID token> or --demo-evidence"
                        + " is required — the server does not guess who authenticated.");
                System.exit(2);
            }
            return new Options(baseUrl, idToken, demoEvidence, development, suspendDeviceId);
        }
    }
}
