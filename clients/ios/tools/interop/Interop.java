/*
 * The real enrolment service in-process, beside an oracle that stands in for Apple and PingOne, so the Swift kit
 * can be driven against the Java over HTTP.
 */
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.pingidentity.ps.oidf.appattest.AppAttestConfig;
import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.enrolment.EnrolmentHttpServer;
import com.pingidentity.ps.oidf.enrolment.EnrolmentService;
import com.pingidentity.ps.oidf.enrolment.PingOneIdTokenVerifier;
import com.pingidentity.ps.oidf.enrolment.UserAuthentication;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;

/**
 * Not part of the Maven reactor: run.sh compiles the reactor modules it needs and runs this against them.
 *
 * What is real: EnrolmentHttpServer and EnrolmentService, AppAttestVerifier, PingOneIdTokenVerifier,
 * DeviceAttestationMinter, the in-memory registry, challenge store and replay cache - the classes the service's
 * Main wires, with REGISTRY=memory and REQUIRE_COMPLIANT_DEVICE=false. What is not: Apple and PingOne. The
 * oracle mints App Attest objects in the shapes libs/app-attest's AppAttestFixtures mints, under a root this
 * process makes and the verifier is told to trust (as EnrolmentHttpEndToEndTest does: no switch in the service
 * trusts another root), and signs ID tokens with a key the verifier's JWKS source serves. It also lets the
 * caller age an instance's user verification and advance a device's App Attest counter, the two server-side
 * states a re-mint recovers from.
 *
 * Prints service=, oracle= and audience= lines, then serves until killed. Both listeners take free ports.
 */
public final class Interop {

    static final String TEAM_ID = "ABCDE12345";
    static final String BUNDLE_ID = "com.example.agentidentity.interop";
    static final String AUDIENCE = "https://enrolment.interop.test";
    static final String IDP_ISSUER = "https://idp.interop.test/as";
    static final String IDP_CLIENT_ID = "interop-app";
    static final String AAL2_POLICY = "interop-passkey";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private final KeyPair rootKey;
    private final X509Certificate rootCert;
    private final PublicJsonWebKey idpKey;
    private final InMemoryInstanceRegistry registry = new InMemoryInstanceRegistry();
    private final Map<String, KeyPair> appAttestKeys = new ConcurrentHashMap<>();

    private Interop() throws Exception {
        this.rootKey = ecKeyPair();
        this.rootCert = selfSignedRoot(this.rootKey);
        this.idpKey = RsaJwkGenerator.generateJwk(2048);
        this.idpKey.setKeyId("interop-idp-1");
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Interop interop = new Interop();
        EnrolmentHttpServer service = interop.service();
        service.start();
        HttpServer oracle = interop.oracle();
        oracle.start();
        System.out.println("service=http://127.0.0.1:" + service.port());
        System.out.println("oracle=http://127.0.0.1:" + oracle.getAddress().getPort());
        System.out.println("audience=" + AUDIENCE);
        System.out.flush();
        new CountDownLatch(1).await();
    }

    private EnrolmentHttpServer service() throws Exception {
        AppAttestVerifier appAttest = new AppAttestVerifier(AppAttestConfig.withTrustRoot(
                TEAM_ID, BUNDLE_ID, EnumSet.of(AppAttestEnvironment.PRODUCTION), this.rootCert));
        JsonWebKey idpPublic = JsonWebKey.Factory.newJwk(this.idpKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        PingOneIdTokenVerifier idTokens = new PingOneIdTokenVerifier(IDP_ISSUER, IDP_CLIENT_ID,
                kid -> this.idpKey.getKeyId().equals(kid) ? idpPublic : null,
                Map.of(AAL2_POLICY, UserAuthentication.AssuranceLevel.AAL2));
        PublicJsonWebKey attesterKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        attesterKey.setKeyId("interop-attester-1");
        JwsSigner signer = new LocalJwkSigner(attesterKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        EnrolmentService enrolment = new EnrolmentService(appAttest, idTokens, this.registry,
                new DeviceAttestationMinter(AUDIENCE), new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(), signer, AUDIENCE, Duration.ofMinutes(5), false);
        return new EnrolmentHttpServer(enrolment, signer, 0);
    }

    private HttpServer oracle() throws Exception {
        HttpServer http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        route(http, "/app-attest/key", body -> this.generateKey());
        route(http, "/app-attest/attest", this::attest);
        route(http, "/app-attest/assert", this::assertion);
        route(http, "/idp/id-token", this::idToken);
        route(http, "/registry/age-user-verification", this::ageUserVerification);
        route(http, "/registry/advance-counter", this::advanceCounter);
        route(http, "/registry/device", this::device);
        return http;
    }

    // ---- Apple ---------------------------------------------------------------------------------------------

    /** generateKey(): a key pair, and its identifier as the macOS 27.2 helper saw Apple return it, standard base64. */
    private Map<String, Object> generateKey() throws Exception {
        KeyPair key = ecKeyPair();
        String keyId = Base64.getEncoder().encodeToString(sha256(uncompressedPoint((ECPublicKey) key.getPublic())));
        this.appAttestKeys.put(keyId, key);
        return Map.of("key_id", keyId);
    }

    /** attestKey(keyId, clientDataHash): fmt, x5c with the nonce SHA-256(authData || clientDataHash), authData. */
    private Map<String, Object> attest(JsonNode body) throws Exception {
        KeyPair key = this.key(body);
        byte[] credentialId = sha256(uncompressedPoint((ECPublicKey) key.getPublic()));
        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.write(sha256((TEAM_ID + "." + BUNDLE_ID).getBytes(StandardCharsets.UTF_8)));
        authData.write(0x40);
        authData.write(new byte[4]);
        authData.write(AppAttestEnvironment.PRODUCTION.aaguid());
        authData.write(new byte[]{0, (byte) credentialId.length});
        authData.write(credentialId);
        byte[] nonce = sha256(concat(authData.toByteArray(), B64URL_DECODER.decode(body.get("client_data_hash").asText())));

        ObjectNode root = CBOR.createObjectNode();
        root.put("fmt", "apple-appattest");
        ObjectNode attStmt = root.putObject("attStmt");
        ArrayNode x5c = attStmt.putArray("x5c");
        x5c.add(leafWithNonce(key, nonce).getEncoded());
        x5c.add(this.rootCert.getEncoded());
        attStmt.put("receipt", "interop-receipt".getBytes(StandardCharsets.UTF_8));
        root.put("authData", authData.toByteArray());
        return Map.of("attestation_object", B64URL.encodeToString(CBOR.writeValueAsBytes(root)));
    }

    /** generateAssertion(keyId, clientDataHash), at the counter the caller keeps: authenticator data in the macOS 27.2 shape. */
    private Map<String, Object> assertion(JsonNode body) throws Exception {
        KeyPair key = this.key(body);
        long counter = body.get("counter").asLong();
        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.write(sha256((TEAM_ID + "." + BUNDLE_ID).getBytes(StandardCharsets.UTF_8)));
        authData.write(0xc0);
        authData.write(new byte[]{(byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter});
        authData.write(java.util.HexFormat.of().parseHex("a1781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314403000000"));
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(key.getPrivate());
        ecdsa.update(sha256(concat(authData.toByteArray(), B64URL_DECODER.decode(body.get("client_data_hash").asText()))));
        ObjectNode root = CBOR.createObjectNode();
        root.put("signature", ecdsa.sign());
        root.put("authenticatorData", authData.toByteArray());
        return Map.of("assertion", B64URL.encodeToString(CBOR.writeValueAsBytes(root)));
    }

    private KeyPair key(JsonNode body) {
        KeyPair key = this.appAttestKeys.get(body.get("key_id").asText());
        if (key == null) {
            throw new IllegalArgumentException("no App Attest key " + body.get("key_id").asText());
        }
        return key;
    }

    // ---- PingOne -------------------------------------------------------------------------------------------

    /** An ID token as PingOne issues one for a passkey sign-on policy: RS256, auth_time now, the caller's nonce. */
    private Map<String, Object> idToken(JsonNode body) throws Exception {
        long now = Instant.now().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(IDP_ISSUER);
        claims.setAudience(IDP_CLIENT_ID);
        claims.setSubject(body.path("sub").asText("interop-owner"));
        claims.setIssuedAt(org.jose4j.jwt.NumericDate.fromSeconds(now));
        claims.setExpirationTime(org.jose4j.jwt.NumericDate.fromSeconds(now + 3600));
        claims.setClaim("auth_time", now);
        claims.setClaim("acr", AAL2_POLICY);
        if (body.hasNonNull("nonce")) {
            claims.setClaim("nonce", body.get("nonce").asText());
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(this.idpKey.getKeyId());
        jws.setKey(this.idpKey.getPrivateKey());
        return Map.of("id_token", jws.getCompactSerialization());
    }

    // ---- the registry's side of the time-box and the counter ----------------------------------------------

    /** The owner last verified an hour ago: the next re-mint is refused with user_verification_required. */
    private Map<String, Object> ageUserVerification(JsonNode body) throws Exception {
        this.registry.recordUserVerification(body.get("instance_id").asText(), Instant.now().minus(Duration.ofHours(1)));
        return Map.of("status", "ok");
    }

    /** Another renewal of the same device won with this counter: the next assertion at or below it loses the race. */
    private Map<String, Object> advanceCounter(JsonNode body) throws Exception {
        this.registry.recordAppAttestCounter(this.deviceOf(body).id(), body.get("counter").asLong());
        return Map.of("status", "ok");
    }

    private Map<String, Object> device(JsonNode body) throws Exception {
        Device device = this.deviceOf(body);
        AgentInstance instance = this.registry.findInstance(body.get("instance_id").asText()).orElseThrow();
        return Map.of("app_attest_sign_count", device.appAttestSignCount(), "app_attest_key_id",
                String.valueOf(device.appAttestKeyId()), "cnf_jkt", instance.cnfJkt(), "agent_build",
                String.valueOf(instance.agentBuild()), "platform", String.valueOf(device.platform()),
                "model", String.valueOf(device.model()), "os_version", String.valueOf(device.osVersion()));
    }

    private Device deviceOf(JsonNode body) throws Exception {
        AgentInstance instance = this.registry.findInstance(body.get("instance_id").asText()).orElseThrow();
        return this.registry.findDevice(instance.deviceId()).orElseThrow();
    }

    // ---- plumbing -------------------------------------------------------------------------------------------

    private interface Handler {
        Map<String, Object> handle(JsonNode body) throws Exception;
    }

    private static void route(HttpServer http, String path, Handler handler) {
        http.createContext(path, exchange -> {
            int status = 200;
            Map<String, Object> reply;
            try {
                reply = handler.handle(JSON.readTree(exchange.getRequestBody().readAllBytes()));
            } catch (Exception e) {
                status = 500;
                reply = Map.of("error", String.valueOf(e));
            }
            write(exchange, status, reply);
        });
    }

    private static void write(HttpExchange exchange, int status, Map<String, Object> body) throws java.io.IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSignedRoot(KeyPair key) throws Exception {
        X500Name name = new X500Name("CN=Interop App Attest Root, O=Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(Instant.now().minusSeconds(3600)), Date.from(Instant.now().plusSeconds(86400)), name,
                key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return sign(builder, key);
    }

    /** The credCert: Apple's nonce extension, SEQUENCE { [1] EXPLICIT OCTET STRING nonce }, as AppAttestFixtures writes it. */
    private X509Certificate leafWithNonce(KeyPair subject, byte[] nonce) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(this.rootCert, BigInteger.valueOf(2),
                Date.from(Instant.now().minusSeconds(3600)), Date.from(Instant.now().plusSeconds(86400)),
                new X500Name("CN=Interop credCert, O=Test"), subject.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(true, 1, new DEROctetString(nonce)));
        builder.addExtension(new ASN1ObjectIdentifier(AppAttestVerifier.NONCE_OID), false, new DERSequence(vector));
        return sign(builder, this.rootKey);
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair signingKey) throws Exception {
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(signingKey.getPrivate())));
    }

    /** The X9.62 uncompressed point, 0x04 || X || Y, which Apple hashes into the key identifier. */
    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        fixed(key.getW().getAffineX(), out, 1);
        fixed(key.getW().getAffineY(), out, 33);
        return out;
    }

    private static void fixed(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int from = Math.max(0, bytes.length - 32);
        int count = bytes.length - from;
        System.arraycopy(bytes, from, target, offset + 32 - count, count);
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
