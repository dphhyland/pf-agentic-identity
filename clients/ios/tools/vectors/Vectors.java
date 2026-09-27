/*
 * Prints the enrolment protocol's vectors with the enrolment service's own classes, for the Swift tests to pin.
 */
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.enrolment.EnrolmentService;
import com.pingidentity.ps.oidf.jose.Jwks;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Not part of the Maven reactor: run.sh compiles the reactor modules it needs and runs this against them, so the
 * values come from the code the server runs and not from a copy of it. Three of the methods are package-private
 * static helpers (EnrolmentService's two derivations, AppAttestVerifier's nonce reader), reached by reflection
 * rather than by widening their visibility.
 *
 * The second half reads the real App Attest objects captured on macOS 27.2 (libs/app-attest's fixtures) with
 * the server's CBOR reader, so the kit can check its commitments against what a real device signed.
 */
public final class Vectors {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
    private static final HexFormat HEX = HexFormat.of();

    private Vectors() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: Vectors <libs/app-attest fixtures directory>");
        }
        // RFC 7515 Appendix A.3.1's P-256 key as the instance key and RFC 7517 Appendix A.1's first key as a
        // federation key: public keys anyone can look up, in the RFCs' own encoding.
        Map<String, Object> instance = jwk("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        Map<String, Object> federation = jwk("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        String jkt = Jwks.thumbprint(instance);
        String federationJkt = Jwks.thumbprint(federation);
        System.out.println("instance_jkt=" + jkt);
        System.out.println("federation_jkt=" + federationJkt);
        Map<String, Object> withKid = new LinkedHashMap<>(instance);
        withKid.put("kid", "enclave-1");
        System.out.println("thumbprint_ignores_kid=" + Jwks.thumbprint(withKid).equals(jkt));

        String challenge = "Kf8-TzQb1x0yJ3v2wE5tN7oP9aR4sU6dV8gH1jL0mZc";
        String build = "b4x-3Zq9vP1Ls8Kj7Hn6Md5Fc4Vb3Nx2Za1Qw0Er9Ty";
        Method twoSegments = EnrolmentService.class.getDeclaredMethod("clientDataHash", String.class, String.class);
        Method threeSegments = EnrolmentService.class.getDeclaredMethod("clientDataHash", String.class, String.class, String.class);
        Method nonce = EnrolmentService.class.getDeclaredMethod("enrolmentNonce", String.class, String.class, String.class);
        twoSegments.setAccessible(true);
        threeSegments.setAccessible(true);
        nonce.setAccessible(true);
        System.out.println("challenge=" + challenge);
        System.out.println("build=" + build);
        System.out.println("clientDataHash(jkt,challenge)_hex=" + HEX.formatHex((byte[]) twoSegments.invoke(null, jkt, challenge)));
        System.out.println("clientDataHash(jkt,challenge,build)_hex=" + HEX.formatHex((byte[]) threeSegments.invoke(null, jkt, challenge, build)));
        System.out.println("enrolmentNonce(challenge,jkt,federationJkt)=" + nonce.invoke(null, challenge, jkt, federationJkt));

        // The two-segment nonce an iOS enrolment has: the same digest, separator and encoding as the server's
        // three-segment method, but not a method the server has. Plan item X-A05 decides whether it becomes one.
        System.out.println("sha256(challenge|jkt)_b64url_NOT_A_SERVER_METHOD="
                + B64URL.encodeToString(sha256((challenge + "|" + jkt).getBytes(StandardCharsets.UTF_8))));

        // EnrolmentService.verifyRenewalAssertion: SHA-256 over the key proof's UTF-8 bytes, inline there. A made-up
        // proof: header {"alg":"ES256"}, payload {"aud":"https://enrol"}, the word "sig".
        String madeUp = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2Vucm9sIn0.c2ln";
        System.out.println("assertionClientDataHash(keyProof)_hex="
                + HEX.formatHex(sha256(madeUp.getBytes(StandardCharsets.UTF_8))));

        realDevice(Path.of(args[0]));
    }

    /**
     * The macOS 27.2 attestation: its authenticator data and the nonce Apple wrote into the credential
     * certificate, read as AppAttestVerifier reads them. The kit recomputes SHA-256(authData || clientDataHash)
     * from the fixture's jkt and challenge and must arrive at that nonce. And the two macOS 27.2 assertions:
     * authenticator data and signature, which the kit verifies over its own assertion commitment.
     */
    private static void realDevice(Path fixtures) throws Exception {
        JsonNode attestation = JSON.readTree(fixtures.resolve("macos-27.2-attestation.json").toFile());
        JsonNode object = CBOR.readTree(B64URL_DECODER.decode(attestation.get("attestation_object").asText()));
        X509Certificate credCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(object.path("attStmt").path("x5c").get(0).binaryValue()));
        Method nonceOf = AppAttestVerifier.class.getDeclaredMethod("nonceFromCertificate", X509Certificate.class);
        nonceOf.setAccessible(true);
        System.out.println("macos27_attestation_jkt=" + attestation.get("jkt").asText());
        System.out.println("macos27_attestation_challenge=" + attestation.get("challenge").asText());
        System.out.println("macos27_attestation_authData_hex=" + HEX.formatHex(object.get("authData").binaryValue()));
        System.out.println("macos27_attestation_credCert_nonce_hex=" + HEX.formatHex((byte[]) nonceOf.invoke(null, credCert)));

        JsonNode assertions = JSON.readTree(fixtures.resolve("macos-27.2-assertions.json").toFile());
        System.out.println("macos27_assertion_client_data=" + assertions.get("client_data").asText());
        System.out.println("macos27_assertion_key_spki_b64url=" + assertions.get("attested_key_spki").asText());
        int i = 0;
        for (JsonNode encoded : assertions.get("assertions")) {
            JsonNode assertion = CBOR.readTree(B64URL_DECODER.decode(encoded.asText()));
            System.out.println("macos27_assertion" + i + "_authenticatorData_hex="
                    + HEX.formatHex(assertion.get("authenticatorData").binaryValue()));
            System.out.println("macos27_assertion" + i + "_signature_der_hex="
                    + HEX.formatHex(assertion.get("signature").binaryValue()));
            i++;
        }
    }

    private static Map<String, Object> jwk(String x, String y) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", x);
        jwk.put("y", y);
        return jwk;
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}
