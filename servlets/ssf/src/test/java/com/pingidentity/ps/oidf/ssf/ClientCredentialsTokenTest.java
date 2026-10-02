/*
 * H-SSF-1: the receiver's poll and stream token, by client credentials from a stub authorization server.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClientCredentialsTokenTest {

    /** A clock the test moves. */
    private static final class MovingClock extends Clock {
        private Instant now = Instant.parse("2026-09-30T00:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }

        void advance(long seconds) {
            this.now = this.now.plusSeconds(seconds);
        }
    }

    /** One token request the stub server saw. */
    private record Seen(String authorization, Map<String, String> form) {
    }

    private final MovingClock clock = new MovingClock();
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final List<String> answers = new CopyOnWriteArrayList<>();
    private final List<Integer> statuses = new CopyOnWriteArrayList<>();
    private HttpServer as;

    @BeforeEach
    void start() throws IOException {
        as = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        as.createContext("/token", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = new LinkedHashMap<>();
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
            seen.add(new Seen(exchange.getRequestHeaders().getFirst("Authorization"), form));
            int n = seen.size() - 1;
            String answer = n < answers.size() ? answers.get(n) : answers.get(answers.size() - 1);
            int status = n < statuses.size() ? statuses.get(n) : 200;
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        as.start();
    }

    @AfterEach
    void stop() {
        as.stop(0);
    }

    private String endpoint() {
        return "http://127.0.0.1:" + as.getAddress().getPort() + "/token";
    }

    private SsfConfiguration.Builder receiver() {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").receiverTokenEndpoint(endpoint())
                .receiverClientId("rx client");
    }

    private ClientCredentialsToken token(SsfConfiguration config) {
        return ClientCredentialsToken.of(config, ClientCredentialsToken.httpTransport(false), clock);
    }

    private static String issued(String token, Object expiresIn) {
        return "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\"" + (expiresIn == null ? "" : ",\"expires_in\":" + expiresIn) + "}";
    }

    /** RFC 6749 §4.4.2 and §2.3.1: grant_type and scope in the form, the client in Basic, form-encoded first. */
    @Test
    @Requirement("RFC6749 §4.4.2")
    void aTokenIsObtainedWithClientSecretBasicAndKeptUntilShortlyBeforeItExpires() throws Exception {
        answers.add(issued("t1", 300));
        answers.add(issued("t2", 300));
        ClientCredentialsToken t = token(receiver().receiverClientSecret("s:ecret").receiverClientScope("ssf.manage").build());

        assertEquals("t1", t.token());
        Seen first = seen.get(0);
        assertEquals(Map.of("grant_type", "client_credentials", "scope", "ssf.manage"), first.form());
        assertEquals("Basic " + Base64.getEncoder().encodeToString("rx+client:s%3Aecret".getBytes(StandardCharsets.UTF_8)),
                first.authorization());

        clock.advance(269);
        assertEquals("t1", t.token(), "kept: 30 seconds before its 300 run out is not yet");
        assertEquals(1, seen.size());
        clock.advance(1);
        assertEquals("t2", t.token(), "replaced 30 seconds before it expires");
        assertEquals(2, seen.size());
    }

    @Test
    void aShortLivedTokenIsReplacedATenthOfItsLifetimeEarlyAndOneWithNoLifetimeUntilRefused() throws Exception {
        answers.add(issued("short", 100));
        answers.add(issued("forever", null));
        answers.add(issued("next", null));
        ClientCredentialsToken t = token(receiver().receiverClientSecret("s").build());
        assertEquals("short", t.token());
        clock.advance(89);
        assertEquals("short", t.token());
        clock.advance(1);
        assertEquals("forever", t.token());
        clock.advance(1_000_000);
        assertEquals("forever", t.token(), "no expires_in: kept until the transmitter refuses it");
        t.rejected("someone else's");
        t.rejected(null);
        assertEquals("forever", t.token());
        t.rejected("forever");
        assertEquals("next", t.token());
        assertFalse(seen.get(0).form().containsKey("scope"), "no scope configured, none asked for");
    }

    /** RFC 7523 §2.2 and §3: the assertion's iss and sub are the client, aud the token endpoint, signed by the key. */
    @Test
    void aClientWithAKeyAuthenticatesWithPrivateKeyJwt() throws Exception {
        answers.add(issued("t1", 60));
        RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048);
        key.setKeyId("rx-1");
        ClientCredentialsToken t = token(receiver()
                .receiverClientKey(key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)).build());
        assertEquals("t1", t.token());
        Seen request = seen.get(0);
        assertNull(request.authorization());
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", request.form().get("client_assertion_type"));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(request.form().get("client_assertion"));
        jws.setKey(key.getPublicKey());
        assertTrue(jws.verifySignature());
        assertEquals("RS256", jws.getAlgorithmHeaderValue());
        assertEquals("rx-1", jws.getKeyIdHeaderValue());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals("rx client", claims.getIssuer());
        assertEquals("rx client", claims.getSubject());
        assertEquals(List.of(endpoint()), claims.getAudience());
        assertEquals(clock.instant().getEpochSecond() + ClientCredentialsToken.ASSERTION_SECONDS,
                claims.getExpirationTime().getValue());
        assertTrue(claims.getJwtId() != null && claims.getIssuedAt() != null);
    }

    @Test
    void aTokenEndpointThatRefusesOrAnswersBadlyGivesNoToken() {
        ClientCredentialsToken t = token(receiver().receiverClientSecret("s").build());
        statuses.add(401);
        answers.add("{\"error\":\"invalid_client\"}");
        IOException e = assertThrows(IOException.class, t::token);
        assertEquals("the token endpoint answered HTTP 401 for client 'rx client' (invalid_client)", e.getMessage());
        List<String[]> bad = new ArrayList<>();
        bad.add(new String[] {"500", "oops", "the token endpoint answered HTTP 500 for client 'rx client'"});
        bad.add(new String[] {"400", "{\"error\":1}", "the token endpoint answered HTTP 400 for client 'rx client'"});
        bad.add(new String[] {"200", "not json", "the token endpoint's answer is not JSON"});
        bad.add(new String[] {"200", "{\"token_type\":\"Bearer\"}", "the token endpoint's answer has no access_token"});
        bad.add(new String[] {"200", "{\"access_token\":\" \",\"token_type\":\"Bearer\"}", "the token endpoint's answer has no access_token"});
        bad.add(new String[] {"200", "{\"access_token\":\"x\",\"token_type\":\"mac\"}", "the token endpoint issued a token of type mac, not Bearer"});
        bad.add(new String[] {"200", "{\"access_token\":\"x\"}", "the token endpoint issued a token of type null, not Bearer"});
        for (String[] b : bad) {
            statuses.add(Integer.parseInt(b[0]));
            answers.add(b[1]);
            assertEquals(b[2], assertThrows(IOException.class, t::token).getMessage());
        }
    }

    @Test
    void theTokenTypeIsReadInAnyCase() throws Exception {
        answers.add("{\"access_token\":\"t\",\"token_type\":\"bEaReR\",\"expires_in\":60}");
        assertEquals("t", token(receiver().receiverClientSecret("s").build()).token());
    }

    @Test
    void theSigningAlgorithmIsTheKeysOwnOrTheOneItsTypeImplies() throws Exception {
        assertEquals("RS256", ClientCredentialsToken.algorithmOf(RsaJwkGenerator.generateJwk(2048)));
        RsaJsonWebKey ps = RsaJwkGenerator.generateJwk(2048);
        ps.setAlgorithm("PS256");
        assertEquals("PS256", ClientCredentialsToken.algorithmOf(ps));
        assertEquals("ES256", ClientCredentialsToken.algorithmOf(EcJwkGenerator.generateJwk(EllipticCurves.P256)));
        assertEquals("ES384", ClientCredentialsToken.algorithmOf(EcJwkGenerator.generateJwk(EllipticCurves.P384)));
        EllipticCurveJsonWebKey p521 = EcJwkGenerator.generateJwk(EllipticCurves.P521);
        assertEquals("ES512", ClientCredentialsToken.algorithmOf(p521));
        assertEquals("EdDSA", ClientCredentialsToken.algorithmOf(OkpJwkGenerator.generateJwk(org.jose4j.jwk.OctetKeyPairJsonWebKey.SUBTYPE_ED25519)));
    }

    @Test
    void aKeyThatIsNotAPrivateJwkIsRefusedWithoutRepeatingIt() throws Exception {
        assertEquals("the receiver's client key is not a JWK",
                assertThrows(IllegalArgumentException.class, () -> ClientCredentialsToken.privateKey("secret-ish")).getMessage());
        String publicOnly = RsaJwkGenerator.generateJwk(2048).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        assertEquals("the receiver's client key is not a private RSA, EC or OKP JWK",
                assertThrows(IllegalArgumentException.class, () -> ClientCredentialsToken.privateKey(publicOnly)).getMessage());
        String oct = OctJwkGenerator.generateJwk(256).toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
        assertThrows(IllegalArgumentException.class, () -> ClientCredentialsToken.privateKey(oct));
    }

    @Test
    void anAssertionThatCannotBeSignedFailsTheRequest() throws Exception {
        EllipticCurveJsonWebKey ec = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        ec.setAlgorithm("RS256"); // an EC key cannot make an RS256 signature
        answers.add(issued("t", 60));
        ClientCredentialsToken t = token(receiver()
                .receiverClientKey(ec.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)).build());
        IllegalStateException e = assertThrows(IllegalStateException.class, t::token);
        assertTrue(e.getMessage().startsWith("the client assertion could not be signed"), e.getMessage());
    }

    @Test
    void aStaticTokenIsGivenAsItIsAndCannotBeReplaced() {
        ReceiverBearer fixed = ReceiverBearer.fixed("pt");
        assertEquals("pt", assertDoesNotThrowToken(fixed));
        fixed.rejected("pt");
        assertEquals("pt", assertDoesNotThrowToken(fixed));
    }

    private static String assertDoesNotThrowToken(ReceiverBearer bearer) {
        try {
            return bearer.token();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
