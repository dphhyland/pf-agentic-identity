/*
 * device-enrolment's credentials for the authority's hosted-entity API: a DPoP-bound client-credentials token against a
 * stub token endpoint, and the static bearer in development only.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthorityCredentialsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String AUTHORITY = "https://authority.example";

    /** One request the stub saw. */
    private record Seen(String path, Map<String, String> headers, String body) {
    }

    private HttpServer server;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final AtomicReference<String> tokenType = new AtomicReference<>("DPoP");
    private final AtomicInteger tokenStatus = new AtomicInteger(200);
    private final AtomicInteger apiStatus = new AtomicInteger(201);
    private final AtomicReference<String> nonce = new AtomicReference<>();
    private final AtomicInteger issued = new AtomicInteger();

    @BeforeEach
    void start() throws Exception {
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/as/token.oauth2", exchange -> {
            Seen request = this.record(exchange);
            String wanted = this.nonce.get();
            if (wanted != null && !claims(request.headers().get("dpop")).contains("\"nonce\":\"" + wanted + "\"")) {
                exchange.getResponseHeaders().add("DPoP-Nonce", wanted);
                this.answer(exchange, 400, "{\"error\":\"use_dpop_nonce\"}");
                return;
            }
            this.answer(exchange, this.tokenStatus.get(), "{\"access_token\":\"at-" + this.issued.incrementAndGet()
                    + "\",\"token_type\":\"" + this.tokenType.get() + "\",\"expires_in\":300}");
        });
        this.server.createContext("/federation/agents", exchange -> {
            this.record(exchange);
            this.answer(exchange, this.apiStatus.get(), "{\"entityId\":\"" + AUTHORITY + "/federation/agents/a1\"}");
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private Seen record(HttpExchange exchange) throws java.io.IOException {
        Map<String, String> headers = new java.util.HashMap<>();
        exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(java.util.Locale.ROOT), v.get(0)));
        Seen s = new Seen(exchange.getRequestURI().getPath(), headers,
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        this.seen.add(s);
        return s;
    }

    private void answer(HttpExchange exchange, int status, String body) throws java.io.IOException {
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, out.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(out);
        }
    }

    private String base() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    private static String claims(String jws) {
        if (jws == null) {
            return "";
        }
        return new String(java.util.Base64.getUrlDecoder().decode(jws.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    private static Map<String, String> form(String body) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            out.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
        }
        return out;
    }

    private List<Seen> at(String path) {
        return this.seen.stream().filter(s -> s.path().equals(path)).toList();
    }

    private HostedEntityRegistrar.PingFederate registrar(String clientSecret, String clientJwk, DeploymentProfile profile) {
        return HostedEntityRegistrar.PingFederate.of(AUTHORITY, new AuthorityCredentials.Settings(this.base(), null,
                "device-enrolment", clientSecret, clientJwk, null), false, profile);
    }

    private static String register(HostedEntityRegistrar registrar) throws EnrolmentException {
        return registrar.register("a1", Map.of("kty", "EC"), Map.of(), null, null);
    }

    @Test
    void aDpopBoundClientCredentialsTokenEnrolsAndIsReused() throws Exception {
        HostedEntityRegistrar.PingFederate registrar = this.registrar("s3cret", null, DeploymentProfile.PRODUCTION);
        assertEquals(AUTHORITY + "/federation/agents/a1", register(registrar));
        assertEquals(AUTHORITY + "/federation/agents/a1", register(registrar));

        List<Seen> tokens = this.at("/as/token.oauth2");
        assertEquals(1, tokens.size(), "one token for both enrolments");
        Seen token = tokens.get(0);
        assertEquals(Map.of("grant_type", "client_credentials", "scope", "oidf.admin.entities"), form(token.body()));
        assertTrue(token.headers().get("authorization").startsWith("Basic "), "client_secret_basic");
        String tokenProof = claims(token.headers().get("dpop"));
        assertTrue(tokenProof.contains("\"htm\":\"POST\"") && tokenProof.contains("\"htu\":\"" + this.base() + "/as/token.oauth2\""),
                tokenProof);
        assertFalse(tokenProof.contains("\"ath\""), "a token request's proof has no ath");

        List<Seen> api = this.at("/federation/agents");
        assertEquals(2, api.size());
        for (Seen call : api) {
            assertEquals("DPoP at-1", call.headers().get("authorization"));
            String proof = claims(call.headers().get("dpop"));
            assertTrue(proof.contains("\"htu\":\"" + this.base() + "/federation/agents\""), proof);
            assertTrue(proof.contains("\"ath\":\"" + AuthorityCredentials.ClientCredentials.ath("at-1") + "\""), proof);
        }
        assertTrue(!claims(api.get(0).headers().get("dpop")).equals(claims(api.get(1).headers().get("dpop"))),
                "a fresh proof per request");
    }

    @Test
    void privateKeyJwtSignsAnAssertionForTheTokenEndpoint() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("enrolment-1");
        register(this.registrar(null, key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE), DeploymentProfile.PRODUCTION));

        Seen token = this.at("/as/token.oauth2").get(0);
        Map<String, String> form = form(token.body());
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.get("client_assertion_type"));
        assertNull(token.headers().get("authorization"), "no Basic header with an assertion");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(form.get("client_assertion"));
        jws.setKey(key.getPublicKey());
        assertTrue(jws.verifySignature());
        assertEquals("ES256", jws.getAlgorithmHeaderValue());
        assertEquals("enrolment-1", jws.getKeyIdHeaderValue());
        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        assertEquals("device-enrolment", claims.getIssuer());
        assertEquals("device-enrolment", claims.getSubject());
        assertEquals(List.of(this.base() + "/as/token.oauth2"), claims.getAudience());
        assertEquals(60, claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue());
    }

    @Test
    void aNonceTheTokenEndpointAsksForIsSentOnce() throws Exception {
        this.nonce.set("n-1");
        register(this.registrar("s3cret", null, DeploymentProfile.PRODUCTION));
        List<Seen> tokens = this.at("/as/token.oauth2");
        assertEquals(2, tokens.size());
        assertTrue(claims(tokens.get(1).headers().get("dpop")).contains("\"nonce\":\"n-1\""));
    }

    @Test
    void productionRefusesATokenPingFederateDidNotBindAndDevelopmentSendsItAsBearer() throws Exception {
        this.tokenType.set("Bearer");
        EnrolmentException refused = assertThrows(EnrolmentException.class,
                () -> register(this.registrar("s3cret", null, DeploymentProfile.PRODUCTION)));
        assertTrue(refused.getMessage().contains("not a DPoP-bound one"), refused.getMessage());
        assertTrue(this.at("/federation/agents").isEmpty(), "nothing is sent with an unbound token in production");

        register(this.registrar("s3cret", null, DeploymentProfile.DEVELOPMENT));
        Seen call = this.at("/federation/agents").get(0);
        assertEquals("Bearer at-2", call.headers().get("authorization"));
        assertNull(call.headers().get("dpop"));
    }

    @Test
    void aRefusedTokenIsForgottenAndATokenEndpointThatRefusesIsAnEnrolmentFailure() throws Exception {
        HostedEntityRegistrar.PingFederate registrar = this.registrar("s3cret", null, DeploymentProfile.PRODUCTION);
        this.apiStatus.set(401);
        assertThrows(EnrolmentException.class, () -> register(registrar));
        this.apiStatus.set(201);
        register(registrar);
        assertEquals(2, this.at("/as/token.oauth2").size(), "the 401 made the registrar ask again");
        assertEquals("DPoP at-2", this.at("/federation/agents").get(1).headers().get("authorization"));

        this.tokenStatus.set(401);
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> register(this.registrar("wrong", null, DeploymentProfile.PRODUCTION)));
        assertTrue(e.getMessage().contains("token endpoint refused"), e.getMessage());
        assertFalse(e.getMessage().contains("access_token"), "the endpoint's answer stays in the log, not the device's error");
    }

    @Test
    void theStaticBearerIsDevelopmentsAndProductionRefusesToStartWithIt() throws Exception {
        HttpClientHolder holder = new HttpClientHolder();
        AuthorityCredentials.Settings staticOnly = new AuthorityCredentials.Settings(this.base(), "admin-token", null, null,
                null, null);
        AuthorityCredentials dev = AuthorityCredentials.from(staticOnly, DeploymentProfile.DEVELOPMENT, holder.http, Clock.systemUTC());
        assertInstanceOf(AuthorityCredentials.StaticBearer.class, dev);
        assertEquals(Map.of("Authorization", "Bearer admin-token"), dev.headers("POST", URI.create(this.base() + "/federation/agents")));
        dev.rejected();
        assertTrue(dev.describe().contains("PF_AUTHORITY_ADMIN_TOKEN"));

        IllegalStateException production = assertThrows(IllegalStateException.class,
                () -> AuthorityCredentials.from(staticOnly, DeploymentProfile.PRODUCTION, holder.http, Clock.systemUTC()));
        assertTrue(production.getMessage().startsWith("PF_AUTHORITY_ADMIN_TOKEN is set, and production never sends the static"
                + " bearer: remove it"), production.getMessage());
        assertThrows(IllegalStateException.class, () -> AuthorityCredentials.from(new AuthorityCredentials.Settings(this.base(),
                "admin-token", "device-enrolment", "s3cret", null, null), DeploymentProfile.PRODUCTION, holder.http, Clock.systemUTC()),
                "a client does not make the static bearer acceptable in production");

        AuthorityCredentials both = AuthorityCredentials.from(new AuthorityCredentials.Settings(this.base(), "admin-token",
                "device-enrolment", "s3cret", null, null), DeploymentProfile.DEVELOPMENT, holder.http, Clock.systemUTC());
        assertInstanceOf(AuthorityCredentials.ClientCredentials.class, both, "a client wins over the static bearer");
    }

    @Test
    void settingsThatDescribeNoUsableCredentialsNameWhatToSet() throws Exception {
        HttpClientHolder holder = new HttpClientHolder();
        IllegalStateException none = assertThrows(IllegalStateException.class, () -> AuthorityCredentials.from(
                new AuthorityCredentials.Settings(this.base(), null, null, null, null, null), DeploymentProfile.DEVELOPMENT,
                holder.http, Clock.systemUTC()));
        assertTrue(none.getMessage().contains("PF_AUTHORITY_CLIENT_ID") && none.getMessage().contains("PF_AUTHORITY_ADMIN_TOKEN"));
        IllegalStateException noneInProduction = assertThrows(IllegalStateException.class, () -> AuthorityCredentials.from(
                new AuthorityCredentials.Settings(this.base(), null, null, null, null, null), DeploymentProfile.PRODUCTION,
                holder.http, Clock.systemUTC()));
        assertFalse(noneInProduction.getMessage().contains("PF_AUTHORITY_ADMIN_TOKEN"), "production is not offered the static bearer");
        for (String[] pair : new String[][] {{null, null}, {"s", "{}"}}) {
            assertThrows(IllegalStateException.class, () -> AuthorityCredentials.from(new AuthorityCredentials.Settings(this.base(),
                    null, "c", pair[0], pair[1], null), DeploymentProfile.PRODUCTION, holder.http, Clock.systemUTC()));
        }
        assertThrows(IllegalStateException.class, () -> AuthorityCredentials.ClientAuth.privateKeyJwt("c", "not a jwk", Clock.systemUTC()));
        String publicOnly = EcJwkGenerator.generateJwk(EllipticCurves.P256).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        assertThrows(IllegalStateException.class, () -> AuthorityCredentials.ClientAuth.privateKeyJwt("c", publicOnly, Clock.systemUTC()));
        AuthorityCredentials explicit = AuthorityCredentials.from(new AuthorityCredentials.Settings(this.base() + "/", null, "c",
                "s", null, "https://pf.example/as/token.oauth2"), DeploymentProfile.PRODUCTION, holder.http, Clock.systemUTC());
        assertTrue(explicit.describe().contains("https://pf.example/as/token.oauth2") && explicit.describe().contains("client_secret_basic"));
        AuthorityCredentials defaulted = AuthorityCredentials.from(new AuthorityCredentials.Settings(this.base() + "/", null, "c",
                "s", null, null), DeploymentProfile.PRODUCTION, holder.http, Clock.systemUTC());
        assertTrue(defaulted.describe().contains(this.base() + "/as/token.oauth2"), defaulted.describe());
    }

    @Test
    void aProofsHtuHasNoQueryOrFragment() {
        assertEquals("https://pf.example:9031/federation/agents",
                AuthorityCredentials.ClientCredentials.htu(URI.create("https://pf.example:9031/federation/agents?x=1#f")));
        assertEquals("https://pf.example", AuthorityCredentials.ClientCredentials.htu(URI.create("https://pf.example")));
    }

    /** A JDK client for the settings tests, which never send. */
    private static final class HttpClientHolder {
        final java.net.http.HttpClient http = java.net.http.HttpClient.newHttpClient();
    }

    @Test
    void anAnswerThatIsNotATokenIsAnEnrolmentFailure() throws Exception {
        this.server.removeContext("/as/token.oauth2");
        this.server.createContext("/as/token.oauth2", exchange -> {
            this.record(exchange);
            this.answer(exchange, 200, exchange.getRequestURI().getQuery() == null && this.issued.getAndIncrement() == 0
                    ? "not json" : "{\"token_type\":\"DPoP\"}");
        });
        HostedEntityRegistrar.PingFederate registrar = this.registrar("s3cret", null, DeploymentProfile.PRODUCTION);
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("no JSON"));
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("no access_token"));
        this.server.stop(0);
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("could not reach"));
        assertEquals(0, JSON.readTree("{}").size());
    }
    @Test
    void onlyANonceChallengeIsRetriedAndAnEmptyTokenIsNoToken() throws Exception {
        java.util.Deque<String[]> answers = new java.util.ArrayDeque<>(List.of(
                new String[] {"400", null, "{\"error\":\"invalid_request\"}"},
                new String[] {"400", "n-2", "{\"error\":\"invalid_dpop_proof\"}"},
                new String[] {"200", null, "{\"access_token\":\"\",\"token_type\":\"DPoP\"}"}));
        this.server.removeContext("/as/token.oauth2");
        this.server.createContext("/as/token.oauth2", exchange -> {
            this.record(exchange);
            String[] next = answers.poll();
            if (next[1] != null) {
                exchange.getResponseHeaders().add("DPoP-Nonce", next[1]);
            }
            this.answer(exchange, Integer.parseInt(next[0]), next[2]);
        });
        HostedEntityRegistrar.PingFederate registrar = this.registrar("s3cret", null, DeploymentProfile.PRODUCTION);
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("refused"),
                "a 400 with no nonce is a refusal");
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("refused"),
                "a nonce beside another error is a refusal, not a retry");
        assertEquals(2, this.at("/as/token.oauth2").size(), "neither was retried");
        assertTrue(assertThrows(EnrolmentException.class, () -> register(registrar)).getMessage().contains("no access_token"));
    }
}
