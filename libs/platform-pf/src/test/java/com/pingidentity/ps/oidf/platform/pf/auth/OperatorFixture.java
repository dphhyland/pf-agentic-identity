package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.HttpServletRequest;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;

/**
 * PingFederate as the operator authenticator sees it, on loopback: a JWKS and an introspection endpoint served by the
 * JDK's HTTP server, an access token manager's key, an operator's DPoP key, the requests an operator sends, and the
 * events the authenticator emits.
 */
final class OperatorFixture implements AutoCloseable {
    static final String ISSUER = "https://pf.example.com";
    static final String AUDIENCE = "https://operator.example.com/agentic-identity";
    static final String BASE = "https://pf.example.com";
    static final String PATH = "/federation-admin/hosted-entities";
    static final String CLIENT = "operator-console";
    static final String ADDRESS = "192.0.2.10";
    static final String INTROSPECTION_CLIENT = "operator-rs";
    static final OperatorRoute READ = OperatorRoute.read("hosted-entities.list", OperatorScopes.ADMIN_READ);
    static final OperatorRoute UPDATE = OperatorRoute.mutation("hosted-entities.update", OperatorScopes.ADMIN_ENTITIES);

    /** A clock the rate-limit tests move by hand. */
    static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.now());

        void advance(Duration by) {
            this.now.updateAndGet(i -> i.plus(by));
        }

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
            return this.now.get();
        }
    }

    final PublicJsonWebKey asKey;
    final PublicJsonWebKey clientKey;
    final HttpServer server;
    final AtomicReference<String> introspection = new AtomicReference<>();
    final AtomicInteger introspectionStatus = new AtomicInteger(200);
    final AtomicReference<String> lastIntrospectionAuthorization = new AtomicReference<>();
    final AtomicInteger jwksFetches = new AtomicInteger();
    final List<Event> events = new CopyOnWriteArrayList<>();
    final MutableClock clock = new MutableClock();

    OperatorFixture() throws Exception {
        this.asKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.asKey.setKeyId("pf-atm-1");
        this.clientKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        String jwks = new JsonWebKeySet(publicOnly(this.asKey)).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        this.server.createContext("/pf/JWKS", exchange -> {
            this.jwksFetches.incrementAndGet();
            byte[] out = jwks.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        this.server.createContext("/as/introspect.oauth2", exchange -> {
            exchange.getRequestBody().readAllBytes();
            this.lastIntrospectionAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] out = String.valueOf(this.introspection.get()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(this.introspectionStatus.get(), out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        this.server.start();
        Events.reset();
        Events.configure(this.events::add);
    }

    @Override
    public void close() {
        this.server.stop(0);
        Events.reset();
    }

    String origin() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    static JsonWebKey publicOnly(PublicJsonWebKey key) throws Exception {
        return JsonWebKey.Factory.newJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    static String thumbprint(PublicJsonWebKey key) throws Exception {
        return Jwks.thumbprint(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    // ---- configuration --------------------------------------------------------------------------------------------

    /** The settings of a jwt-mode deployment against this fixture's JWKS. */
    Map<String, String> jwtSettings() {
        Map<String, String> env = new HashMap<>();
        env.put(OperatorAuthConfig.AUDIENCE, AUDIENCE);
        env.put(OperatorAuthConfig.BASE_URL, BASE);
        env.put(OperatorAuthConfig.JWKS_URL, this.origin() + "/pf/JWKS");
        return env;
    }

    /** The settings of an introspection-mode deployment against this fixture's endpoint. */
    Map<String, String> introspectionSettings() {
        Map<String, String> env = new HashMap<>();
        env.put(OperatorAuthConfig.MODE, "introspection");
        env.put(OperatorAuthConfig.AUDIENCE, AUDIENCE);
        env.put(OperatorAuthConfig.BASE_URL, BASE);
        env.put(OperatorAuthConfig.INTROSPECTION_ENDPOINT, this.origin() + "/as/introspect.oauth2");
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_ID, INTROSPECTION_CLIENT);
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_SECRET, "introspection-secret");
        return env;
    }

    static Settings settings(Map<String, String> env) {
        return Settings.of(Catalogue.load(OperatorFixture.class.getClassLoader(), OperatorAuthConfig.COMPONENT),
                Sources.of(env::get, name -> null, null));
    }

    static OperatorAuthConfig config(Map<String, String> env, DeploymentProfile profile) {
        return OperatorAuthConfig.from(settings(env), profile, AcceptedRisks.none(), profile.isDevelopment());
    }

    /** An authenticator over {@code env}, in {@code profile}, with this JVM's replay store and counters. */
    OperatorAuthenticator authenticator(Map<String, String> env, DeploymentProfile profile) {
        OperatorAuthConfig config = OperatorAuthConfig.from(settings(env), profile,
                AcceptedRisks.parse("in-memory-state", java.time.LocalDate.now(ZoneOffset.UTC)), false);
        return OperatorAuthenticator.from(config, null, request -> ISSUER, this.clock);
    }

    OperatorAuthenticator jwt() {
        return this.authenticator(this.jwtSettings(), DeploymentProfile.PRODUCTION);
    }

    OperatorAuthenticator introspecting() {
        return this.authenticator(this.introspectionSettings(), DeploymentProfile.PRODUCTION);
    }

    // ---- tokens -----------------------------------------------------------------------------------------------------

    /** What PingFederate's JWT access token manager puts in a DPoP-bound client-credentials token (the rig, 2026-09-29). */
    JwtClaims claims(String scope) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(CLIENT);
        claims.setClaim("client_id", CLIENT);
        claims.setClaim("scope", scope);
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jkt", thumbprint(this.clientKey));
        claims.setClaim("cnf", cnf);
        return claims;
    }

    String token(JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(this.asKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(this.asKey.getKeyId());
        jws.setHeader("typ", "at+jwt");
        return jws.getCompactSerialization();
    }

    String token(String scope) throws Exception {
        return this.token(this.claims(scope));
    }

    /** The introspection answer PingFederate 13.1.3 gives for {@code claims}' token (the rig, 2026-09-29). */
    void introspects(JwtClaims claims) {
        Map<String, Object> answer = new LinkedHashMap<>(claims.getClaimsMap());
        answer.put("active", true);
        answer.put("token_type", answer.containsKey("cnf") ? "DPoP" : "Bearer");
        this.introspection.set(Json.write(answer));
    }

    String proof(String token, String method, String url, Consumer<JwtClaims> change) throws Exception {
        return proof(this.clientKey, token, method, url, change);
    }

    String proof(String token, String method) throws Exception {
        return this.proof(token, method, BASE + PATH, c -> { });
    }

    static String proof(PublicJsonWebKey key, String token, String method, String url, Consumer<JwtClaims> change)
            throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", method);
        claims.setClaim("htu", url);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("ath", ath(token));
        change.accept(claims);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "dpop+jwt");
        jws.getHeaders().setJwkHeaderValue("jwk",
                PublicJsonWebKey.Factory.newPublicJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return jws.getCompactSerialization();
    }

    /** RFC 9449 §4.2's ath: base64url(SHA-256(the ASCII access token)). */
    static String ath(String token) throws Exception {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest
                .getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
    }

    // ---- requests ---------------------------------------------------------------------------------------------------

    /** A request as the servlet container gives it; nothing in it is read but what the authenticator asks for. */
    static final class Request {
        final List<String> authorization = new ArrayList<>();
        final List<String> dpop = new ArrayList<>();
        String method = "GET";
        String uri = PATH;
        String query;
        String address = ADDRESS;
        String actorHeader;
        String host = "attacker.example";
        X509Certificate[] certificates;
        final Map<String, Object> attributes = new HashMap<>();

        HttpServletRequest mock() {
            HttpServletRequest r = org.mockito.Mockito.mock(HttpServletRequest.class);
            when(r.getHeaders("Authorization")).thenAnswer(i -> Collections.enumeration(this.authorization));
            when(r.getHeaders("DPoP")).thenAnswer(i -> Collections.enumeration(this.dpop));
            when(r.getHeader("X-Federation-Actor")).thenReturn(this.actorHeader);
            when(r.getHeader("Host")).thenReturn(this.host);
            when(r.getMethod()).thenReturn(this.method);
            when(r.getRequestURI()).thenReturn(this.uri);
            when(r.getQueryString()).thenReturn(this.query);
            when(r.getRemoteAddr()).thenReturn(this.address);
            when(r.getAttribute(OperatorAuthenticator.CERTIFICATE_ATTRIBUTE)).thenReturn(this.certificates);
            org.mockito.Mockito.doAnswer(i -> this.attributes.put(i.getArgument(0), i.getArgument(1)))
                    .when(r).setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
            return r;
        }
    }

    /** A DPoP request for {@code token} with a fresh proof for {@code method} on the fixture's path. */
    Request dpop(String token, String method) throws Exception {
        Request r = new Request();
        r.method = method;
        r.authorization.add("DPoP " + token);
        r.dpop.add(this.proof(token, method));
        return r;
    }

    static Request bearer(String token) {
        Request r = new Request();
        r.authorization.add("Bearer " + token);
        return r;
    }

    static X509Certificate certificate(byte[] der) throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(der);
        return cert;
    }

    /** The events of {@code code} emitted so far. */
    List<Event> events(String code) {
        return this.events.stream().filter(e -> e.code().equals(code)).toList();
    }

    Event last() {
        return this.events.get(this.events.size() - 1);
    }
}
