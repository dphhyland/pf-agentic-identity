/*
 * Operator authenticators, tokens and DPoP proofs for the operator surfaces' own tests (platform-pf's test-jar).
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.rs.InMemoryReplayStore;
import com.pingidentity.ps.oidf.rs.JwksSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;

/**
 * PingFederate as an operator surface's test sees it, with no server: an access token manager's key that the
 * authenticator is handed directly, an operator client's DPoP key, JWT access tokens with the scopes a test names, and
 * DPoP proofs for a method and a path. {@link #authenticator} builds an {@link OperatorAuthenticator} in either
 * profile over them, in jwt mode, with this JVM's replay store and counters.
 */
public final class OperatorTestKit {
    public static final String ISSUER = "https://pf.example.com";
    public static final String AUDIENCE = "https://pf.example.com/agentic-identity";
    /** {@code OIDF_OPERATOR_BASE_URL}: a proof's htu is this followed by the request's path. */
    public static final String BASE = "https://pf.example.com";
    /** The operator client: the token's sub and client_id, so the actor. */
    public static final String CLIENT = "operator-console";

    private final PublicJsonWebKey asKey;
    private final PublicJsonWebKey clientKey;

    public OperatorTestKit() throws Exception {
        this.asKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.asKey.setKeyId("pf-atm-1");
        this.clientKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }

    /** An authenticator in {@code profile}, jwt mode, verifying this kit's tokens; no static bearer. */
    public OperatorAuthenticator authenticator(DeploymentProfile profile) {
        Map<String, String> env = new HashMap<>();
        env.put(OperatorAuthConfig.AUDIENCE, AUDIENCE);
        env.put(OperatorAuthConfig.BASE_URL, BASE);
        env.put(OperatorAuthConfig.JWKS_URL, ISSUER + "/pf/JWKS");
        PublicJsonWebKey verification = publicOnly(this.asKey);
        return build(env, profile, kid -> kid.equals(this.asKey.getKeyId()) ? List.of(verification) : List.of());
    }

    /** An authenticator in {@code profile} with no PingFederate token settings at all: only a static bearer can open it. */
    public static OperatorAuthenticator unconfigured(DeploymentProfile profile) {
        return build(new HashMap<>(), profile, null);
    }

    /** An authenticator in {@code profile} over the operator-auth settings {@code env}, with no keys: for configuration tests. */
    public static OperatorAuthenticator of(Map<String, String> env, DeploymentProfile profile) {
        return build(env, profile, null);
    }

    private static OperatorAuthenticator build(Map<String, String> env, DeploymentProfile profile, JwksSource keys) {
        Settings settings = Settings.of(Catalogue.load(OperatorTestKit.class.getClassLoader(), OperatorAuthConfig.COMPONENT),
                Sources.of(env::get, name -> null, null));
        OperatorAuthConfig config = OperatorAuthConfig.from(settings, profile,
                AcceptedRisks.parse("in-memory-state", LocalDate.now(ZoneOffset.UTC)), false);
        return new OperatorAuthenticator(config, keys, null, new InMemoryReplayStore(),
                new InMemoryWindowCounter(Clock.systemUTC()), new InMemoryWindowCounter(Clock.systemUTC()), request -> ISSUER);
    }

    /** A DPoP-bound token for {@link #CLIENT} carrying {@code scopes}. */
    public String token(String... scopes) throws Exception {
        return this.token(true, scopes);
    }

    /** A token bound to nothing, carrying {@code scopes}: production refuses it. */
    public String bearerToken(String... scopes) throws Exception {
        return this.token(false, scopes);
    }

    private String token(boolean bound, String... scopes) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(CLIENT);
        claims.setClaim("client_id", CLIENT);
        claims.setClaim("scope", String.join(" ", scopes));
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        if (bound) {
            Map<String, Object> cnf = new LinkedHashMap<>();
            cnf.put("jkt", Jwks.thumbprint(this.clientKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
            claims.setClaim("cnf", cnf);
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(this.asKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(this.asKey.getKeyId());
        jws.setHeader("typ", "at+jwt");
        return jws.getCompactSerialization();
    }

    /** A DPoP proof by the kit's client key for {@code token}, {@code method} and {@link #BASE} followed by {@code path}. */
    public String proof(String token, String method, String path) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", method);
        claims.setClaim("htu", BASE + path);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("ath", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII))));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(this.clientKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "dpop+jwt");
        jws.getHeaders().setJwkHeaderValue("jwk", publicOnly(this.clientKey));
        return jws.getCompactSerialization();
    }

    private static PublicJsonWebKey publicOnly(PublicJsonWebKey key) {
        try {
            return PublicJsonWebKey.Factory.newPublicJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalStateException(e);
        }
    }
}
