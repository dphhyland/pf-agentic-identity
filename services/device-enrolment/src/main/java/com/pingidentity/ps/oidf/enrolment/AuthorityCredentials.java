/*
 * How device-enrolment authenticates to the federation authority's hosted-entity API.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

/**
 * The headers a request to the authority's hosted-entity API carries (plan item S8b). The API is an operator route that
 * needs a PingFederate-issued access token with {@code oidf.admin.entities}, DPoP-bound in production; the static
 * bearer ({@code PF_AUTHORITY_ADMIN_TOKEN}, the other side's {@code OIDF_AUTHORITY_ADMIN_TOKEN}) is development's escape
 * and nothing else.
 */
interface AuthorityCredentials {

    /** The scope the hosted-entity API's enrolment route needs. */
    String SCOPE = "oidf.admin.entities";

    /** The headers for {@code method} {@code url}: {@code Authorization}, and {@code DPoP} for a DPoP-bound token. */
    Map<String, String> headers(String method, URI url) throws EnrolmentException;

    /** The API refused the credentials with 401: forget any token, so the next request gets a fresh one. */
    default void rejected() {
    }

    /** What this is, for the start-up log. */
    String describe();

    /** The settings {@link #from} reads, as Main passes them. */
    record Settings(String authorityUrl, String adminToken, String clientId, String clientSecret, String clientJwk,
                    String tokenEndpoint) {
    }

    /**
     * The credentials {@code settings} describe in {@code profile}.
     * <ul>
     *   <li>{@code PF_AUTHORITY_CLIENT_ID} set: client credentials at {@code PF_AUTHORITY_TOKEN_ENDPOINT} (default
     *       {@code <PF_AUTHORITY_URL>/as/token.oauth2}), authenticating with {@code private_key_jwt} when
     *       {@code PF_AUTHORITY_CLIENT_JWK} is set or {@code client_secret_basic} when {@code PF_AUTHORITY_CLIENT_SECRET}
     *       is (one of the two, never both), every token request carrying a DPoP proof.</li>
     *   <li>Otherwise, in development only, {@code PF_AUTHORITY_ADMIN_TOKEN} as a static bearer, with a WARN.</li>
     * </ul>
     * Production refuses to start with {@code PF_AUTHORITY_ADMIN_TOKEN} set, as the authority refuses its own static
     * bearer there (Phase 3 decision 20).
     *
     * @throws IllegalStateException naming the settings to change, when they do not describe usable credentials
     */
    static AuthorityCredentials from(Settings settings, DeploymentProfile profile, OutboundHttp http, Clock clock) {
        if (settings.adminToken() != null && profile.isProduction()) {
            throw new IllegalStateException("PF_AUTHORITY_ADMIN_TOKEN is set, and production never sends the static bearer:"
                    + " remove it and give device-enrolment a PingFederate client (PF_AUTHORITY_CLIENT_ID with"
                    + " PF_AUTHORITY_CLIENT_JWK or PF_AUTHORITY_CLIENT_SECRET)");
        }
        if (settings.clientId() != null) {
            if ((settings.clientJwk() == null) == (settings.clientSecret() == null)) {
                throw new IllegalStateException("PF_AUTHORITY_CLIENT_ID is set: set exactly one of PF_AUTHORITY_CLIENT_JWK"
                        + " (private_key_jwt) and PF_AUTHORITY_CLIENT_SECRET (client_secret_basic)");
            }
            URI endpoint = URI.create(settings.tokenEndpoint() != null ? settings.tokenEndpoint()
                    : settings.authorityUrl().replaceAll("/+$", "") + "/as/token.oauth2");
            ClientAuth auth = settings.clientJwk() != null
                    ? ClientAuth.privateKeyJwt(settings.clientId(), settings.clientJwk(), clock)
                    : ClientAuth.clientSecretBasic(settings.clientId(), settings.clientSecret());
            return new ClientCredentials(endpoint, auth, profile, http, HostedEntityRegistrar.PingFederate.TOTAL_TIMEOUT, clock);
        }
        if (settings.adminToken() != null) {
            return new StaticBearer(settings.adminToken());
        }
        throw new IllegalStateException("PF_AUTHORITY_ENTITY_ID is set but device-enrolment has no credentials for the"
                + " authority's hosted-entity API: set PF_AUTHORITY_CLIENT_ID with PF_AUTHORITY_CLIENT_JWK or"
                + " PF_AUTHORITY_CLIENT_SECRET" + (profile.isDevelopment() ? ", or in development PF_AUTHORITY_ADMIN_TOKEN" : ""));
    }

    /** Development's static bearer. */
    final class StaticBearer implements AuthorityCredentials {
        private static final Log LOGGER = LogFactory.getLog(StaticBearer.class);
        private final String token;

        StaticBearer(String token) {
            this.token = Objects.requireNonNull(token, "token");
        }

        @Override
        public Map<String, String> headers(String method, URI url) {
            LOGGER.warn((Object) ("Enrolling at " + url.getPath() + " with the static bearer PF_AUTHORITY_ADMIN_TOKEN:"
                    + " development only; production needs PF_AUTHORITY_CLIENT_ID"));
            return Map.of("Authorization", "Bearer " + this.token);
        }

        @Override
        public String describe() {
            return "the development static bearer (PF_AUTHORITY_ADMIN_TOKEN)";
        }
    }

    /** How the client authenticates at the token endpoint. */
    interface ClientAuth {
        String clientId();

        /** Adds the credentials to {@code form} and {@code headers} for a request to {@code endpoint}. */
        void apply(URI endpoint, Map<String, String> form, Map<String, String> headers) throws JoseException;

        String method();

        /** RFC 6749 §2.3.1: the client id and secret, form-encoded, as HTTP Basic's user name and password. */
        static ClientAuth clientSecretBasic(String clientId, String secret) {
            return new ClientAuth() {
                @Override
                public String clientId() {
                    return clientId;
                }

                @Override
                public void apply(URI endpoint, Map<String, String> form, Map<String, String> headers) {
                    String pair = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                            + URLEncoder.encode(secret, StandardCharsets.UTF_8);
                    headers.put("Authorization", "Basic "
                            + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8)));
                }

                @Override
                public String method() {
                    return "client_secret_basic";
                }
            };
        }

        /**
         * RFC 7523 §2.2 {@code private_key_jwt}: a fresh assertion per request, signed by the client's key - ES256 for
         * an EC key, PS256 for an RSA one, or the key's own {@code alg} - with {@code iss} and {@code sub} the client id,
         * {@code aud} the token endpoint, a {@code jti} and a lifetime of one minute.
         */
        static ClientAuth privateKeyJwt(String clientId, String jwk, Clock clock) {
            PublicJsonWebKey key;
            try {
                key = PublicJsonWebKey.Factory.newPublicJwk(jwk);
            } catch (JoseException e) {
                throw new IllegalStateException("PF_AUTHORITY_CLIENT_JWK is not a JWK: " + e.getMessage(), e);
            }
            if (key.getPrivateKey() == null) {
                throw new IllegalStateException("PF_AUTHORITY_CLIENT_JWK has no private key");
            }
            String alg = key.getAlgorithm() != null ? key.getAlgorithm()
                    : key instanceof RsaJsonWebKey ? AlgorithmIdentifiers.RSA_PSS_USING_SHA256
                    : AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
            return new ClientAuth() {
                @Override
                public String clientId() {
                    return clientId;
                }

                @Override
                public void apply(URI endpoint, Map<String, String> form, Map<String, String> headers) throws JoseException {
                    JwtClaims claims = new JwtClaims();
                    claims.setIssuer(clientId);
                    claims.setSubject(clientId);
                    claims.setAudience(endpoint.toString());
                    claims.setJwtId(UUID.randomUUID().toString());
                    long now = clock.instant().getEpochSecond();
                    claims.setClaim("iat", now);
                    claims.setClaim("exp", now + 60);
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setPayload(claims.toJson());
                    jws.setKey(key.getPrivateKey());
                    jws.setAlgorithmHeaderValue(alg);
                    if (key.getKeyId() != null) {
                        jws.setKeyIdHeaderValue(key.getKeyId());
                    }
                    form.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                    form.put("client_assertion", jws.getCompactSerialization());
                }

                @Override
                public String method() {
                    return "private_key_jwt";
                }
            };
        }
    }

    /**
     * RFC 6749 §4.4's client credentials grant for {@link #SCOPE}, each token request carrying an RFC 9449 DPoP proof by a
     * key made at start-up, so PingFederate binds the token to it; each API request then carries the token under the
     * {@code DPoP} scheme with a fresh proof. A token is reused until thirty seconds before its {@code expires_in}.
     * PingFederate answering a {@code Bearer} token - the client not set to bind - is refused in production and used as
     * a bearer token in development. A {@code use_dpop_nonce} answer (RFC 9449 §8) is retried once with the nonce.
     */
    final class ClientCredentials implements AuthorityCredentials {
        private static final Log LOGGER = LogFactory.getLog(ClientCredentials.class);
        private static final ObjectMapper JSON = new ObjectMapper();
        private static final Duration EARLY = Duration.ofSeconds(30);

        private final URI endpoint;
        private final ClientAuth auth;
        private final DeploymentProfile profile;
        private final OutboundHttp http;
        private final Duration total;
        private final Clock clock;
        private final EllipticCurveJsonWebKey proofKey;
        private String token;
        private boolean bound;
        private long expiresAt;

        /** {@code total} bounds each token request, the answer's body included. */
        ClientCredentials(URI endpoint, ClientAuth auth, DeploymentProfile profile, OutboundHttp http, Duration total,
                          Clock clock) {
            this.endpoint = endpoint;
            this.auth = auth;
            this.profile = profile;
            this.http = http;
            this.total = total;
            this.clock = clock;
            try {
                this.proofKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            } catch (JoseException e) {
                throw new IllegalStateException("a DPoP key could not be made: " + e.getMessage(), e);
            }
        }

        @Override
        public synchronized Map<String, String> headers(String method, URI url) throws EnrolmentException {
            if (this.token == null || this.clock.millis() >= this.expiresAt) {
                this.fetch();
            }
            Map<String, String> headers = new LinkedHashMap<>();
            if (this.bound) {
                headers.put("Authorization", "DPoP " + this.token);
                headers.put("DPoP", this.proof(method, url, this.token, null));
            } else {
                headers.put("Authorization", "Bearer " + this.token);
            }
            return headers;
        }

        @Override
        public synchronized void rejected() {
            this.token = null;
        }

        @Override
        public String describe() {
            return "client credentials as " + this.auth.clientId() + " (" + this.auth.method() + ", DPoP) at " + this.endpoint;
        }

        private void fetch() throws EnrolmentException {
            OutboundResponse response = this.request(null);
            String nonce = response.header("DPoP-Nonce").orElse(null);
            if (response.status() == 400 && nonce != null && response.bodyText().contains("use_dpop_nonce")) {
                response = this.request(nonce);
            }
            if (response.status() != 200) {
                // The answer stays in this log: the exception's message reaches the enrolling device.
                String body = response.bodyText();
                LOGGER.warn((Object) ("The authority's token endpoint refused device-enrolment's client " + this.auth.clientId()
                        + " (HTTP " + response.status() + "): "
                        + body.substring(0, Math.min(body.length(), 512))));
                throw EnrolmentException.serverError("the authority's token endpoint refused device-enrolment's client (HTTP "
                        + response.status() + "); device-enrolment's log has its answer", null);
            }
            JsonNode answer;
            try {
                answer = JSON.readTree(response.bodyText());
            } catch (java.io.IOException e) {
                throw EnrolmentException.serverError("the authority's token endpoint answered no JSON", e);
            }
            String accessToken = answer.path("access_token").asText(null);
            String type = answer.path("token_type").asText("");
            if (accessToken == null || accessToken.isEmpty()) {
                throw EnrolmentException.serverError("the authority's token endpoint answered no access_token", null);
            }
            boolean dpop = "DPoP".equalsIgnoreCase(type);
            if (!dpop && this.profile.isProduction()) {
                LOGGER.warn((Object) ("The authority issued a " + type + " token, not a DPoP-bound one: set Require DPoP on"
                        + " the client " + this.auth.clientId() + " in PingFederate"));
                throw EnrolmentException.serverError("the authority issued a token that is not a DPoP-bound one", null);
            }
            if (!dpop) {
                LOGGER.warn((Object) ("The authority issued a " + type + " token, not a DPoP-bound one: development only"));
            }
            long lifetime = answer.path("expires_in").asLong(60);
            this.token = accessToken;
            this.bound = dpop;
            this.expiresAt = this.clock.millis() + Math.max(0L, lifetime * 1000L - EARLY.toMillis());
        }

        private OutboundResponse request(String nonce) throws EnrolmentException {
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", "client_credentials");
            form.put("scope", SCOPE);
            Map<String, String> headers = new LinkedHashMap<>();
            try {
                this.auth.apply(this.endpoint, form, headers);
                headers.put("DPoP", this.proof("POST", this.endpoint, null, nonce));
            } catch (JoseException e) {
                throw EnrolmentException.serverError("device-enrolment's token request could not be signed: " + e.getMessage(), e);
            }
            StringBuilder body = new StringBuilder();
            form.forEach((k, v) -> body.append(body.length() == 0 ? "" : "&").append(URLEncoder.encode(k, StandardCharsets.UTF_8))
                    .append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8)));
            OutboundRequest.Builder request = OutboundRequest.builder(OutboundRequest.Method.POST, this.endpoint)
                    .header("Accept", "application/json")
                    .body("application/x-www-form-urlencoded", body.toString());
            headers.forEach(request::header);
            try {
                return this.http.send(request.build(), Deadline.after(this.total));
            } catch (OutboundHttpException e) {
                // An interrupted read keeps the thread's interrupt (platform.http); the reason says which failure it was.
                throw EnrolmentException.serverError("could not reach the authority's token endpoint: " + e.reason() + ": "
                        + e.getMessage(), e);
            }
        }

        /** An RFC 9449 §4.2 proof for {@code method} {@code url}; {@code ath} for {@code token}, {@code nonce} when given. */
        String proof(String method, URI url, String token, String nonce) throws EnrolmentException {
            try {
                JwtClaims claims = new JwtClaims();
                claims.setJwtId(UUID.randomUUID().toString());
                claims.setClaim("htm", method);
                claims.setClaim("htu", htu(url));
                claims.setClaim("iat", this.clock.instant().getEpochSecond());
                if (token != null) {
                    claims.setClaim("ath", ath(token));
                }
                if (nonce != null) {
                    claims.setClaim("nonce", nonce);
                }
                JsonWebSignature jws = new JsonWebSignature();
                jws.setPayload(claims.toJson());
                jws.setKey(this.proofKey.getPrivateKey());
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
                jws.setHeader("typ", "dpop+jwt");
                jws.getHeaders().setJwkHeaderValue("jwk", PublicJsonWebKey.Factory.newPublicJwk(
                        this.proofKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
                return jws.getCompactSerialization();
            } catch (JoseException e) {
                throw EnrolmentException.serverError("a DPoP proof could not be signed: " + e.getMessage(), e);
            }
        }

        /** RFC 9449 §4.2's htu: "The HTTP target URI ... without query and fragment parts". */
        static String htu(URI url) {
            return URI.create(url.getScheme() + "://" + url.getRawAuthority() + (url.getRawPath() == null ? "" : url.getRawPath()))
                    .toString();
        }

        /** RFC 9449 §4.2's ath: base64url(SHA-256(the ASCII access token)). */
        static String ath(String token) {
            try {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
        }
    }
}
