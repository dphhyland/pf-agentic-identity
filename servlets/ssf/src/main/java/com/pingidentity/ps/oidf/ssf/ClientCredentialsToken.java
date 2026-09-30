/*
 * The SSF receiver's access token, obtained from the transmitter's authorization server by client credentials.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.auth.ClientAuthentication;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;

/**
 * The receiver's bearer token for a transmitter's poll and stream endpoints (plan item H-SSF-1), obtained by the
 * client credentials grant. SSF 1.0 §7.1.1 leaves the scheme to the parties and, for {@code urn:ietf:rfc:6749}, says
 * "the Receiver may obtain an access token using the Client Credentials Grant (Section 4.4 of [RFC6749])"; RFC 6749
 * §4.4.2 is a POST of {@code grant_type=client_credentials} and an optional {@code scope}, with the client
 * authenticated as §2.3 says.
 *
 * <p>The client authenticates with {@code client_secret_basic} (RFC 6749 §2.3.1) when it has a secret, or
 * {@code private_key_jwt} (RFC 7523 §2.2) when it has a private key: a JWK, whose {@code alg} it signs with, or
 * RS256, ES256/384/512 by curve, or EdDSA by its key type. Both are platform's {@link ClientAuthentication}.
 *
 * <p>The token is kept until {@value #REFRESH_BEFORE_SECONDS} seconds (or a tenth of its lifetime, if that is less)
 * before its {@code expires_in} runs out, and until a 401 when the server gave no {@code expires_in}; a call answered
 * 401 hands it back ({@link #rejected}) and the next {@link #token} asks again. One request is made at a time.
 */
public final class ClientCredentialsToken implements ReceiverBearer {

    /** A token is replaced this long before it expires, or a tenth of its lifetime when that is shorter. */
    static final long REFRESH_BEFORE_SECONDS = 30;
    /** How long a {@code private_key_jwt} assertion lives. */
    static final long ASSERTION_SECONDS = 60;

    /** The token endpoint POST: form body and headers in, status and body out. */
    public interface TokenTransport {
        Response post(URI endpoint, String formBody, Map<String, String> headers) throws Exception;
    }

    /** A token endpoint's answer. */
    public record Response(int status, String body) {
    }

    private final URI endpoint;
    private final String clientId;
    private final ClientAuthentication authentication;
    private final String scope;
    private final TokenTransport transport;
    private final Clock clock;
    private String token;
    private long refreshAt;

    ClientCredentialsToken(URI endpoint, String clientId, ClientAuthentication authentication, String scope,
            TokenTransport transport, Clock clock) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.authentication = Objects.requireNonNull(authentication, "authentication");
        this.scope = scope;
        this.transport = Objects.requireNonNull(transport, "transport");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The receiver's token from its settings: the token endpoint, the client id, its secret or its private key (one of
     * the two, which {@link SsfConfiguration} ensures), and the scope; over {@code transport}.
     */
    public static ClientCredentialsToken of(SsfConfiguration config, TokenTransport transport, Clock clock) {
        String clientId = config.receiverClientId();
        String secret = config.receiverClientSecret();
        ClientAuthentication auth = secret != null
                ? ClientAuthentication.clientSecretBasic(clientId, () -> secret)
                : privateKeyJwt(clientId, config.receiverClientKey(), clock);
        return new ClientCredentialsToken(URI.create(config.receiverTokenEndpoint()), clientId, auth,
                config.receiverClientScope(), transport, clock);
    }

    @Override
    public synchronized String token() throws Exception {
        long now = this.clock.instant().getEpochSecond();
        if (this.token != null && now < this.refreshAt) {
            return this.token;
        }
        this.token = null;
        ClientAuthentication.Credentials credentials = this.authentication.credentials(this.endpoint);
        LinkedHashMap<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        if (this.scope != null) {
            form.put("scope", this.scope);
        }
        form.putAll(credentials.parameters());
        LinkedHashMap<String, String> headers = new LinkedHashMap<>(credentials.headers());
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Accept", "application/json");
        Response response = this.transport.post(this.endpoint, encode(form), headers);
        if (response.status() != 200) {
            throw new IOException("the token endpoint answered HTTP " + response.status() + " for client '" + this.clientId
                    + "'" + errorOf(response.body()));
        }
        Map<String, Object> json;
        try {
            json = JsonUtil.parseJson(response.body());
        } catch (Exception e) {
            throw new IOException("the token endpoint's answer is not JSON");
        }
        Object accessToken = json.get("access_token");
        Object type = json.get("token_type");
        if (!(accessToken instanceof String) || ((String) accessToken).isBlank()) {
            throw new IOException("the token endpoint's answer has no access_token");
        }
        // RFC 6749 §7.1: the client "MUST NOT use an access token if it does not understand the token type"; RFC 6750
        // §6.1.1 registers "Bearer", and RFC 6749 §5.1 on token_type: "Value is case insensitive".
        if (!(type instanceof String) || !"bearer".equals(((String) type).toLowerCase(Locale.ROOT))) {
            throw new IOException("the token endpoint issued a token of type " + type + ", not Bearer");
        }
        Object expiresIn = json.get("expires_in");
        long lifetime = expiresIn instanceof Number ? ((Number) expiresIn).longValue() : -1;
        this.refreshAt = lifetime < 0 ? Long.MAX_VALUE : now + lifetime - Math.min(REFRESH_BEFORE_SECONDS, lifetime / 10);
        this.token = (String) accessToken;
        return this.token;
    }

    @Override
    public synchronized void rejected(String rejected) {
        if (rejected != null && rejected.equals(this.token)) {
            this.token = null;
        }
    }

    /** The {@code error} of an OAuth error answer, as {@code " (error)"}, or nothing. */
    private static String errorOf(String body) {
        try {
            Object error = JsonUtil.parseJson(body).get("error");
            return error instanceof String ? " (" + error + ")" : "";
        } catch (Exception e) {
            return "";
        }
    }

    private static String encode(Map<String, String> form) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    /**
     * RFC 7523 §3's assertion for {@code private_key_jwt}: {@code iss} and {@code sub} the client id, {@code aud} the
     * token endpoint, a {@code jti}, {@code iat} and an {@code exp} {@value #ASSERTION_SECONDS} seconds on, signed by
     * {@code jwk}, a private JWK.
     *
     * @throws IllegalArgumentException when {@code jwk} is not a private RSA, EC or OKP key
     */
    static ClientAuthentication privateKeyJwt(String clientId, String jwk, Clock clock) {
        PublicJsonWebKey key = privateKey(jwk);
        String alg = algorithmOf(key);
        return ClientAuthentication.privateKeyJwt(endpoint -> {
            try {
                JwtClaims claims = new JwtClaims();
                long now = clock.instant().getEpochSecond();
                claims.setIssuer(clientId);
                claims.setSubject(clientId);
                claims.setAudience(endpoint.toString());
                claims.setJwtId(UUID.randomUUID().toString());
                claims.setClaim("iat", now);
                claims.setClaim("exp", now + ASSERTION_SECONDS);
                JsonWebSignature jws = new JsonWebSignature();
                jws.setPayload(claims.toJson());
                jws.setAlgorithmHeaderValue(alg);
                if (key.getKeyId() != null) {
                    jws.setKeyIdHeaderValue(key.getKeyId());
                }
                jws.setKey(key.getPrivateKey());
                return jws.getCompactSerialization();
            } catch (Exception e) {
                throw new IllegalStateException("the client assertion could not be signed: " + e.getMessage(), e);
            }
        });
    }

    /** {@code jwk} as a private key, refused with a message that never repeats it. */
    static PublicJsonWebKey privateKey(String jwk) {
        JsonWebKey parsed;
        try {
            parsed = JsonWebKey.Factory.newJwk(jwk);
        } catch (Exception e) {
            throw new IllegalArgumentException("the receiver's client key is not a JWK");
        }
        if (!(parsed instanceof PublicJsonWebKey) || ((PublicJsonWebKey) parsed).getPrivateKey() == null) {
            throw new IllegalArgumentException("the receiver's client key is not a private RSA, EC or OKP JWK");
        }
        return (PublicJsonWebKey) parsed;
    }

    /** The key's own {@code alg}, or the one its type implies. */
    static String algorithmOf(PublicJsonWebKey key) {
        if (key.getAlgorithm() != null) {
            return key.getAlgorithm();
        }
        if (key instanceof RsaJsonWebKey) {
            return AlgorithmIdentifiers.RSA_USING_SHA256;
        }
        if (key instanceof OctetKeyPairJsonWebKey) {
            return AlgorithmIdentifiers.EDDSA;
        }
        String curve = ((EllipticCurveJsonWebKey) key).getCurveName();
        if (EllipticCurves.P384.equals(EllipticCurves.getSpec(curve))) {
            return AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;
        }
        if (EllipticCurves.P521.equals(EllipticCurves.getSpec(curve))) {
            return AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;
        }
        return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
    }

    /** How long the token request may take, connect and answer; S-5d moves this client onto platform.http. */
    static final Duration TIMEOUT = Duration.ofSeconds(10);

    /**
     * Runtime transport: a form POST with the receiver's TLS switch ({@code OIDF_SSF_RECEIVER_INSECURE_TLS}, through
     * platform's {@link InsecureTls}; the host name is still checked).
     */
    public static TokenTransport httpTransport(boolean insecureTls) {
        HttpClient http = InsecureTls.trustAnyCertificate(HttpClient.newBuilder().connectTimeout(TIMEOUT),
                PollReceiverClient.RECEIVER_INSECURE_TLS, insecureTls).build();
        return (endpoint, formBody, headers) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(endpoint).timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(formBody));
            headers.forEach(b::header);
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new Response(resp.statusCode(), resp.body());
        };
    }
}
