/*
 * Verifies inbound Security Event Tokens against a transmitter's JWKS (receiver side).
 */
package com.pingidentity.ps.oidf.ssf;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;

/**
 * Receiver-side SET verification: checks an inbound compact JWS is a well-formed RFC 8417 SET
 * ({@code typ: secevent+jwt}), signed by the expected transmitter (signature against its JWKS, matching
 * {@code kid} when present), and addressed to us ({@code iss} equals the expected issuer; {@code aud}
 * contains the expected audience when one is configured). Returns a parsed {@link ReceivedSet}.
 *
 * <p>Keys come from a {@link JwksSource}: the runtime uses {@link #httpJwksSource} (fetch + cache with a
 * refresh on unknown {@code kid} — the standard rotation pattern); tests inject keys directly. Failures
 * throw {@link SetVerificationException} carrying the RFC 8935 error code the push endpoint must return
 * ({@code invalid_request} / {@code invalid_key} / {@code invalid_issuer} / {@code invalid_audience}).
 */
public final class SetVerifier {

    /** Supplies the transmitter's current signing keys; {@code refresh} forces a re-fetch (key rotation). */
    public interface JwksSource {
        List<JsonWebKey> keys(boolean refresh) throws Exception;
    }

    /** A verification failure, carrying the RFC 8935 {@code err} code for the push response. */
    public static final class SetVerificationException extends Exception {
        private static final long serialVersionUID = 1L;
        private final String errorCode;

        public SetVerificationException(String errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return this.errorCode;
        }
    }

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JwksSource jwksSource;

    public SetVerifier(String expectedIssuer, String expectedAudience, JwksSource jwksSource) {
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
        this.expectedAudience = expectedAudience;
        this.jwksSource = Objects.requireNonNull(jwksSource, "jwksSource");
    }

    /** Verify and parse an inbound SET. */
    public ReceivedSet verify(String compactJws) throws SetVerificationException {
        JsonWebSignature jws = new JsonWebSignature();
        Map<String, Object> claims;
        try {
            jws.setCompactSerialization(compactJws);
        } catch (Exception e) {
            throw new SetVerificationException("invalid_request", "not a compact JWS: " + e.getMessage());
        }
        String typ = jws.getHeader("typ");
        if (typ == null || !typ.toLowerCase().contains("secevent")) {
            throw new SetVerificationException("invalid_request", "typ is not secevent+jwt: " + typ);
        }
        if (!signatureVerifies(jws, false) && !signatureVerifies(jws, true)) {
            throw new SetVerificationException("invalid_key", "SET signature does not verify against the transmitter JWKS");
        }
        try {
            claims = JsonUtil.parseJson(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw new SetVerificationException("invalid_request", "SET payload is not JSON");
        }

        Object iss = claims.get("iss");
        if (!this.expectedIssuer.equals(iss)) {
            throw new SetVerificationException("invalid_issuer", "unexpected iss: " + iss);
        }
        if (this.expectedAudience != null && !audMatches(claims.get("aud"))) {
            throw new SetVerificationException("invalid_audience", "aud does not include " + this.expectedAudience);
        }
        Object jti = claims.get("jti");
        Object events = claims.get("events");
        if (!(jti instanceof String) || ((String) jti).isBlank() || !(events instanceof Map)) {
            throw new SetVerificationException("invalid_request", "SET missing jti or events");
        }

        SubjectId subject = null;
        Object subId = claims.get("sub_id");
        if (subId instanceof Map) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> subMap = (Map<String, Object>) subId;
                subject = SubjectId.fromMap(subMap);
            } catch (IllegalArgumentException e) {
                throw new SetVerificationException("invalid_request", "unparseable sub_id: " + e.getMessage());
            }
        }
        long iat = claims.get("iat") instanceof Number ? ((Number) claims.get("iat")).longValue() : 0L;
        @SuppressWarnings("unchecked")
        Map<String, Object> eventsMap = (Map<String, Object>) events;
        return new ReceivedSet((String) iss, (String) jti, iat, subject, eventsMap, compactJws);
    }

    private boolean signatureVerifies(JsonWebSignature jws, boolean refresh) {
        List<JsonWebKey> keys;
        try {
            keys = this.jwksSource.keys(refresh);
        } catch (Exception e) {
            return false;
        }
        String kid = jws.getKeyIdHeaderValue();
        for (JsonWebKey key : keys) {
            if (kid != null && key.getKeyId() != null && !kid.equals(key.getKeyId())) {
                continue;
            }
            try {
                jws.setKey(key.getKey());
                if (jws.verifySignature()) {
                    return true;
                }
            } catch (Exception ignored) {
                // try the next key
            }
        }
        return false;
    }

    private boolean audMatches(Object aud) {
        if (aud instanceof String) {
            return this.expectedAudience.equals(aud);
        }
        if (aud instanceof Iterable) {
            for (Object a : (Iterable<?>) aud) {
                if (this.expectedAudience.equals(a)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Runtime {@link JwksSource}: fetch the JWKS URL, cache for {@code cacheTtlSeconds}, re-fetch on demand. */
    public static JwksSource httpJwksSource(String jwksUrl, long cacheTtlSeconds, boolean insecureTls) {
        HttpClient http = insecureTls ? trustAllClient() : HttpClient.newHttpClient();
        return new JwksSource() {
            private volatile List<JsonWebKey> cached;
            private volatile long fetchedAt;

            @Override
            public synchronized List<JsonWebKey> keys(boolean refresh) throws Exception {
                long now = System.currentTimeMillis() / 1000L;
                if (!refresh && this.cached != null && now - this.fetchedAt < cacheTtlSeconds) {
                    return this.cached;
                }
                HttpResponse<String> resp = http.send(
                        HttpRequest.newBuilder(URI.create(jwksUrl)).header("Accept", "application/json").GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    throw new IllegalStateException("JWKS fetch returned HTTP " + resp.statusCode());
                }
                this.cached = new JsonWebKeySet(resp.body()).getJsonWebKeys();
                this.fetchedAt = now;
                return this.cached;
            }
        };
    }

    private static HttpClient trustAllClient() {
        try {
            javax.net.ssl.TrustManager[] trustAll = {new javax.net.ssl.X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
                    // dev trust-all
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
                    // dev trust-all
                }

                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];
                }
            }};
            javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS");
            ssl.init(null, trustAll, new java.security.SecureRandom());
            return HttpClient.newBuilder().sslContext(ssl).build();
        } catch (Exception e) {
            throw new IllegalStateException("failed to build trust-all HTTP client", e);
        }
    }
}
