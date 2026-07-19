/*
 * Receiver authenticator backed by PingFederate's RFC 7662 token introspection endpoint.
 */
package com.pingidentity.ps.oidf.ssf;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.json.JsonUtil;

/**
 * Validates a receiver's bearer token by calling PingFederate's OAuth 2.0 token introspection endpoint
 * (RFC 7662) — the token was issued by PF itself, so PF is the authority on whether it is active and which
 * scopes it carries. The introspection HTTP call is behind the {@link IntrospectionClient} seam so the
 * response-parsing logic can be unit-tested without a live PF.
 *
 * <p>Introspection is a confidential-client call: the module authenticates to the endpoint with its own
 * client id/secret (HTTP Basic). Configure the endpoint (default {@code <issuer>/as/introspect.oauth2}) and
 * credentials via {@link SsfConfiguration}.
 */
public final class PfIntrospectionReceiverAuthenticator implements ReceiverAuthenticator {

    /** The introspection HTTP call, isolated for testing: token -> parsed RFC 7662 response object. */
    public interface IntrospectionClient {
        Map<String, Object> introspect(String token) throws Exception;
    }

    private final IntrospectionClient client;

    public PfIntrospectionReceiverAuthenticator(IntrospectionClient client) {
        this.client = Objects.requireNonNull(client, "client");
    }

    /** Runtime factory: a JDK-HttpClient introspection call with HTTP Basic client authentication. */
    public static PfIntrospectionReceiverAuthenticator forEndpoint(String endpoint, String clientId,
                                                                   String clientSecret, boolean trustAllTls) {
        Objects.requireNonNull(endpoint, "introspection endpoint");
        String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        HttpClient http = trustAllTls ? trustAllClient() : HttpClient.newHttpClient();
        IntrospectionClient jdk = token -> {
            String form = "token=" + java.net.URLEncoder.encode(token, StandardCharsets.UTF_8)
                    + "&token_type_hint=access_token";
            HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + basic)
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new ReceiverAuthException("introspection returned HTTP " + resp.statusCode());
            }
            return JsonUtil.parseJson(resp.body());
        };
        return new PfIntrospectionReceiverAuthenticator(jdk);
    }

    @Override
    public AuthContext authenticate(String bearerToken) throws ReceiverAuthException {
        Map<String, Object> resp;
        try {
            resp = this.client.introspect(bearerToken);
        } catch (ReceiverAuthException e) {
            throw e;
        } catch (Exception e) {
            throw new ReceiverAuthException("token introspection failed", e);
        }
        Object active = resp == null ? null : resp.get("active");
        if (!(active instanceof Boolean) || !((Boolean) active)) {
            return AuthContext.inactive();
        }
        String clientId = asString(resp.get("client_id"));
        return AuthContext.active(clientId, parseScopes(resp.get("scope")));
    }

    /** Accept-any-cert HTTP client for dev PF instances serving self-signed TLS ({@code introspectionInsecureTls}). */
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

    /** RFC 7662 {@code scope} is a space-delimited string; some ATMs emit a JSON array — accept both. */
    private static Set<String> parseScopes(Object scope) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (scope instanceof String && !((String) scope).isBlank()) {
            out.addAll(Arrays.asList(((String) scope).trim().split("\\s+")));
        } else if (scope instanceof Iterable) {
            for (Object s : (Iterable<?>) scope) {
                if (s != null) {
                    out.add(s.toString());
                }
            }
        }
        return out;
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }
}
