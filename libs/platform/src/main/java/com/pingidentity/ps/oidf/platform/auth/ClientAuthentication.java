/*
 * How an introspecting resource authenticates to the introspection endpoint.
 */
package com.pingidentity.ps.oidf.platform.auth;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * The resource's credentials for one introspection call. RFC 7662 §2.1: "To prevent token scanning attacks, the
 * endpoint MUST also require some form of authorization to access this endpoint". Which form is the caller's: platform
 * knows no client and holds no key. {@link #clientSecretBasic} and {@link #privateKeyJwt} are the two this repository
 * uses.
 */
@FunctionalInterface
public interface ClientAuthentication {

    /** The headers and form parameters one call carries. */
    record Credentials(Map<String, String> headers, Map<String, String> parameters) {
        public Credentials {
            headers = Map.copyOf(headers);
            parameters = Map.copyOf(parameters);
        }
    }

    /**
     * The credentials for one call to {@code endpoint}.
     *
     * @throws IOException when they cannot be made (a signing key that cannot be reached); the call is then refused
     *                     as unavailable
     */
    Credentials credentials(URI endpoint) throws IOException;

    /**
     * RFC 6749 §2.3.1 {@code client_secret_basic}: "The client identifier is encoded using the
     * "application/x-www-form-urlencoded" encoding algorithm per Appendix B, and the encoded value is used as the
     * username; the client password is encoded using the same algorithm and used as the password."
     *
     * @param secret read at each call - {@code settings.secret(...)::reveal} - so the secret is never held here
     */
    static ClientAuthentication clientSecretBasic(String clientId, Supplier<String> secret) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(secret, "secret");
        return endpoint -> {
            String pair = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                    + URLEncoder.encode(Objects.requireNonNull(secret.get(), "secret"), StandardCharsets.UTF_8);
            return new Credentials(Map.of("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8))), Map.of());
        };
    }

    /**
     * RFC 7523 §2.2 {@code private_key_jwt}: {@code client_assertion_type}
     * {@code urn:ietf:params:oauth:client-assertion-type:jwt-bearer} and a fresh {@code client_assertion} for each
     * call, which {@code assertion} signs for the endpoint it is given.
     */
    static ClientAuthentication privateKeyJwt(Function<URI, String> assertion) {
        Objects.requireNonNull(assertion, "assertion");
        return endpoint -> new Credentials(Map.of(), Map.of(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion", Objects.requireNonNull(assertion.apply(endpoint), "client_assertion")));
    }
}
