package com.pingidentity.ps.oidf.pf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

/**
 * The deployment's {@code attest_jwt_client_auth} bridge key.
 *
 * <p>PingFederate has no native attestation-based client authentication, so a verified attestation is
 * translated into the credential PF does understand: a {@code private_key_jwt} client assertion signed
 * by this one deployment-held key, whose public half sits in every attestation client's JWKS. That
 * makes it the highest-value secret in the system - it can mint an assertion for any client whose JWKS
 * carries it - and it is also the thing whose <em>absence</em> is dangerous: with no bridge key the
 * translating filter passes requests through, and a client registered expecting attestation
 * authentication is then a client with no credential requirement at all.
 *
 * <p>So this is fail-closed by default ({@code OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY}, default true):
 * the filter refuses to start and registration refuses to create an attestation client. Set it false
 * only for an environment that deliberately runs without attestation authentication.
 */
public final class BridgeKey {

    private static volatile Optional<PublicJsonWebKey> cached;
    private static volatile String cachedFrom;

    private BridgeKey() {
    }

    /**
     * The parsed bridge key, empty when none is configured.
     *
     * @throws IllegalStateException when one IS configured but cannot be parsed - a malformed key is a
     *     deployment error, never a reason to quietly fall back to no authentication
     */
    public static Optional<PublicJsonWebKey> load() {
        FederationRuntimeConfig config = FederationRuntimeConfig.get();
        String jwkJson = config.bridgePrivateJwk();
        Optional<PublicJsonWebKey> local = cached;
        if (local != null && java.util.Objects.equals(cachedFrom, jwkJson)) {
            return local;
        }
        synchronized (BridgeKey.class) {
            if (jwkJson == null) {
                cached = Optional.empty();
            } else {
                try {
                    cached = Optional.of(PublicJsonWebKey.Factory.newPublicJwk(jwkJson));
                }
                catch (Exception e) {
                    cached = null;
                    throw new IllegalStateException(FederationRuntimeConfig.BRIDGE_KEY_ENV
                            + " is set but is not a usable private JWK: " + e.getMessage(), e);
                }
            }
            cachedFrom = jwkJson;
            return cached;
        }
    }

    /** True when this deployment insists attestation authentication actually works. */
    public static boolean isRequired() {
        return FederationRuntimeConfig.get().requireBridgeKey();
    }

    /**
     * The key, or a failure explaining what to set. Called where continuing without it would leave a
     * client authenticated by nothing.
     */
    public static PublicJsonWebKey require(String what) {
        Optional<PublicJsonWebKey> key = load();
        if (key.isEmpty()) {
            throw new IllegalStateException(what + " requires the attestation bridge key, but "
                    + FederationRuntimeConfig.BRIDGE_KEY_ENV + " is not set. Generate an EC P-256 private "
                    + "JWK and set it on this deployment, or set "
                    + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV + "=false to run without "
                    + "attestation-based client authentication.");
        }
        return key.get();
    }

    /**
     * The public JWKs a federation-registered attestation client must carry so PF will accept the
     * bridge assertion: the current bridge key, plus a superseded one during a rotation overlap.
     */
    public static List<Map<String, Object>> publicJwksForClients() {
        List<Map<String, Object>> keys = new ArrayList<>();
        load().ifPresent(key -> keys.add(publicParams(key)));
        String previous = FederationRuntimeConfig.get().bridgePreviousPublicJwk();
        if (previous != null) {
            try {
                keys.add(publicParams(PublicJsonWebKey.Factory.newPublicJwk(previous)));
            }
            catch (Exception e) {
                throw new IllegalStateException(FederationRuntimeConfig.BRIDGE_PREVIOUS_PUBLIC_KEY_ENV
                        + " is set but is not a usable public JWK: " + e.getMessage(), e);
            }
        }
        return keys;
    }

    private static Map<String, Object> publicParams(PublicJsonWebKey key) {
        return new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    /** Test seam: drop the memoised key so a test can change the environment. */
    static void resetForTest() {
        cached = null;
        cachedFrom = null;
    }
}
