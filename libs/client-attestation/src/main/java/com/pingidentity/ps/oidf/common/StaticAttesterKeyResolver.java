/*
 * A non-federation AttesterKeyResolver that trusts a statically-configured set of attester keys.
 *
 * DEV / DEMO ONLY. This bypasses OpenID Federation trust-chain validation: it trusts whatever
 * public keys are pre-registered for an attester issuer. Use it to exercise the attestation flow
 * before a trust controller / federation deployment is in place. Production deployments must use
 * {@link FederationAttesterKeyResolver}.
 */
package com.pingidentity.ps.oidf.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.json.JsonUtil;

public final class StaticAttesterKeyResolver implements AttesterKeyResolver {

    private final Map<String, List<JsonWebKey>> trustedKeysByIssuer;

    public StaticAttesterKeyResolver(Map<String, List<JsonWebKey>> trustedKeysByIssuer) {
        this.trustedKeysByIssuer = Map.copyOf(trustedKeysByIssuer);
    }

    @Override
    public List<JsonWebKey> resolve(String attesterIssuer, List<String> trustChainHeader) throws Exception {
        List<JsonWebKey> keys = this.trustedKeysByIssuer.get(attesterIssuer);
        if (keys == null || keys.isEmpty()) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_CLIENT,
                    "No statically-trusted attester keys registered for issuer: " + attesterIssuer);
        }
        return keys;
    }

    /**
     * Loads a mock-attester trust file: a JSON object mapping each attester {@code iss} (entity id)
     * to a JWKS object, e.g.
     * <pre>{ "https://attester.example.com": { "keys": [ { "kty":"EC", ... } ] } }</pre>
     */
    @SuppressWarnings("unchecked")
    public static StaticAttesterKeyResolver fromFile(Path file) throws IOException {
        String json = Files.readString(file);
        java.util.HashMap<String, List<JsonWebKey>> byIssuer = new java.util.HashMap<>();
        try {
            Map<String, Object> root = JsonUtil.parseJson(json);
            for (Map.Entry<String, Object> e : root.entrySet()) {
                List<JsonWebKey> keys = new JsonWebKeySet(JsonUtil.toJson((Map<String, Object>) e.getValue())).getJsonWebKeys();
                byIssuer.put(e.getKey(), keys);
            }
        } catch (Exception ex) {
            throw new IOException("Invalid mock-attesters JWKS file " + file, ex);
        }
        return new StaticAttesterKeyResolver(byIssuer);
    }
}
