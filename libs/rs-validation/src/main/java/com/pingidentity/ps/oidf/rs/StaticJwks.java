/*
 * A fixed set of authorisation server keys.
 */
package com.pingidentity.ps.oidf.rs;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

/**
 * A {@link JwksSource} over keys the embedding application already holds - a pinned JWKS, or a test's keys.
 * Only public keys that carry a {@code kid} and are for signing (no {@code use}, or {@code use} {@code sig}) are
 * kept; a key with private parameters is refused, because a resource server has no business holding the
 * authorisation server's private key.
 */
public final class StaticJwks implements JwksSource {
    private final Map<String, List<PublicJsonWebKey>> byKid;

    public StaticJwks(Collection<? extends JsonWebKey> keys) {
        this.byKid = index(keys);
    }

    @Override
    public List<PublicJsonWebKey> keys(String kid) {
        return this.byKid.getOrDefault(kid, List.of());
    }

    /**
     * The signing keys among {@code keys}, by {@code kid}.
     *
     * @throws IllegalArgumentException for a key that carries private parameters
     */
    static Map<String, List<PublicJsonWebKey>> index(Collection<? extends JsonWebKey> keys) {
        Map<String, List<PublicJsonWebKey>> out = new java.util.HashMap<>();
        for (JsonWebKey key : keys) {
            if (!(key instanceof PublicJsonWebKey pub) || key.getKeyId() == null || key.getKeyId().isEmpty()) {
                continue;
            }
            if (pub.getPrivateKey() != null) {
                throw new IllegalArgumentException("the authorisation server key " + key.getKeyId()
                        + " carries its private key; a resource server is given public keys only");
            }
            if (key.getUse() != null && !"sig".equals(key.getUse())) {
                continue;
            }
            out.computeIfAbsent(key.getKeyId(), k -> new ArrayList<>()).add(pub);
        }
        out.replaceAll((kid, list) -> List.copyOf(list));
        return Map.copyOf(out);
    }
}
