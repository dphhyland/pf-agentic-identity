/*
 * One Federation Entity Key this entity no longer signs with.
 */
package com.pingidentity.ps.oidf.keyhistory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A retired Federation Entity Key (OpenID Federation 1.0 §8.7): valid until {@code expiresAt} for what it signed before
 * it was retired, unless it is revoked - which may happen after it expired, when a compromise is found late (§8.7(2)).
 *
 * @param kid       its key id
 * @param publicJwk its public JWK
 * @param issuedAt  when it began to be used, when known
 * @param expiresAt after when nothing it signed is valid
 * @param revokedAt when it was revoked, or must be considered revoked; {@code null} while it is not
 * @param reason    why (§8.7.3); {@code null} when not revoked, or revoked without saying why
 */
public record HistoricalKey(String kid, Map<String, Object> publicJwk, Instant issuedAt, Instant expiresAt, Instant revokedAt, String reason) {
    /** §8.7.3's revocation reasons. */
    public static final Set<String> REASONS = Set.of("unspecified", "compromised", "superseded");

    public HistoricalKey {
        if (kid == null || kid.isBlank()) {
            throw new IllegalArgumentException("a historical key needs its kid");
        }
        publicJwk = Map.copyOf(Objects.requireNonNull(publicJwk, "publicJwk"));
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (reason != null && revokedAt == null) {
            throw new IllegalArgumentException("only a revoked key has a revocation reason");
        }
    }

    /** §8.7.2: the public JWK with its {@code kid}, {@code iat} when known, {@code exp}, and {@code revoked} when revoked. */
    public Map<String, Object> asJwk() {
        Map<String, Object> jwk = new LinkedHashMap<>(this.publicJwk);
        jwk.put("kid", this.kid);
        if (this.issuedAt != null) {
            jwk.put("iat", this.issuedAt.getEpochSecond());
        }
        jwk.put("exp", this.expiresAt.getEpochSecond());
        if (this.revokedAt != null) {
            Map<String, Object> revoked = new LinkedHashMap<>();
            revoked.put("revoked_at", this.revokedAt.getEpochSecond());
            if (this.reason != null) {
                revoked.put("reason", this.reason);
            }
            jwk.put("revoked", revoked);
        }
        return jwk;
    }
}
