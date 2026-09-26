/*
 * What this entity's federation endpoints need of its Trust Mark Issuer.
 */
package com.pingidentity.ps.oidf.federation;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;

/**
 * The decisions behind the Trust Mark endpoints (OpenID Federation 1.0 §8.4-§8.6) and the marks this entity
 * publishes, apart from signing - which {@link FederationService} does with its Federation Entity Key.
 * {@code com.pingidentity.ps.oidf.trustmark.TrustMarkIssuer} implements it over the grants the operator gives.
 */
public interface TrustMarkIssuing {

    /** A mark that may be issued now: its claims, and when the grant it is issued under was given. */
    record Mintable(JwtClaims claims, Instant grantedAt) {
    }

    /** The types this entity issues, in the order they were configured; empty when it issues none. */
    Set<String> types();

    /** The claims of a new mark of {@code type} for {@code subject} from {@code issuerId}, when one may be issued now. */
    Optional<Mintable> mintable(String issuerId, String type, String subject);

    /** The entities holding a mark of {@code type} now (§8.5); only {@code subject}, if it holds one, when given. */
    List<String> marked(String type, String subject);

    /** Whether {@code subject} holds a mark of {@code type} now, or of any type when {@code type} is null (§8.2.1). */
    boolean isMarked(String subject, String type);

    /**
     * The §8.4.2 status of a mark whose signature and {@code typ} are already known to be this entity's:
     * {@code active}, {@code expired} or {@code revoked}; empty when there is nothing it was issued under.
     */
    Optional<String> status(JwtClaims mark);
}
