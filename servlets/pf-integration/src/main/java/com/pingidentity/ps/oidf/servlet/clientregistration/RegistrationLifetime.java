/*
 * How long a federation registration lives.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * OpenID Federation 1.0 §12.3: "The validity of an Automatic or Explicit Registration at an OP MUST NOT
 * exceed the lifetime of the Trust Chain the OP used to create the registration." A registration ends at
 * the earlier of its chain's expiry (§10.4) and the deployment's maximum; one that would end sooner than
 * the minimum is refused rather than created to expire at once.
 */
final class RegistrationLifetime {
    private final RegistrationSettings settings;
    private final Clock clock;

    RegistrationLifetime(RegistrationSettings settings, Clock clock) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    RegistrationSettings settings() {
        return this.settings;
    }

    long now() {
        return this.clock.instant().getEpochSecond();
    }

    /**
     * When a registration from this chain ends, in epoch seconds.
     *
     * @throws RegistrationRejectedException {@code invalid_trust_chain} when that is sooner than the minimum
     */
    long expiresAt(TrustChainValidationResult validation) throws RegistrationRejectedException {
        long now = this.now();
        long chainExpiry = validation.expEpochSeconds() < 0 ? Long.MAX_VALUE : validation.expEpochSeconds();
        long expires = Math.min(chainExpiry, now + this.settings.maxTtlSeconds());
        if (expires - now < this.settings.minTtlSeconds()) {
            throw new RegistrationRejectedException(400, "invalid_trust_chain", "the trust chain expires in " + (expires - now)
                    + "s, sooner than the " + this.settings.minTtlSeconds() + "s a registration needs", RegistrationRejectedException.Kind.TRUST, null);
        }
        return expires;
    }

    /** The expiry stored on a client, or empty for one registered before expiries were recorded. */
    static OptionalLong storedExpiry(Client client) {
        Map<String, ParamValues> params = client.getExtendedParams();
        ParamValues values = params == null ? null : params.get(FederationClientParams.EXPIRES_AT);
        List<String> elements = values == null ? null : values.getElements();
        if (elements == null || elements.isEmpty()) {
            return OptionalLong.empty();
        }
        try {
            return OptionalLong.of(Long.parseLong(elements.get(0).trim()));
        } catch (NumberFormatException e) {
            return OptionalLong.empty();
        }
    }

    /** Expired - including a client with no recorded expiry, whose chain nothing has checked against §12.3. */
    boolean isExpired(OptionalLong expiresAt) {
        return expiresAt.isEmpty() || this.now() >= expiresAt.getAsLong();
    }

    /** Close enough to expiry to renew now, while a failure still leaves time to retry. */
    boolean isDueForRenewal(OptionalLong expiresAt) {
        return this.isExpired(expiresAt) || this.now() >= expiresAt.getAsLong() - this.settings.refreshBeforeExpirySeconds();
    }
}
