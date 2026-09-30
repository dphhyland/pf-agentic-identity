/*
 * The longest lifetime the attester gives an attestation it issues.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * The cap on a client's {@code attestation_issued_ttl} (plan item S4c: "Issuer TTL cap: 3600 s in production,
 * 64800 s hard maximum").
 *
 * <ul>
 *   <li>{@code OIDF_ATTESTER_MAX_ISSUED_TTL} sets the cap, in seconds: default {@value #DEFAULT_SECONDS}, from
 *       {@value #MIN_SECONDS} to {@value #HARD_MAX_SECONDS}. A value that is not a whole number in that range is
 *       refused in either profile, and every issuance answers 500 naming the variable.</li>
 *   <li>A client whose TTL is above the cap is refused at config parse in production ({@code invalid_client},
 *       naming the property and never its value), and clamped to the cap with a WARN in development.</li>
 *   <li>Above {@value #HARD_MAX_SECONDS} is refused in both profiles. The AI Agent Profile §5, item 1: "An issued
 *       Client Attestation's {@code exp} SHALL NOT exceed {@code iat} + 18 hours." A development rig clamped past
 *       it would mint attestations no conformant verifier accepts, so there is no escape from it.</li>
 * </ul>
 *
 * <p>The lifetime the attester issues is still never past the evidence ({@link EvidencePolicy#effectiveTtlSeconds});
 * this cap bounds the client's own setting before that rule shortens it further.
 */
public final class IssuedTtlCap {
    private static final Log LOGGER = LogFactory.getLog(IssuedTtlCap.class);

    public static final String ENV = "OIDF_ATTESTER_MAX_ISSUED_TTL";
    public static final String PROPERTY = "oidf.attester.max.issued.ttl";
    public static final long DEFAULT_SECONDS = 3600L;
    public static final long MIN_SECONDS = 60L;
    /** 18 hours: the AI Agent Profile §5(1) ceiling on {@code exp - iat}. */
    public static final long HARD_MAX_SECONDS = 64800L;

    /** Client TTLs already warned about in development, by issuer and TTL; bounded so a bad fleet cannot grow it. */
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();
    private static final int MAX_WARNED = 256;

    private final long capSeconds;
    private final boolean production;

    /**
     * @throws IllegalArgumentException if {@code capSeconds} is outside {@value #MIN_SECONDS} to
     *                                  {@value #HARD_MAX_SECONDS}
     */
    public IssuedTtlCap(long capSeconds, boolean production) {
        if (capSeconds < MIN_SECONDS || capSeconds > HARD_MAX_SECONDS) {
            throw new IllegalArgumentException(ENV + " must be a whole number of seconds from " + MIN_SECONDS + " to "
                    + HARD_MAX_SECONDS);
        }
        this.capSeconds = capSeconds;
        this.production = production;
    }

    /** The cap this process is configured with: the system property, then the environment variable, then 3600 s. */
    public static IssuedTtlCap fromEnvironment() {
        return fromEnvironment(System::getProperty, System::getenv);
    }

    /**
     * @throws IllegalArgumentException naming {@value #ENV} when its value is not a whole number from
     *                                  {@value #MIN_SECONDS} to {@value #HARD_MAX_SECONDS}
     */
    public static IssuedTtlCap fromEnvironment(Function<String, String> props, Function<String, String> env) {
        long cap = DEFAULT_SECONDS;
        String raw = firstSet(props.apply(PROPERTY), env.apply(ENV));
        if (raw != null) {
            try {
                cap = Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(ENV + " must be a whole number of seconds from " + MIN_SECONDS
                        + " to " + HARD_MAX_SECONDS, e);
            }
        }
        return new IssuedTtlCap(cap, DeploymentProfile.of(env).isProduction());
    }

    public long capSeconds() {
        return this.capSeconds;
    }

    public boolean production() {
        return this.production;
    }

    /**
     * The TTL a client configured with {@code ttlSeconds} is issued with.
     *
     * @param issuer     the client's {@code attestation_issuer}, for the development WARN
     * @param ttlSeconds the client's {@code attestation_issued_ttl}, already known to be positive
     * @throws IssuanceException {@code invalid_client} naming {@code attestation_issued_ttl} when the TTL is above
     *                           {@value #HARD_MAX_SECONDS}, or above the cap in production
     */
    public long apply(String issuer, long ttlSeconds) throws IssuanceException {
        if (ttlSeconds > HARD_MAX_SECONDS) {
            throw IssuanceException.invalidClient(AttestationIssuanceConfig.P_TTL + " is above " + HARD_MAX_SECONDS
                    + " s, the AI Agent Profile's 18-hour ceiling on an attestation's lifetime");
        }
        if (ttlSeconds <= this.capSeconds) {
            return ttlSeconds;
        }
        if (this.production) {
            throw IssuanceException.invalidClient(AttestationIssuanceConfig.P_TTL + " is above the longest lifetime "
                    + "this attester issues (" + ENV + ")");
        }
        String key = issuer + " " + ttlSeconds;
        if (WARNED.size() < MAX_WARNED && WARNED.add(key)) {
            LOGGER.warn((Object) ("Client with " + AttestationIssuanceConfig.P_ISSUER + "=" + issuer + " sets "
                    + AttestationIssuanceConfig.P_TTL + "=" + ttlSeconds + ", above " + ENV + "=" + this.capSeconds
                    + "; issuing for " + this.capSeconds + " s. The development profile clamps it; production refuses"
                    + " the client"));
        }
        return this.capSeconds;
    }

    private static String firstSet(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        if (b != null && !b.isBlank()) {
            return b.trim();
        }
        return null;
    }
}
