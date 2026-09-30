/*
 * Each client's attestation policy, shared by the token-endpoint filter and the OGNL criterion.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Each client's attestation policy (plan item S4c): its {@code attestation_*} extended properties, read from
 * PingFederate's client manager and parsed by {@link ClientAttestationPolicy}, which applies them to the server's
 * policy so that they can only tighten it. {@code ClientAttestationAuthFilter} and the OGNL criterion
 * ({@link ClientAttestationUtils#validateClientAttestation(Object)}) both ask it, so the two routes hold a client to the
 * same policy (F-0009).
 *
 * <p>A client's policy is kept for {@link #TTL} after it is read, for at most {@link #MAX_ENTRIES} clients, the least
 * recently used going first; a client PingFederate does not have is kept as well, so an unknown id cannot make every
 * request a lookup. The lookup is {@code ClientManager.getClient}: a synchronised map lookup on PingFederate's XML client
 * store, which reloads from the store for an id it does not hold, and a SQL query per call on a JDBC one (13.1.3,
 * javap, 2026-09-30). A change an administrator makes to a client is seen within {@link #TTL}; nothing in PingFederate
 * tells this class of one. A lookup that fails is not kept, and is {@link Unavailable}: the request is answered 503,
 * never as though the client had no policy.
 *
 * <p>Statics are per loader: the webapp's filter and the engine's criterion each hold their own copy.
 */
public final class AttestationPolicyResolver {
    private static final Log LOGGER = LogFactory.getLog(AttestationPolicyResolver.class);

    /** How long a client's policy is kept after it is read. */
    public static final Duration TTL = Duration.ofSeconds(30);
    /** How many clients' policies are kept. */
    public static final int MAX_ENTRIES = 10_000;

    /** A client's extended properties, name to values, or null when PingFederate has no such client. */
    @FunctionalInterface
    public interface ClientSource {
        Map<String, List<String>> properties(String clientId) throws Exception;
    }

    /** The client manager could not answer: the request is answered 503 {@code temporarily_unavailable}. */
    public static final class Unavailable extends Exception {
        private static final long serialVersionUID = 1L;

        Unavailable(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record Cached(ClientAttestationPolicy policy, Instant expires) {
    }

    private static final AttestationPolicyResolver SHARED = new AttestationPolicyResolver(
            AttestationPolicyResolver.from(new PfMgmtClientStore()), Clock.systemUTC(),
            () -> DeploymentProfile.current().isDevelopment());

    private final ClientSource source;
    private final Clock clock;
    private final BooleanSupplier development;
    private final LinkedHashMap<String, Cached> cache = new LinkedHashMap<>(64, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
            return this.size() > MAX_ENTRIES;
        }
    };

    AttestationPolicyResolver(ClientSource source, Clock clock, BooleanSupplier development) {
        this.source = source;
        this.clock = clock;
        this.development = development;
    }

    /** This loader's resolver, over PingFederate's client manager. */
    public static AttestationPolicyResolver shared() {
        return SHARED;
    }

    /** A resolver over {@code source}, for a test or a caller with its own client store. */
    public static AttestationPolicyResolver over(ClientSource source, Clock clock, BooleanSupplier development) {
        return new AttestationPolicyResolver(source, clock, development);
    }

    /**
     * {@code clientId}'s policy: from the cache while it is fresh, otherwise read now. A blank id names no client and has
     * the server's policy.
     *
     * @throws Unavailable when the client manager cannot answer
     */
    public ClientAttestationPolicy policy(String clientId) throws Unavailable {
        if (clientId == null || clientId.isBlank()) {
            return ClientAttestationPolicy.unknown(clientId);
        }
        Instant now = this.clock.instant();
        synchronized (this.cache) {
            Cached cached = this.cache.get(clientId);
            if (cached != null && now.isBefore(cached.expires())) {
                return cached.policy();
            }
        }
        Map<String, List<String>> properties;
        try {
            properties = this.source.properties(clientId);
        } catch (Exception | LinkageError | java.util.ServiceConfigurationError e) {
            throw new Unavailable("the client manager could not be asked for client " + clientId + " ("
                    + e.getClass().getSimpleName() + ")", e);
        }
        ClientAttestationPolicy policy = this.parse(clientId, properties);
        synchronized (this.cache) {
            this.cache.put(clientId, new Cached(policy, now.plus(TTL)));
        }
        return policy;
    }

    /** {@code properties} parsed for {@code clientId}; null properties are a client PingFederate does not have. */
    ClientAttestationPolicy parse(String clientId, Map<String, List<String>> properties) {
        if (properties == null) {
            return ClientAttestationPolicy.unknown(clientId);
        }
        return ClientAttestationPolicy.parse(clientId, properties, this.development.getAsBoolean(),
                warning -> LOGGER.warn((Object) ("attestation policy: " + warning)));
    }

    /** Forgets {@code clientId}'s policy, so the next request reads it again. */
    public void invalidate(String clientId) {
        synchronized (this.cache) {
            this.cache.remove(clientId);
        }
    }

    /** Forgets every client's policy. */
    public void invalidateAll() {
        synchronized (this.cache) {
            this.cache.clear();
        }
    }

    /** How many clients' policies are kept now. */
    int cached() {
        synchronized (this.cache) {
            return this.cache.size();
        }
    }

    /** A client source over a {@link ClientStore}: each client's extended properties, name to values. */
    public static ClientSource from(ClientStore store) {
        return clientId -> {
            Client client = store.get(clientId);
            return client == null ? null : AttestationPolicyResolver.properties(client);
        };
    }

    /** {@code client}'s extended properties, name to values; an absent or empty map is none. */
    static Map<String, List<String>> properties(Client client) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        Map<String, ParamValues> params = client.getExtendedParams();
        if (params == null) {
            return out;
        }
        for (Map.Entry<String, ParamValues> e : params.entrySet()) {
            List<String> values = e.getValue() == null || e.getValue().getElements() == null
                    ? List.of() : new ArrayList<>(e.getValue().getElements());
            out.put(e.getKey(), values);
        }
        return out;
    }

    /**
     * The SHA-256, lower-case hex, of the effective policy: every member of {@code config} the verifier reads, sets
     * sorted. The filter publishes it with the verified attestation, and the criterion, which reuses that
     * verification, computes it again from the policy it resolves for the client and refuses a different one.
     */
    public static String fingerprint(ClientAttestationConfig config) {
        StringBuilder s = new StringBuilder("attestation-policy/1");
        s.append("\natt=").append(new TreeSet<>(config.attestationAlgorithms()));
        s.append("\npop=").append(new TreeSet<>(config.popAlgorithms()));
        s.append("\ndpop=").append(new TreeSet<>(config.dpopAlgorithms()));
        s.append("\nskew=").append(config.allowedClockSkewSeconds());
        s.append("\npopMaxAge=").append(config.popMaxAgeSeconds());
        s.append("\ndpopMaxAge=").append(config.dpopMaxAgeSeconds());
        s.append("\naud=").append(config.expectedAudience());
        s.append("\nhtu=").append(config.expectedHtu());
        s.append("\nhtm=").append(config.expectedHtm());
        s.append("\nchallenge=").append(config.challengeRequired());
        s.append("\nclaims=").append(new TreeSet<>(config.requiredDisclosedClaims()));
        s.append("\nmaxLifetime=").append(config.maxAttestationLifetimeSeconds());
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
