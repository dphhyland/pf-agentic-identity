/*
 * Process-wide singletons shared between every servlet that reads or writes the hosted-entity registry.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.common.JwsSigner;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link HostedEntityRegistry}, {@link HostedEntitySigner} and
 * {@link HostedEntityConfigurationBuilder} so every servlet that touches hosted entities (the
 * resolution endpoint, and the enrolment API that will follow it) shares the same state.
 *
 * <p>This exists because of a bug this codebase already made once: {@code AttestationSupport}
 * (the equivalent holder for the attestation challenge/replay stores) was added after the challenge
 * servlet and the token-endpoint hook turned out to be loaded by two different classloaders and so held
 * two independent stores — a challenge issued by one was invisible to the other. Any deployment that
 * loads this module's servlets from more than one classloader would hit the identical failure here
 * without a single shared holder to configure explicitly.
 *
 * <p>Lazily initialized to an in-memory registry if nothing configures one first — workable for tests
 * and a single-node demo, wrong for anything meant to host entities durably (see
 * {@link InMemoryHostedEntityRegistry}'s own javadoc).
 */
public final class AuthoritySupport {
    private static final Log LOGGER = LogFactory.getLog(AuthoritySupport.class);
    private static final Object LOCK = new Object();

    private static volatile HostedEntityRegistry registry;
    private static volatile HostedEntitySigner signer;
    private static volatile String authorityEntityId;
    private static volatile HostedEntityConfigurationBuilder configurationBuilder;

    private AuthoritySupport() {
    }

    /**
     * Configures the shared registry against a durable store. Call once, before {@link #registry()} is
     * first used — subsequent calls are ignored with a warning, matching the "first configuration wins,
     * everything after is a caller bug" contract the equivalent attestation holder uses.
     */
    public static void configureJdbcRegistry(DataSource dataSource) {
        synchronized (LOCK) {
            if (registry != null) {
                LOGGER.warn("AuthoritySupport registry already configured; ignoring a second configuration");
                return;
            }
            registry = new JdbcHostedEntityRegistry(Objects.requireNonNull(dataSource, "dataSource"));
        }
    }

    /** Configures the shared signer and the authority's own fixed entity id (never derived per-request). */
    public static void configureSigning(HostedEntitySigner hostedEntitySigner, String configuredAuthorityEntityId) {
        synchronized (LOCK) {
            if (signer != null) {
                LOGGER.warn("AuthoritySupport signer already configured; ignoring a second configuration");
                return;
            }
            signer = Objects.requireNonNull(hostedEntitySigner, "hostedEntitySigner");
            authorityEntityId = com.pingidentity.ps.oidf.common.Claims.requireNonBlank(
                    configuredAuthorityEntityId, "authorityEntityId");
            configurationBuilder = new HostedEntityConfigurationBuilder(signer, authorityEntityId);
        }
    }

    public static HostedEntityRegistry registry() {
        HostedEntityRegistry local = registry;
        if (local == null) {
            synchronized (LOCK) {
                if (registry == null) {
                    LOGGER.warn("DEV MODE: no durable hosted-entity registry configured — "
                            + "using an in-memory registry that will not survive a restart");
                    registry = new InMemoryHostedEntityRegistry();
                }
                local = registry;
            }
        }
        return local;
    }

    public static HostedEntityConfigurationBuilder configurationBuilder() {
        HostedEntityConfigurationBuilder local = configurationBuilder;
        if (local == null) {
            throw new IllegalStateException(
                    "AuthoritySupport.configureSigning(...) must be called before configurationBuilder() — "
                            + "unlike the registry, there is no safe default signer to fall back to");
        }
        return local;
    }

    /** The authority's own fixed entity id, as configured — never derived from a request's Host header. */
    public static String authorityEntityId() {
        String local = authorityEntityId;
        if (local == null) {
            throw new IllegalStateException("AuthoritySupport.configureSigning(...) must be called before authorityEntityId()");
        }
        return local;
    }

    public static HostedEntitySigner hostedEntitySigner() {
        HostedEntitySigner local = signer;
        if (local == null) {
            throw new IllegalStateException("AuthoritySupport.configureSigning(...) must be called before hostedEntitySigner()");
        }
        return local;
    }

    /**
     * The public {@code jwks} (wrapped as {@code {"keys": [...]}}, the shape a subordinate statement's
     * own {@code jwks} claim uses) for a resolvable hosted entity, or {@code null} if {@code subject} is
     * not — or is no longer — one. {@code null} rather than an exception on "not found" is deliberate:
     * this is meant to be wired straight into {@code FederationService}'s subordinate-statement path as
     * a lookup function it falls through past when a subject isn't hosted here at all, and a subject
     * that plainly isn't a hosted entity is the overwhelmingly common case, not an error.
     *
     * @throws IllegalStateException if the registry itself is unavailable, or signing fails — both are
     *                                genuine faults, not "subject not hosted"
     */
    public static Map<String, Object> hostedEntityJwks(String subject) {
        Optional<HostedEntity> found;
        try {
            found = registry().find(subject);
        } catch (AuthorityRegistryException e) {
            throw new IllegalStateException("hosted-entity lookup failed for " + subject, e);
        }
        if (found.isEmpty() || !found.get().resolvable(Instant.now())) {
            return null;
        }
        JwsSigner jwsSigner;
        try {
            jwsSigner = hostedEntitySigner().signerFor(found.get());
        } catch (RuntimeException e) {
            throw new IllegalStateException("could not resolve signer for hosted entity " + subject, e);
        }
        return Map.of("keys", List.of(jwsSigner.publicJwk()));
    }
}
