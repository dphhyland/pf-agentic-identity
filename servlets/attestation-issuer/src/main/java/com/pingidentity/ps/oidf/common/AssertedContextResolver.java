/*
 * Second-stage SPI: resolves a caller-asserted (unverified) discriminator against an evidenced instance.
 */
package com.pingidentity.ps.oidf.common;

/**
 * Runs <em>after</em> an {@link InstanceAttestationValidator} has already cryptographically verified the
 * calling workload's evidence. Some platforms layer many logical agents over one evidenced identity —
 * Copilot Studio's Entra Agent ID directory over one evidenced Azure workload is the motivating case —
 * where the specific agent can only ever be <em>asserted</em> by the caller at request time, never proven.
 * A resolver takes that assertion plus the already-verified {@link InstanceIdentity} and does a
 * directory/group-membership lookup, producing an {@link AssertedContext}.
 *
 * <p>Opt-in and additive only: a client with no {@code attestation_asserted_context_resolver} configured
 * (the default) never invokes any resolver, and every existing evidence-only client is unaffected.
 *
 * <p>Non-negotiable constraint enforced by the caller ({@link AttestationIssuanceServlet}), not by
 * implementations: the produced {@link AssertedContext#ceiling()} is <em>intersected</em> with the
 * evidenced instance's own ceiling, never unioned — the asserted layer can only narrow authority, never
 * grant beyond what the evidenced workload itself was bound to.
 */
public interface AssertedContextResolver {

    /** The resolver id a client's {@code attestation_asserted_context_resolver} property names. */
    String id();

    /**
     * Resolves the asserted discriminator against the verified instance identity.
     *
     * @param verified             the already-validated instance identity (evidence-proven)
     * @param assertedDiscriminator the caller-supplied, unverified value (e.g. an Entra Agent ID {@code oid})
     * @param config                the resolving client's issuance config
     * @throws IssuanceException {@code access_denied} if the discriminator is unknown to the directory, or
     *                           another appropriate code for a malformed/unresolvable discriminator
     */
    AssertedContext resolve(InstanceIdentity verified, String assertedDiscriminator,
                            AttestationIssuanceConfig config) throws IssuanceException;
}
