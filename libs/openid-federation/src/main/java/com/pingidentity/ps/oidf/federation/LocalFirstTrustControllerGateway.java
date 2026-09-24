/*
 * A gateway that answers for this deployment's own statements without a network round trip.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;

/**
 * Wraps another gateway so that the statements this deployment issues - its own Entity Configuration, the
 * Subordinate Statements it makes, and the configurations of the entities it hosts - are produced in-process
 * rather than fetched from its own public URL.
 *
 * <p>Fetching its own hostname from inside a container is the step most likely to fail (the public name
 * may not route back in), and each such fetch is a request a caller can make this deployment spend on
 * itself. Everything else goes to the wrapped gateway, whose cache and anchor bindings are shared. Nothing
 * here skips validation: a local statement is checked like any other.
 */
public final class LocalFirstTrustControllerGateway implements TrustControllerGateway {
    private final TrustControllerGateway delegate;
    private final LocalStatementSource local;

    public LocalFirstTrustControllerGateway(TrustControllerGateway delegate, LocalStatementSource local) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.local = Objects.requireNonNull(local, "local");
    }

    @Override
    public JwtClaims fetchEntityConfiguration() throws Exception {
        return this.delegate.fetchEntityConfiguration();
    }

    @Override
    public List<String> fetchMembers() throws Exception {
        return this.delegate.fetchMembers();
    }

    @Override
    public String fetchEntityStatement(String issuer) throws Exception {
        return this.fetchEntityStatement(issuer, -1L, null);
    }

    @Override
    public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites)
            throws Exception {
        String jwt = this.local.entityConfiguration(issuer);
        return jwt != null ? jwt : this.delegate.fetchEntityStatement(issuer, maxAgeFromIatSeconds, pendingWrites);
    }

    @Override
    public String fetchSubordinateStatement(String authorityIssuer, String subject) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, -1L, null);
    }

    @Override
    public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds,
            SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        String jwt = this.local.subordinateStatement(authorityIssuer, subject);
        return jwt != null ? jwt : this.delegate.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds, pendingWrites);
    }

    @Override
    public String anchorConfiguration(TrustAnchor anchor, Set<String> acceptedSigningAlgorithms,
            SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        String jwt = this.local.entityConfiguration(anchor.entityId());
        return jwt != null ? jwt : this.delegate.anchorConfiguration(anchor, acceptedSigningAlgorithms, pendingWrites);
    }

    @Override
    public void bindTrustAnchor(TrustAnchor trustAnchor, Set<String> acceptedSigningAlgorithms) {
        this.delegate.bindTrustAnchor(trustAnchor, acceptedSigningAlgorithms);
    }

    @Override
    public void bindTrustAnchors(TrustAnchorSet trustAnchors, Set<String> acceptedSigningAlgorithms) {
        this.delegate.bindTrustAnchors(trustAnchors, acceptedSigningAlgorithms);
    }

    @Override
    public SubordinateStatementCache.PendingWrites newPendingWrites() {
        return this.delegate.newPendingWrites();
    }

    @Override
    public void evictCachedStatement(String issuer, String subject) {
        this.delegate.evictCachedStatement(issuer, subject);
    }
}
