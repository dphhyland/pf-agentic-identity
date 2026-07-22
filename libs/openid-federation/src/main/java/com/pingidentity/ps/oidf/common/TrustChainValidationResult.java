package com.pingidentity.ps.oidf.common;

import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;

/**
 * Immutable outcome of a successful trust-chain validation: the trust anchor it resolved to,
 * the validated leaf's subject and metadata, the ordered chain of statements, and the leaf's
 * verified entity statement. Metadata and chain are defensively copied and never {@code null}.
 */
public final class TrustChainValidationResult {
    private final String trustAnchorIssuer;
    private final String leafSubject;
    private final Map<String, Object> leafMetadata;
    private final List<String> trustChain;
    private final JwtClaims leafEntityStatement;

    public TrustChainValidationResult(String trustAnchorIssuer, String leafSubject, Map<String, Object> leafMetadata, List<String> trustChain, JwtClaims leafEntityStatement) {
        this.trustAnchorIssuer = trustAnchorIssuer;
        this.leafSubject = leafSubject;
        this.leafMetadata = leafMetadata != null ? leafMetadata : Map.of();
        this.trustChain = trustChain != null ? List.copyOf(trustChain) : List.of();
        this.leafEntityStatement = leafEntityStatement;
    }

    public String trustAnchorIssuer() {
        return this.trustAnchorIssuer;
    }

    public String leafSubject() {
        return this.leafSubject;
    }

    public Map<String, Object> leafMetadata() {
        return this.leafMetadata;
    }

    public List<String> trustChain() {
        return this.trustChain;
    }

    public JwtClaims leafEntityStatement() {
        return this.leafEntityStatement;
    }
}

