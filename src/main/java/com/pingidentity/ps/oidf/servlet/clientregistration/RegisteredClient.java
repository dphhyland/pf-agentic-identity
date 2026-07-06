package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.List;
import java.util.Map;

/**
 * Immutable result of a successful explicit registration: the assigned client id, the RP issuer
 * and trust anchor, the trust chain, the effective RP metadata, a status, and the signed
 * registration-response JWT returned to the caller.
 */
final class RegisteredClient {
    private final String clientId;
    private final String issuer;
    private final String trustAnchor;
    private final List<String> trustChain;
    private final Map<String, Object> metadata;
    private final String status;
    private final String signedJwt;

    RegisteredClient(String clientId, String issuer, String trustAnchor, List<String> trustChain, Map<String, Object> metadata, String status, String signedJwt) {
        this.clientId = clientId;
        this.issuer = issuer;
        this.trustAnchor = trustAnchor;
        this.trustChain = trustChain != null ? List.copyOf(trustChain) : List.of();
        this.metadata = metadata != null ? metadata : Map.of();
        this.status = status;
        this.signedJwt = signedJwt;
    }

    String clientId() {
        return this.clientId;
    }

    String issuer() {
        return this.issuer;
    }

    String trustAnchor() {
        return this.trustAnchor;
    }

    Map<String, Object> metadata() {
        return this.metadata;
    }

    String signedJwt() {
        return this.signedJwt;
    }

    Map<String, Object> toMap() {
        return Map.of("client_id", this.clientId, "issuer", this.issuer, "trust_anchor", this.trustAnchor, "status", this.status, "metadata", this.metadata, "trust_chain_length", this.trustChain.size());
    }
}

