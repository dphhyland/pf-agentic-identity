package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.sourceid.oauth20.domain.Client;

/**
 * Parsed explicit client-registration request. Built either from a signed entity-statement JWT
 * (verified against its inline JWKS) or from a bare trust-chain JSON body, capturing the RP issuer,
 * subject, trust chain and metadata. In both cases an already-registered client is disabled and
 * the registration rejected.
 */
final class ExplicitRegistrationRequest {
    private final String issuer;
    private final String sub;
    private final List<String> trustChain;
    private final Map<String, Object> metadata;
    private static final ClientStore clientStore = new PfMgmtClientStore();

    ExplicitRegistrationRequest(String issuer, String sub, List<String> trustChain, Map<String, Object> metadata) {
        this.issuer = issuer;
        this.sub = sub;
        this.trustChain = trustChain != null ? List.copyOf(trustChain) : List.of();
        this.metadata = metadata != null ? metadata : Map.of();
    }

    static ExplicitRegistrationRequest fromJwt(String jwt, String expectedAud) throws Exception {
        JwtClaims unverifiedClaims = JwtCodec.parseUnverifiedClaims(jwt);
        List<String> audience = unverifiedClaims.getAudience();
        if (!audience.contains(expectedAud)) {
            throw new IllegalArgumentException("Invalid audience");
        }
        Client client = clientStore.get(unverifiedClaims.getSubject());
        if (client != null) {
            clientStore.disable(client);
            throw new IllegalArgumentException("Deactivated client because it already exists");
        }
        String opIssuer = Claims.requireNonBlank(unverifiedClaims.getIssuer(), "iss");
        Map<String, Object> jwks = Claims.requiredMap(unverifiedClaims, "jwks");
        JwtClaims verifiedClaims = JwtCodec.verifyAgainstInlineJwks(jwt, jwks, opIssuer);
        Map<String, Object> headers = JwtCodec.getJwtHeaders(jwt);
        try {
            Map<String, Object> root = verifiedClaims.getClaimsMap();
            List<String> trustChain = List.of();
            Object trustChainRaw = headers.get("trust_chain");
            if (trustChainRaw instanceof List) {
                List<?> list = (List<?>)trustChainRaw;
                trustChain = list.stream().map(String::valueOf).toList();
            }
            Object metadataRaw = root.get("metadata");
            Map<String, Object> metadata = metadataRaw instanceof Map ? asStringObjectMap(metadataRaw) : Map.of();
            return new ExplicitRegistrationRequest(verifiedClaims.getIssuer(), verifiedClaims.getSubject(), trustChain, metadata);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid explicit registration request JSON", e);
        }
    }

    static ExplicitRegistrationRequest fromTrustChainJson(String body) throws Exception {
        List<String> trustChain;
        try {
            trustChain = new ObjectMapper().readValue(body, new TypeReference<List<String>>(){});
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid trust-chain+json body: " + e.getMessage(), e);
        }
        JwtClaims leafClaims = TrustChainValidator.selectLeafEntityStatement(trustChain);
        String rpIssuer = Claims.requireNonBlank(leafClaims.getIssuer(), "iss");
        String leafSubject = Claims.requireNonBlank(leafClaims.getSubject(), "sub");
        Client client = clientStore.get(leafSubject);
        if (client != null) {
            clientStore.disable(client);
            throw new IllegalArgumentException("Deactivated client because it already exists");
        }
        return new ExplicitRegistrationRequest(rpIssuer, leafSubject, trustChain, Map.of());
    }

    String issuer() {
        return this.issuer;
    }

    String sub() {
        return this.sub;
    }

    List<String> trustChain() {
        return this.trustChain;
    }

    Map<String, Object> metadata() {
        return this.metadata;
    }

    private static String string(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value == null ? null : String.valueOf(value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asStringObjectMap(Object value) {
        return (Map<String, Object>) value;
    }
}

