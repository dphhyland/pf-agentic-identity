package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwt.JwtClaims;

/**
 * Parsed explicit client-registration request (OpenID Federation 1.0 §12.2). Built either from a
 * signed Entity Configuration (verified against its own inline {@code jwks}) or from a bare
 * trust-chain JSON body, capturing the RP issuer, subject, trust chain and metadata.
 *
 * <p>This is a <em>parser</em> and nothing more. It holds no reference to the client store and has no
 * side effects: an unverified, forged or malformed request produces an exception and changes nothing.
 * Whether the subject already exists, and what to do about it, is {@link RegistrationService}'s
 * decision — taken only after the trust chain has been validated to the configured anchor. (An
 * earlier revision disabled an existing client here, on the <em>unverified</em> {@code sub}, before
 * the signature was checked; that made an unauthenticated POST able to disable any client.)
 *
 * <p>Verifying against inline {@code jwks} proves only that the sender holds the key the statement
 * advertises — it is self-signed. Trust comes from the chain, which is why the parser must not act.
 */
final class ExplicitRegistrationRequest {
    /** Upper bound on the number of statements accepted in a trust-chain body. */
    static final int MAX_TRUST_CHAIN_LENGTH = 16;
    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";

    private final String issuer;
    private final String sub;
    private final List<String> trustChain;
    private final Map<String, Object> metadata;
    private final String requestJwt;
    private final List<String> peerTrustChain;

    ExplicitRegistrationRequest(String issuer, String sub, List<String> trustChain, Map<String, Object> metadata) {
        this(issuer, sub, trustChain, metadata, null, List.of());
    }

    ExplicitRegistrationRequest(String issuer, String sub, List<String> trustChain, Map<String, Object> metadata,
                                String requestJwt, List<String> peerTrustChain) {
        this.issuer = issuer;
        this.sub = sub;
        this.trustChain = trustChain != null ? List.copyOf(trustChain) : List.of();
        this.metadata = metadata != null ? metadata : Map.of();
        this.requestJwt = requestJwt;
        this.peerTrustChain = peerTrustChain != null ? List.copyOf(peerTrustChain) : List.of();
    }

    /**
     * From an {@code application/entity-statement+jwt} body. The unverified pass reads only what is
     * needed to verify ({@code iss}, {@code jwks}); every claim the caller acts on is read from the
     * verified result.
     */
    static ExplicitRegistrationRequest fromJwt(String jwt, String expectedAud) throws Exception {
        JwtClaims verified = verifySelfSigned(jwt);

        List<String> audience = verified.getAudience();
        if (audience == null || !audience.contains(expectedAud)) {
            throw new IllegalArgumentException("Invalid audience: expected " + expectedAud);
        }
        String sub = Claims.requireNonBlank(verified.getSubject(), "sub");
        if (!Objects.equals(sub, verified.getIssuer())) {
            throw new IllegalArgumentException("Explicit registration requires a self-statement (sub == iss)");
        }
        Map<String, Object> headers = JwtCodec.getJwtHeaders(jwt);
        try {
            Map<String, Object> root = verified.getClaimsMap();
            List<String> trustChain = header(headers, "trust_chain");
            Object metadataRaw = root.get("metadata");
            Map<String, Object> metadata = metadataRaw instanceof Map ? asStringObjectMap(metadataRaw) : Map.of();
            return new ExplicitRegistrationRequest(verified.getIssuer(), sub, trustChain, metadata, jwt, header(headers, "peer_trust_chain"));
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid explicit registration request JSON", e);
        }
    }

    /**
     * The request statement's claims, once it is typed and verifies under its own {@code jwks}.
     *
     * <p>OpenID Federation 1.0 §3: an Entity Statement without {@code typ: entity-statement+jwt} MUST be
     * rejected, and §12.2.2 applies the normal Entity Statement validation rules to this request. It
     * has to happen here: {@link RegistrationService#explicitRegister} validates the chain in the
     * body's {@code trust_chain} header, which never contains the body itself, so no later check reads
     * this statement's header.
     */
    private static JwtClaims verifySelfSigned(String jwt) {
        try {
            JwtCodec.requireType(JwtCodec.getJwtHeaders(jwt), ENTITY_STATEMENT_TYP);
            JwtClaims unverified = JwtCodec.parseUnverifiedClaims(jwt);
            String opIssuer = Claims.requireNonBlank(unverified.getIssuer(), "iss");
            Map<String, Object> jwks = Claims.requiredMap(unverified, "jwks");
            return JwtCodec.verifyAgainstInlineJwks(jwt, jwks, opIssuer);
        }
        catch (IllegalArgumentException e) {
            throw e;
        }
        catch (Exception e) {
            // A statement that cannot be parsed or does not verify under its own jwks is a malformed
            // request (400), not a server fault - and it has, by construction, touched nothing.
            throw new IllegalArgumentException("Entity statement could not be verified: " + e.getMessage(), e);
        }
    }

    /**
     * From an {@code application/trust-chain+json} body. Only <em>selects</em> the leaf so the caller
     * knows which subject the chain claims to be about; the statements are verified by the chain
     * validator, not here.
     */
    static ExplicitRegistrationRequest fromTrustChainJson(String body) throws Exception {
        List<String> trustChain;
        try {
            trustChain = new ObjectMapper().readValue(body, new TypeReference<List<String>>(){});
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid trust-chain+json body: " + e.getMessage(), e);
        }
        if (trustChain == null || trustChain.isEmpty()) {
            throw new IllegalArgumentException("trust-chain+json body is empty");
        }
        if (trustChain.size() > MAX_TRUST_CHAIN_LENGTH) {
            throw new IllegalArgumentException("trust-chain+json body has " + trustChain.size()
                    + " statements; at most " + MAX_TRUST_CHAIN_LENGTH + " are accepted");
        }
        JwtClaims leafClaims = TrustChainValidator.selectLeafEntityStatement(trustChain);
        String rpIssuer = Claims.requireNonBlank(leafClaims.getIssuer(), "iss");
        String leafSubject = Claims.requireNonBlank(leafClaims.getSubject(), "sub");
        return new ExplicitRegistrationRequest(rpIssuer, leafSubject, trustChain, Map.of());
    }

    private static List<String> header(Map<String, Object> headers, String name) {
        Object raw = headers.get(name);
        return raw instanceof List<?> list ? list.stream().map(String::valueOf).toList() : List.of();
    }

    /**
     * The statements to validate. For an Entity Configuration body that is the posted configuration itself
     * plus whatever its {@code trust_chain} header carries - minus the RP's own configuration in that header:
     * §12.2.2 says the header only shows there is a path, and "it is the metadata, etc. in the request
     * Entity Configuration ... that is used". The posted configuration also means an RP that publishes no
     * configuration of its own (§9 allows that for explicit registration) is not fetched. For a Trust Chain
     * body, the chain as sent.
     */
    List<String> presentedChain() {
        if (this.requestJwt == null) {
            return this.trustChain;
        }
        List<String> presented = new java.util.ArrayList<>();
        presented.add(this.requestJwt);
        for (String statement : this.trustChain) {
            if (!this.isOwnConfiguration(statement)) {
                presented.add(statement);
            }
        }
        return List.copyOf(presented);
    }

    private boolean isOwnConfiguration(String statement) {
        try {
            JwtClaims claims = JwtCodec.parseUnverifiedClaims(statement);
            return Objects.equals(claims.getIssuer(), this.issuer) && Objects.equals(claims.getSubject(), this.issuer);
        } catch (Exception e) {
            return false;
        }
    }

    /** The {@code peer_trust_chain} header of an Entity Configuration body (§12.2.1), or empty. */
    List<String> peerTrustChain() {
        return this.peerTrustChain;
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

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asStringObjectMap(Object value) {
        return (Map<String, Object>) value;
    }
}
