/*
 * The OpenID Federation 1.0 §3.2 checks that read an Entity Statement itself.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;

/**
 * The steps of OpenID Federation 1.0 §3.2 that look at one statement's header and claims: required claims,
 * Entity Identifiers, the key set, {@code crit}, which claims may appear in an Entity Configuration and
 * which in a Subordinate Statement, and the syntax of each claim. The steps that need a key - {@code typ},
 * {@code alg}, {@code kid}, the signature, {@code iat} and {@code exp} - are the verifier's
 * ({@link com.pingidentity.ps.oidf.jose.VerificationPolicy#entityStatement()}).
 *
 * <p>§3.2 lets the steps run in any order "provided that the result - accepting or rejecting the Entity
 * Statement - is the same", so these run on the unverified claims, before any key is tried; nothing here
 * trusts a value, it only refuses bad ones. Every refusal is a {@link TrustChainValidationException} naming
 * the statement, and every description is written here, never copied from the statement.
 */
final class EntityStatementChecks {

    /** The claims this specification defines for Entity Statements, which {@code crit} MUST NOT list (§3.1.1). */
    static final Set<String> DEFINED_CLAIMS = Set.of("iss", "sub", "iat", "exp", "jwks", "metadata", "crit",
            "authority_hints", "trust_anchor_hints", "trust_marks", "trust_mark_issuers", "trust_mark_owners",
            "constraints", "metadata_policy", "metadata_policy_crit", "source_endpoint", "aud", "trust_anchor");

    /** Extension claims this implementation understands and processes. None: {@code crit} always refuses. */
    static final Set<String> SUPPORTED_CRITICAL_CLAIMS = Set.of();

    private static final Set<String> CONFIGURATION_ONLY = Set.of("authority_hints", "trust_anchor_hints", "trust_marks",
            "trust_mark_issuers", "trust_mark_owners");
    private static final Set<String> SUBORDINATE_ONLY = Set.of("metadata_policy", "metadata_policy_crit", "constraints",
            "source_endpoint");

    private EntityStatementChecks() {
    }

    /**
     * @param header               the statement's protected header
     * @param claims               its claims, unverified
     * @param registrationAudience the OP's Entity Identifier when this statement is the chain subject's Entity
     *                             Configuration and may be an Explicit Registration request (§12.2.1), whose
     *                             {@code aud} names the OP and which may carry {@code trust_chain} and
     *                             {@code peer_trust_chain} headers; {@code null} otherwise
     * @throws TrustChainValidationException at the first step that fails
     */
    static void check(Map<String, Object> header, JwtClaims claims, String registrationAudience) {
        check(header, claims, registrationAudience, SUPPORTED_CRITICAL_CLAIMS);
    }

    /** As {@link #check(Map, JwtClaims, String)}, with the extension claims this caller understands. */
    static void check(Map<String, Object> header, JwtClaims claims, String registrationAudience, Set<String> understood) {
        Map<String, Object> raw = claims.getClaimsMap();
        String iss = entityId(raw, "iss", null, null);
        String sub = entityId(raw, "sub", iss, null);
        boolean configuration = EntityId.same(iss, sub);
        requireNumber(raw, "iat", iss, sub);
        requireNumber(raw, "exp", iss, sub);
        checkKeySet(raw.get("jwks"), "jwks", iss, sub);
        checkCrit(raw, understood, iss, sub);
        for (String name : raw.keySet()) {
            if (configuration && SUBORDINATE_ONLY.contains(name)) {
                throw refuse(Kind.SYNTAX, iss, sub, name + " may appear only in a Subordinate Statement (§3.2)");
            }
            if (!configuration && CONFIGURATION_ONLY.contains(name)) {
                throw refuse(Kind.SYNTAX, iss, sub, name + " may appear only in an Entity Configuration (§3.2)");
            }
        }
        checkEntityIdArray(raw, "authority_hints", iss, sub);
        checkEntityIdArray(raw, "trust_anchor_hints", iss, sub);
        checkMetadata(raw.get("metadata"), iss, sub);
        checkMetadataPolicy(raw, iss, sub);
        if (raw.containsKey("constraints")) {
            try {
                Constraints.parse(raw.get("constraints"));
            } catch (IllegalArgumentException e) {
                throw refuse(Kind.SYNTAX, iss, sub, "constraints: " + e.getMessage());
            }
        }
        checkTrustMarks(raw.get("trust_marks"), iss, sub);
        checkTrustMarkIssuers(raw.get("trust_mark_issuers"), iss, sub);
        checkTrustMarkOwners(raw.get("trust_mark_owners"), iss, sub);
        if (raw.containsKey("source_endpoint") && !isHttpUrl(raw.get("source_endpoint"))) {
            throw refuse(Kind.SYNTAX, iss, sub, "source_endpoint is not a URL (§3.2)");
        }
        if (raw.containsKey("trust_anchor")) {
            throw refuse(Kind.SYNTAX, iss, sub, "trust_anchor appears only in an Explicit Registration response (§3.2)");
        }
        boolean registrationRequest = checkAudience(raw, configuration, registrationAudience, iss, sub);
        checkChainHeaders(header, registrationRequest, sub, iss);
    }

    // ---- identifiers, numbers, keys --------------------------------------------------------------------

    private static String entityId(Map<String, Object> raw, String name, String iss, String sub) {
        Object value = raw.get(name);
        if (value == null) {
            throw refuse(Kind.MISSING_CLAIM, iss, sub, "the " + name + " claim is missing (§3.1.1)");
        }
        if (!(value instanceof String s) || !EntityId.isValid(s)) {
            throw refuse(Kind.SYNTAX, iss, sub, "the " + name + " claim is not a valid Entity Identifier (§3.2)");
        }
        return s;
    }

    private static void requireNumber(Map<String, Object> raw, String name, String iss, String sub) {
        Object value = raw.get(name);
        if (value == null) {
            throw refuse(Kind.MISSING_CLAIM, iss, sub, "the " + name + " claim is missing (§3.1.1)");
        }
        if (!(value instanceof Number)) {
            throw refuse(Kind.SYNTAX, iss, sub, "the " + name + " claim is not a number (§3.1.1)");
        }
    }

    private static void checkKeySet(Object value, String name, String iss, String sub) {
        if (value == null) {
            throw refuse(Kind.MISSING_CLAIM, iss, sub, "the " + name + " claim is missing (§3.2)");
        }
        if (!(value instanceof Map<?, ?>)) {
            throw refuse(Kind.SYNTAX, iss, sub, name + " is not a JWK Set (§3.2)");
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) value;
            Jwks.parseFederationKeySet(jwks);
        } catch (IllegalArgumentException e) {
            throw refuse(Kind.SYNTAX, iss, sub, name + " is not a usable set of Federation Entity Keys: " + e.getMessage());
        }
    }

    // ---- crit ------------------------------------------------------------------------------------

    private static void checkCrit(Map<String, Object> raw, Set<String> understood, String iss, String sub) {
        if (!raw.containsKey("crit")) {
            return;
        }
        if (!(raw.get("crit") instanceof List<?> names) || names.isEmpty()) {
            throw refuse(Kind.SYNTAX, iss, sub, "crit must be a non-empty array of claim names (§13.4)");
        }
        for (Object name : names) {
            if (!(name instanceof String s)) {
                throw refuse(Kind.SYNTAX, iss, sub, "crit holds something other than a claim name (§13.4)");
            }
            if (DEFINED_CLAIMS.contains(s)) {
                throw refuse(Kind.SYNTAX, iss, sub, "crit lists " + s + ", a claim this specification defines (§3.1.1)");
            }
            if (!understood.contains(s)) {
                throw refuse(Kind.CRIT, iss, sub, "crit lists " + LogSafe.value(s) + ", which this implementation does not"
                        + " understand, so the statement MUST be rejected (§3.2)");
            }
        }
    }

    // ---- claim syntax ----------------------------------------------------------------------------

    private static void checkEntityIdArray(Map<String, Object> raw, String name, String iss, String sub) {
        if (!raw.containsKey(name)) {
            return;
        }
        if (!(raw.get(name) instanceof List<?> values) || values.isEmpty()) {
            throw refuse(Kind.SYNTAX, iss, sub, name + " must be a non-empty array of Entity Identifiers (§3.1.2)");
        }
        for (Object value : values) {
            if (!(value instanceof String s) || !EntityId.isValid(s)) {
                throw refuse(Kind.SYNTAX, iss, sub, name + " holds something other than an Entity Identifier (§3.1.2)");
            }
        }
    }

    private static void checkMetadata(Object metadata, String iss, String sub) {
        if (metadata == null) {
            return;
        }
        if (!(metadata instanceof Map<?, ?> types)) {
            throw refuse(Kind.SYNTAX, iss, sub, "metadata is not a JSON object (§5)");
        }
        for (Map.Entry<?, ?> type : types.entrySet()) {
            if (!(type.getValue() instanceof Map<?, ?> parameters)) {
                throw refuse(Kind.SYNTAX, iss, sub, "metadata for " + LogSafe.value(String.valueOf(type.getKey()))
                        + " is not a JSON object (§3.1.1)");
            }
            for (Map.Entry<?, ?> parameter : parameters.entrySet()) {
                if (parameter.getValue() == null) {
                    throw refuse(Kind.SYNTAX, iss, sub, "metadata parameter " + LogSafe.value(String.valueOf(parameter.getKey()))
                            + " is null, which metadata may not use (§5)");
                }
            }
        }
    }

    private static void checkMetadataPolicy(Map<String, Object> raw, String iss, String sub) {
        if (raw.containsKey("metadata_policy_crit")) {
            if (!(raw.get("metadata_policy_crit") instanceof List<?> operators) || operators.isEmpty()) {
                throw refuse(Kind.SYNTAX, iss, sub, "metadata_policy_crit must be a non-empty array of operator names (§3.1.3)");
            }
            for (Object operator : operators) {
                if (!(operator instanceof String s)) {
                    throw refuse(Kind.SYNTAX, iss, sub, "metadata_policy_crit holds something other than an operator name (§3.1.3)");
                }
                if (MetadataPolicy.KNOWN_OPERATORS.contains(s)) {
                    throw refuse(Kind.SYNTAX, iss, sub, "metadata_policy_crit lists the standard operator " + s
                            + "; it may list only additional operators (§3.2)");
                }
            }
            // MetadataPolicy understands no additional operator, so any it names is one it cannot process.
            throw refuse(Kind.CRIT, iss, sub, "metadata_policy_crit lists " + LogSafe.value(String.valueOf(operators))
                    + ", operators this implementation does not understand, so the statement MUST be rejected (§3.2)");
        }
        if (!raw.containsKey("metadata_policy")) {
            return;
        }
        if (!(raw.get("metadata_policy") instanceof Map<?, ?> types)) {
            throw refuse(Kind.SYNTAX, iss, sub, "metadata_policy is not a JSON object (§6.1.2)");
        }
        for (Map.Entry<?, ?> type : types.entrySet()) {
            if (!(type.getValue() instanceof Map<?, ?>)) {
                throw refuse(Kind.SYNTAX, iss, sub, "metadata_policy for " + LogSafe.value(String.valueOf(type.getKey()))
                        + " is not a JSON object (§6.1.2)");
            }
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> policy = (Map<String, Object>) type.getValue();
                MetadataPolicy.parse(policy, null);
            } catch (MetadataPolicy.PolicyException e) {
                throw new TrustChainValidationException(Kind.POLICY, iss, sub, "metadata_policy for "
                        + LogSafe.value(String.valueOf(type.getKey())) + " is not valid: " + e.getMessage(), e);
            }
        }
    }

    private static void checkTrustMarks(Object value, String iss, String sub) {
        if (value == null) {
            return;
        }
        if (!(value instanceof List<?> marks)) {
            throw refuse(Kind.SYNTAX, iss, sub, "trust_marks is not an array (§3.1.2)");
        }
        for (Object mark : marks) {
            if (!(mark instanceof Map<?, ?> entry) || !(entry.get("trust_mark_type") instanceof String type)
                    || !(entry.get("trust_mark") instanceof String jwt)) {
                throw refuse(Kind.SYNTAX, iss, sub, "each trust_marks entry needs a trust_mark_type and a trust_mark (§3.1.2)");
            }
            Object inner;
            try {
                inner = JwtCodec.parseUnverifiedClaims(jwt).getClaimValue("trust_mark_type");
            } catch (Exception e) {
                throw refuse(Kind.SYNTAX, iss, sub, "a trust_marks entry does not hold a Trust Mark JWT (§3.2)");
            }
            if (!type.equals(inner)) {
                throw refuse(Kind.SYNTAX, iss, sub, "a trust_marks entry's trust_mark_type differs from the one in its Trust"
                        + " Mark (§3.2)");
            }
        }
    }

    private static void checkTrustMarkIssuers(Object value, String iss, String sub) {
        if (value == null) {
            return;
        }
        if (!(value instanceof Map<?, ?> types)) {
            throw refuse(Kind.SYNTAX, iss, sub, "trust_mark_issuers is not a JSON object (§3.2)");
        }
        for (Object issuers : types.values()) {
            if (!(issuers instanceof List<?> list)) {
                throw refuse(Kind.SYNTAX, iss, sub, "trust_mark_issuers maps a type to something other than an array (§3.2)");
            }
            for (Object issuer : list) {
                if (!(issuer instanceof String s) || !EntityId.isValid(s)) {
                    throw refuse(Kind.SYNTAX, iss, sub, "trust_mark_issuers holds something other than an Entity Identifier (§3.2)");
                }
            }
        }
    }

    private static void checkTrustMarkOwners(Object value, String iss, String sub) {
        if (value == null) {
            return;
        }
        if (!(value instanceof Map<?, ?> types)) {
            throw refuse(Kind.SYNTAX, iss, sub, "trust_mark_owners is not a JSON object (§3.2)");
        }
        for (Object owner : types.values()) {
            if (!(owner instanceof Map<?, ?> entry) || !(entry.get("sub") instanceof String ownerId) || !EntityId.isValid(ownerId)) {
                throw refuse(Kind.SYNTAX, iss, sub, "each trust_mark_owners entry needs a sub that is an Entity Identifier (§3.2)");
            }
            checkKeySet(entry.get("jwks"), "trust_mark_owners jwks", iss, sub);
        }
    }

    // ---- registration-only claims and headers ----------------------------------------------------------

    /**
     * §3.2: {@code aud} "MUST NOT be present in Entity Statements that are not Explicit Registration requests
     * or responses"; in a request it is the OP and nothing else (§12.2.1).
     *
     * @return true when this statement is an Explicit Registration request
     */
    private static boolean checkAudience(Map<String, Object> raw, boolean configuration, String registrationAudience,
            String iss, String sub) {
        if (!raw.containsKey("aud")) {
            return false;
        }
        Object aud = raw.get("aud");
        boolean onlyTheOp = registrationAudience != null && configuration
                && (EntityId.same(registrationAudience, aud instanceof String s ? s : null)
                    || aud instanceof List<?> list && list.size() == 1 && list.get(0) instanceof String one
                        && EntityId.same(registrationAudience, one));
        if (!onlyTheOp) {
            throw refuse(Kind.SYNTAX, iss, sub, "aud appears only in an Explicit Registration request, naming the OP and"
                    + " nothing else (§3.2, §12.2.1)");
        }
        return true;
    }

    /**
     * §4.3, §4.4: "Entity Configurations and Subordinate Statements MUST NOT contain" the {@code trust_chain} or
     * {@code peer_trust_chain} header - except the Explicit Registration request, whose {@code trust_chain}
     * MUST begin with an Entity Configuration of the same Entity (§3.2, §12.2.1).
     */
    private static void checkChainHeaders(Map<String, Object> header, boolean registrationRequest, String sub, String iss) {
        for (String name : List.of("trust_chain", "peer_trust_chain")) {
            if (!header.containsKey(name)) {
                continue;
            }
            if (!registrationRequest) {
                throw refuse(Kind.SYNTAX, iss, sub, "the " + name + " header may not appear on an Entity Statement in a"
                        + " Trust Chain (§4.3, §4.4)");
            }
            if (!(header.get(name) instanceof List<?> chain) || chain.isEmpty()) {
                throw refuse(Kind.SYNTAX, iss, sub, "the " + name + " header is not a Trust Chain (§3.2)");
            }
            for (Object entry : chain) {
                if (!(entry instanceof String)) {
                    throw refuse(Kind.SYNTAX, iss, sub, "the " + name + " header holds something other than a JWT (§3.2)");
                }
            }
            if ("trust_chain".equals(name)) {
                String first;
                try {
                    JwtClaims firstClaims = JwtCodec.parseUnverifiedClaims((String) chain.get(0));
                    first = firstClaims.getSubject();
                    if (!EntityId.same(firstClaims.getIssuer(), first)) {
                        first = null;
                    }
                } catch (Exception e) {
                    first = null;
                }
                if (!EntityId.same(first, sub)) {
                    throw refuse(Kind.SYNTAX, iss, sub, "the trust_chain header does not begin with this Entity's own Entity"
                            + " Configuration (§3.2)");
                }
            }
        }
    }

    private static boolean isHttpUrl(Object value) {
        if (!(value instanceof String s)) {
            return false;
        }
        try {
            URI uri = new URI(s);
            return ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme())) && uri.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static TrustChainValidationException refuse(Kind kind, String iss, String sub, String description) {
        return new TrustChainValidationException(kind, iss, sub, description);
    }
}
