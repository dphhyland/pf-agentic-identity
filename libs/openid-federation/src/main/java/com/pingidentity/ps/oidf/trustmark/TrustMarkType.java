/*
 * A Trust Mark type this entity issues.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * A Trust Mark type this entity issues (OpenID Federation 1.0 §7), as the operator configured it.
 *
 * @param id              the Trust Mark type identifier, the marks' {@code trust_mark_type} (§7.1)
 * @param lifetimeSeconds how long a mark lives from issue; never past the end of the grant it was issued under
 * @param subjects        whom it may be issued to
 * @param delegation      the owner's {@code trust-mark-delegation+jwt} (§7.2.1) when this entity issues a type another
 *                        entity owns, carried in every mark; {@code null} when this entity owns the type
 * @param ref             the marks' {@code ref} (§7.1), or {@code null}
 * @param logoUri         the marks' {@code logo_uri} (§7.1), or {@code null}
 */
public record TrustMarkType(String id, long lifetimeSeconds, Subjects subjects, String delegation, String ref, String logoUri) {
    public static final long DEFAULT_LIFETIME_SECONDS = 86_400L;

    /** Whom a type may be issued to. */
    public enum Subjects {
        /** Only entities this authority hosts, and only while they are active. The default. */
        HOSTED,
        /** Any entity granted it. */
        ANY
    }

    public TrustMarkType {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("a Trust Mark type needs an identifier");
        }
        if (lifetimeSeconds <= 0) {
            throw new IllegalArgumentException("Trust Mark type " + id + ": lifetime_seconds must be positive");
        }
        Objects.requireNonNull(subjects, "subjects");
    }

    /**
     * Parses {@code {"<type>": {"lifetime_seconds": 86400, "subjects": "hosted" | "any", "delegation": "<jwt>",
     * "ref": "https://...", "logo_uri": "https://..."}, ...}}; every member but the type is optional. Blank is none.
     *
     * @throws IllegalArgumentException for anything else - a delegation that is not a {@code trust-mark-delegation+jwt}
     *                                  for the type it is configured under included
     */
    public static Map<String, TrustMarkType> parseAll(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        Map<String, Object> parsed;
        try {
            parsed = new ObjectMapper().readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Trust Mark types are not a JSON object: expected {\"<trust mark type>\": {\"lifetime_seconds\":"
                    + " 86400, \"subjects\": \"hosted\"}, ...}");
        }
        Map<String, TrustMarkType> types = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> settings)) {
                throw new IllegalArgumentException("Trust Mark type " + entry.getKey() + " is not configured with an object");
            }
            types.put(entry.getKey(), of(entry.getKey(), settings));
        }
        return java.util.Collections.unmodifiableMap(types);
    }

    private static TrustMarkType of(String id, Map<?, ?> settings) {
        Object lifetime = settings.get("lifetime_seconds");
        if (lifetime != null && !(lifetime instanceof Integer || lifetime instanceof Long)) {
            throw new IllegalArgumentException("Trust Mark type " + id + ": lifetime_seconds is not a whole number");
        }
        String subjects = text(settings, "subjects", id);
        Subjects parsedSubjects;
        try {
            parsedSubjects = subjects == null ? Subjects.HOSTED : Subjects.valueOf(subjects.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Trust Mark type " + id + ": subjects must be hosted or any, not " + subjects);
        }
        String delegation = text(settings, "delegation", id);
        if (delegation != null) {
            requireDelegationFor(id, delegation);
        }
        return new TrustMarkType(id, lifetime == null ? DEFAULT_LIFETIME_SECONDS : ((Number) lifetime).longValue(), parsedSubjects,
                delegation, httpsUrl(text(settings, "ref", id), "ref", id), httpsUrl(text(settings, "logo_uri", id), "logo_uri", id));
    }

    private static String text(Map<?, ?> settings, String name, String id) {
        Object value = settings.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException("Trust Mark type " + id + ": " + name + " is not a non-empty string");
        }
        return s.trim();
    }

    /** A delegation is checked for shape here; the validator that receives the mark checks the owner's signature. */
    private static void requireDelegationFor(String id, String delegation) {
        try {
            Object typ = JwtCodec.getJwtHeaders(delegation).get("typ");
            Object type = JwtCodec.parseUnverifiedClaims(delegation).getClaimValue("trust_mark_type");
            if (TrustMarkValidator.DELEGATION_TYP.equals(typ) && id.equals(type)) {
                return;
            }
        } catch (Exception e) {
            // falls through to the refusal
        }
        throw new IllegalArgumentException("Trust Mark type " + id + ": delegation is not a " + TrustMarkValidator.DELEGATION_TYP
                + " for this type (§7.2.1)");
    }

    private static String httpsUrl(String value, String name, String id) {
        if (value == null) {
            return null;
        }
        try {
            URI uri = URI.create(value);
            if ("https".equals(uri.getScheme()) && uri.getHost() != null) {
                return value;
            }
        } catch (IllegalArgumentException e) {
            // falls through to the refusal
        }
        throw new IllegalArgumentException("Trust Mark type " + id + ": " + name + " is not an https URL");
    }
}
