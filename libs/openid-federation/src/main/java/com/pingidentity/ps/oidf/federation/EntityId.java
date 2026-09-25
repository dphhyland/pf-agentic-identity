/*
 * Comparison and URL rules for OpenID Federation Entity Identifiers.
 */
package com.pingidentity.ps.oidf.federation;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/**
 * Entity Identifiers as OpenID Federation 1.0 §1.2 and §9 define them: an {@code https} URL with a host,
 * optionally a port and path, never a fragment; and "if the Entity Identifier contains a trailing "/"
 * character, it MUST be removed before concatenating /.well-known/openid-federation".
 *
 * <p>Claims are never rewritten. What this class normalises is <em>comparison</em> and <em>URL
 * construction</em>: {@code https://a.example/} and {@code https://a.example} name the same entity, so
 * every equality check between identifiers ({@code iss}/{@code sub} matching, {@code authority_hints},
 * anchor lookup, cache keys, request parameters) goes through {@link #same}, and every well-known URL
 * through {@link #wellKnownUrl}. Nothing else is normalised: no case folding of the path, no default
 * port removal - two spellings the spec does not equate are not equated here.
 */
public final class EntityId {
    private static final String WELL_KNOWN = "/.well-known/openid-federation";

    private EntityId() {
    }

    /**
     * The identifier with surrounding whitespace and one trailing {@code /} removed.
     *
     * @throws IllegalArgumentException when it is not an {@code https} URL with a host, or it carries a
     *                                  fragment, user info or query
     */
    public static String normalize(String id) {
        String trimmed = id == null ? "" : id.trim();
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        URI uri;
        try {
            uri = new URI(trimmed);
        } catch (Exception e) {
            throw new IllegalArgumentException("Not a valid Entity Identifier: " + id);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Entity Identifiers use the https scheme (OpenID Federation 1.0 §1.2): " + id);
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("Entity Identifier has no host: " + id);
        }
        if (uri.getRawFragment() != null || uri.getRawUserInfo() != null || uri.getRawQuery() != null) {
            throw new IllegalArgumentException("Entity Identifier must not carry a fragment, user info or query: " + id);
        }
        return trimmed;
    }

    /** {@link #normalize} without the validation, for comparing values that may not be valid at all. */
    public static String comparable(String id) {
        if (id == null) {
            return null;
        }
        String trimmed = id.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    /** True when {@code a} and {@code b} name the same entity: equal after trailing-slash removal. */
    public static boolean same(String a, String b) {
        return a != null && b != null && Objects.equals(comparable(a), comparable(b));
    }

    /** True when {@code id} is a well-formed Entity Identifier. */
    public static boolean isValid(String id) {
        try {
            normalize(id);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** {@code <id without trailing slash>/.well-known/openid-federation} (OpenID Federation 1.0 §9). */
    public static String wellKnownUrl(String id) {
        return comparable(id) + WELL_KNOWN;
    }

    /** The lower-cased host of the identifier, for naming constraints (OpenID Federation 1.0 §6.2.2). */
    public static String host(String id) {
        URI uri = URI.create(normalize(id));
        return uri.getHost().toLowerCase(Locale.ROOT);
    }
}
