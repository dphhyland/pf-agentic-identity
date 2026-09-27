/*
 * What the access token's typ header must say.
 */
package com.pingidentity.ps.oidf.rs;

import java.util.Locale;
import java.util.Objects;

/**
 * The {@code typ} JOSE header an access token must carry.
 *
 * <p>RFC 9068 §4: "The resource server MUST verify that the "typ" header value is "at+jwt" or "application/at+jwt"
 * and reject tokens carrying any other value." That is {@link #RFC9068}, the default. PingFederate does not emit
 * it unless told to: its JWT access token manager has a "Type Header Value" field whose description reads
 * "Indicates the value of the Type (typ) header in the JWT (omitted, if blank)", and whose default is blank (read
 * 2026-09-28 with javap from {@code JwtBearerAccessTokenManagementPlugin} in pf-core-plugins.jar, PingFederate
 * 13.1.3). The conformance rig sets it to {@code at+jwt} (conformance/terraform/tokens.tf). A deployment whose
 * token manager leaves it blank uses {@link #ABSENT}, which requires the header to be missing, so the check still
 * refuses a token of another type - an ID token, say - that does carry one.
 *
 * <p>Media types compare without regard to case, so the comparison here does too.
 */
public final class AccessTokenType {
    /** {@code at+jwt} or {@code application/at+jwt}, as RFC 9068 §4 requires. */
    public static final AccessTokenType RFC9068 = new AccessTokenType("at+jwt", true);
    /** No {@code typ} header at all: PingFederate's token manager with a blank "Type Header Value". */
    public static final AccessTokenType ABSENT = new AccessTokenType(null, false);

    private final String expected;
    private final boolean applicationPrefix;

    private AccessTokenType(String expected, boolean applicationPrefix) {
        this.expected = expected;
        this.applicationPrefix = applicationPrefix;
    }

    /** Exactly {@code typ} (without regard to case), for an authorisation server configured to send another value. */
    public static AccessTokenType exactly(String typ) {
        if (Objects.requireNonNull(typ, "typ").isBlank()) {
            throw new IllegalArgumentException("an expected typ is not blank; use ABSENT for a token without one");
        }
        return new AccessTokenType(typ, false);
    }

    /** Whether a token whose {@code typ} header is {@code typ} (null when it has none) is acceptable. */
    public boolean accepts(String typ) {
        if (this.expected == null || typ == null) {
            return this.expected == null && typ == null;
        }
        String presented = typ.toLowerCase(Locale.ROOT);
        String wanted = this.expected.toLowerCase(Locale.ROOT);
        return presented.equals(wanted) || this.applicationPrefix && presented.equals("application/" + wanted);
    }

    @Override
    public String toString() {
        if (this.expected == null) {
            return "no typ header";
        }
        return this.applicationPrefix ? this.expected + " or application/" + this.expected : this.expected;
    }
}
