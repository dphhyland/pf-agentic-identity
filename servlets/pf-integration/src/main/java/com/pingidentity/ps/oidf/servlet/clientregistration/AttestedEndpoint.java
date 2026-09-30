/*
 * The PingFederate endpoints ClientAttestationAuthFilter is mapped over, and what it does at each.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

/**
 * Which of PingFederate's endpoints a request to {@link ClientAttestationAuthFilter} is, from the path the container
 * routed it to ({@code ClientAttestationUtils.endpointPath}: servlet path and path info, decoded and normalised, so
 * {@code /as/bc-auth.ciba;x}, {@code /as/bc-auth%2Eciba} and {@code /as/./bc-auth.ciba} are all the backchannel
 * endpoint - the spellings PingFederate 13.1.3 serves there, seen on the rig on 2026-09-30, U-0094). The mapping in
 * {@code build/pingfederate/filters.xml} is what puts a request here; this says what the filter does with it.
 *
 * <p>Every endpoint below that authenticates a client authenticates it the same way (RFC 9126 §2.1, at PAR:
 * "Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749])"), so the filter verifies
 * an attestation and bridges it at each. Where a request can carry {@code authorization_details} - the token endpoint,
 * PAR, CIBA's backchannel endpoint and the device authorization endpoint (RFC 9396 §3 names the last three besides the
 * authorization request) - the details forwarded are the ones granted against the attestation's, never the client's.
 * Introspection and revocation carry none. The authorization endpoint takes no client authentication; there the filter
 * only refuses details that should have been pushed ({@link PushedDetailsRule}).
 */
enum AttestedEndpoint {
    /** {@code /as/token.oauth2}. */
    TOKEN("/as/token.oauth2", true, true, false),
    /** {@code /as/par.oauth2}: RFC 9126. A signed request object is held to the ceiling as it stands. */
    PAR("/as/par.oauth2", true, true, true),
    /** {@code /as/bc-auth.ciba}: OpenID Connect CIBA's backchannel authentication endpoint; it takes request objects too. */
    CIBA("/as/bc-auth.ciba", true, true, true),
    /** {@code /as/device_authz.oauth2}: RFC 8628 §3.1, which PingFederate 13.1.3 serves with client authentication. */
    DEVICE("/as/device_authz.oauth2", true, true, false),
    /** {@code /as/introspect.oauth2}: authentication only. */
    INTROSPECTION("/as/introspect.oauth2", true, false, false),
    /** {@code /as/revoke_token.oauth2}: authentication only. */
    REVOCATION("/as/revoke_token.oauth2", true, false, false),
    /** {@code /as/authorization.oauth2}: no client authentication; {@link PushedDetailsRule} only. */
    AUTHORIZATION("/as/authorization.oauth2", false, false, false),
    /**
     * A path this enum does not name, which only a mapping added without it can send here: treated as the strictest
     * client-authenticating endpoint - details rewritten, request objects held to the ceiling - never as one that skips
     * a check.
     */
    OTHER(null, true, true, true);

    private final String path;
    private final boolean authenticates;
    private final boolean carriesDetails;
    private final boolean takesRequestObjects;

    AttestedEndpoint(String path, boolean authenticates, boolean carriesDetails, boolean takesRequestObjects) {
        this.path = path;
        this.authenticates = authenticates;
        this.carriesDetails = carriesDetails;
        this.takesRequestObjects = takesRequestObjects;
    }

    /** The endpoint at {@code path} (servlet path and path info), {@link #OTHER} for any other. */
    static AttestedEndpoint of(String path) {
        for (AttestedEndpoint e : values()) {
            if (e.path != null && e.path.equals(path)) {
                return e;
            }
        }
        return OTHER;
    }

    /** The path PingFederate serves this endpoint at, or null for {@link #OTHER}. */
    String path() {
        return this.path;
    }

    /** Whether a client authenticates here, so an attestation is verified and bridged. */
    boolean authenticates() {
        return this.authenticates;
    }

    /** Whether a request here can carry {@code authorization_details} that PingFederate issues or stores. */
    boolean carriesDetails() {
        return this.carriesDetails;
    }

    /** Whether a request here can carry a signed request object ({@code request}) whose details PingFederate reads. */
    boolean takesRequestObjects() {
        return this.takesRequestObjects;
    }
}
