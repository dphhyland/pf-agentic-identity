/*
 * Who the PDP decides about, per OAuth flow, from what PingFederate 13.1.3 hands the processor.
 */
package com.pingidentity.ps.oidf.rar;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Resolves the decision's principal and labels how it was established, the {@code principal_source} the PDP
 * receives. The label is the point: {@code AuthorizationDetailContext.getUserKey()} is not a person in
 * every flow, and a policy that cannot tell the flows apart trusts whatever the key happens to be.
 *
 * <p>What PingFederate 13.1.3 passes as the user key, read with javap from {@code pf-protocolengine}
 * (2026-09-27; the callers of {@code AuthorizationDetailsUtil.enrich}):
 * <ul>
 *   <li>client credentials ({@code ClientCredentialsGrantProcessor}): the client id - so the source is
 *       {@link #CLIENT}, and the key is not a user.</li>
 *   <li>refresh ({@code RefreshTokenGrantProcessor}): the grant's {@code getUniqueUserIdentifer()} - the person
 *       who authorised the grant, {@link #AUTHENTICATED} via refresh.</li>
 *   <li>CIBA ({@code CibaAuthenticationRequestHandler}, at {@code /as/bc-auth.ciba}): the
 *       {@code IDENTITY_HINT_SUBJECT} the request policy mapped from the hint - {@link #IDENTITY_HINT}: who
 *       the client says it is asking, before that person has approved anything.</li>
 *   <li>token exchange ({@code TokenExchangeRequest}): {@code null}, and enrich is skipped altogether when the
 *       requested token type is {@code id-jag}. The subject token's subject is used only when the
 *       token-endpoint filter has verified it and published it ({@link AttestationSubject#VERIFIED_SUBJECT_TOKEN_KEY}):
 *       {@link #SUBJECT_TOKEN}, else {@link #NONE}.</li>
 *   <li>the authorization endpoint (code, with or without PAR) and every other flow with a non-blank key:
 *       the authenticated subject, {@link #AUTHENTICATED}. The code and JWT-bearer grant processors never call
 *       enrich.</li>
 * </ul>
 *
 * <p>Two caller-supplied names, the {@code login_hint} parameter and the {@code _principal_sub} marker a
 * front-end folds into {@code authorization_details}, are {@link #CLIENT_ASSERTED}: honoured only when the
 * resolution above found nobody, the operator switched it on, AND the deployment profile is development.
 * Everything in this class is a pure function of its arguments, so each flow is a unit test.
 */
final class PrincipalResolver {

    static final String AUTHENTICATED = "authenticated";
    static final String CLIENT = "client";
    static final String IDENTITY_HINT = "identity_hint";
    static final String SUBJECT_TOKEN = "subject_token";
    static final String CLIENT_ASSERTED = "client_asserted";
    static final String NONE = "none";

    static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    static final String GRANT_REFRESH_TOKEN = "refresh_token";
    static final String GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    /** PingFederate's backchannel authentication endpoint, the one request whose user key is a hint. */
    static final String CIBA_PATH_SUFFIX = "/bc-auth.ciba";

    private PrincipalResolver() { }

    /** The principal and how it was established. {@code subject} is {@code null} exactly when the source is {@link #NONE}. */
    record Principal(String subject, String source) {

        boolean isNone() { return NONE.equals(source); }
    }

    /**
     * What the request tells us about the flow: the {@code grant_type} parameter at the token endpoint, and
     * whether this is the CIBA backchannel endpoint. Both are read off the servlet request by the processor;
     * kept as plain strings here so the resolution is testable without one.
     */
    record Flow(String grantType, String requestPath) {

        static final Flow UNKNOWN = new Flow(null, null);

        boolean isClientCredentials() { return GRANT_CLIENT_CREDENTIALS.equals(grantType); }
        boolean isRefresh() { return GRANT_REFRESH_TOKEN.equals(grantType); }
        boolean isTokenExchange() { return GRANT_TOKEN_EXCHANGE.equals(grantType); }
        boolean isCiba() { return requestPath != null && requestPath.endsWith(CIBA_PATH_SUFFIX); }
    }

    /**
     * @param flow           the flow, from the request
     * @param userKey        {@code AuthorizationDetailContext.getUserKey()}, as PingFederate passed it
     * @param clientId       {@code AuthorizationDetailContext.getClientId()}
     * @param subject        the verified attestation context, for the subject-token subject
     * @param clientAsserted the caller's own name for the principal ({@code login_hint} or {@code _principal_sub}),
     *                       or {@code null}
     * @param honourClientAsserted whether {@code clientAsserted} may be used at all: the switch AND the
     *                       development profile ({@link GovernanceEngineConfig#isClientAssertedPrincipalHonoured()})
     */
    static Principal resolve(Flow flow, String userKey, String clientId, AttestationSubject subject,
                             String clientAsserted, boolean honourClientAsserted) {
        Principal resolved = fromPingFederate(flow == null ? Flow.UNKNOWN : flow, userKey, clientId,
                subject == null ? AttestationSubject.empty() : subject);
        if (resolved.isNone() && honourClientAsserted && notBlank(clientAsserted)) {
            return new Principal(clientAsserted, CLIENT_ASSERTED);
        }
        return resolved;
    }

    private static Principal fromPingFederate(Flow flow, String userKey, String clientId, AttestationSubject subject) {
        if (flow.isTokenExchange()) {
            String verified = subject.getVerifiedSubjectTokenSubject();
            return notBlank(verified) ? new Principal(verified, SUBJECT_TOKEN) : new Principal(null, NONE);
        }
        // The client id as user key: what client credentials passes, and what no person is. Checked by
        // grant type and by value, so a client-only flow this list does not know cannot pass its client
        // off as a user either.
        if (flow.isClientCredentials() || (notBlank(userKey) && userKey.equals(clientId))) {
            return new Principal(clientId, CLIENT);
        }
        if (!notBlank(userKey)) {
            return new Principal(null, NONE);
        }
        if (flow.isCiba()) {
            return new Principal(userKey, IDENTITY_HINT);
        }
        // Refresh (the grant's user) and the authorization endpoint (the authenticated subject) alike.
        return new Principal(userKey, AUTHENTICATED);
    }

    /**
     * Whether a detail of this type may be decided at all with this principal: a type on the
     * authenticated-principal list is refused before any PDP call when the principal is nobody, or is the
     * client. A hint, a verified subject token and a development-only asserted name pass; the label goes to
     * the PDP with them so policy can be stricter still.
     */
    static boolean requiresAuthenticatedPrincipal(String type, Principal principal, java.util.Set<String> types) {
        if (type == null || types == null || !types.contains(type)) {
            return false;
        }
        return principal == null || principal.isNone() || CLIENT.equals(principal.source());
    }

    /**
     * The first sixteen hex characters of the SHA-256 of a principal, for log lines: a user key is a person,
     * and PingFederate's server log is not the place for one. Two log lines about the same person still
     * match; {@code null} logs as {@code -}.
     */
    static String hashForLog(String principal) {
        if (principal == null) {
            return "-";
        }
        byte[] digest = sha256().digest(principal.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder(16);
        for (int i = 0; i < 8; i++) {
            hex.append(String.format("%02x", digest[i]));
        }
        return "sha256:" + hex;
    }

    /** SHA-256 is an algorithm every Java platform must provide; the checked exception has no reachable path. */
    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is a required JDK algorithm", e);
        }
    }

    private static boolean notBlank(String v) {
        return v != null && !v.isBlank();
    }
}
