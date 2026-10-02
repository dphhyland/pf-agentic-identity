/*
 * Who an authorised operator request is from.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import java.util.List;

/**
 * An operator request the authenticator let through, as the surface's own code sees it (the request attribute
 * {@link OperatorAuthenticator#OPERATOR_ATTRIBUTE}).
 *
 * @param actor        who is acting: the token's {@code sub} - for a client-credentials token, the client id. Record
 *                     this, never a header.
 * @param clientId     the token's {@code client_id}, or null when it carries none
 * @param scopes       the token's scopes
 * @param binding      {@code dpop}, {@code mtls}, {@code none} (development only), or {@code static-bearer} (the
 *                     development static bearer)
 * @param claimedLabel the caller's {@code X-Federation-Actor} header, cut to 128 characters and made safe for a log, or
 *                     null: a label the caller chose, which nothing checked
 * @param route        the route it was authorised for
 */
public record Operator(String actor, String clientId, List<String> scopes, String binding, String claimedLabel,
                       OperatorRoute route) {
    public Operator {
        scopes = List.copyOf(scopes);
    }
}
