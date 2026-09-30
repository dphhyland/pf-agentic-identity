/*
 * What a caller that has not authenticated is told when it is refused, and how the detail is found again.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The public side of every refusal written to a caller that has not authenticated - the token, PAR and CIBA
 * endpoints before the client is verified, registration, and the federation endpoints (plan item H-FED-4, finding
 * F-0046). The caller is told two things: a description taken from a fixed list by error code ({@link #generic}),
 * and a correlation id. The detail - which can hold a trust chain's messages, a JWT's claims or a URL the request
 * named, all chosen by a peer - goes to {@code server.log} on one line that carries the same id, and never into the
 * response.
 *
 * <p>The correlation id is PingFederate's tracking id when the request thread has one ({@link PfTracking}), so that
 * the line lines up with PingFederate's own for the request; otherwise a generated {@code oidf-<8 hex>}. Checked on
 * the rig on 2026-10-01 (PingFederate 13.1.3): the tracking id is on the thread inside PingFederate's own processing
 * (an OGNL issuance criterion) but not yet when this module's filters over {@code /as/token.oauth2} and
 * {@code /idp/userinfo.openid} run, so a refusal there carries a generated id.
 *
 * <p>An operator authenticated by {@code OperatorAuthenticator} is not a caller this class is for: its responses
 * keep their detail ({@code FederationErrors.writeToOperator}).
 */
public final class PublicErrors {
    private static final Log LOGGER = LogFactory.getLog(PublicErrors.class);

    /** The prefix of a correlation id this module generated rather than read from PingFederate. */
    static final String GENERATED_PREFIX = "oidf";

    /** The description of an error code the list does not name. */
    static final String DEFAULT = "The request was refused";

    /**
     * One fixed description per error code - the codes of RFC 6749, RFC 6750, RFC 7591, RFC 9396, RFC 9449, OpenID
     * Federation 1.0 and the attestation-based client authentication draft that this module's refusals use. None names
     * a value from the request.
     */
    private static final Map<String, String> GENERIC = Map.ofEntries(
            Map.entry("invalid_request", "The request is missing a parameter, repeats one, or is otherwise malformed"),
            Map.entry("invalid_client", "Client authentication failed"),
            Map.entry("invalid_grant", "The grant is invalid, expired or revoked"),
            Map.entry("unauthorized_client", "The client is not authorised to make this request"),
            Map.entry("unsupported_grant_type", "The grant type is not supported"),
            Map.entry("invalid_scope", "The requested scope is invalid"),
            Map.entry("access_denied", "The request was denied"),
            Map.entry("invalid_token", "The access token is invalid"),
            Map.entry("insufficient_scope", "The access token does not allow this request"),
            Map.entry("invalid_dpop_proof", "The DPoP proof is invalid"),
            Map.entry("use_dpop_nonce", "The DPoP proof must carry the server's nonce"),
            Map.entry("invalid_authorization_details", "The authorization_details are invalid or not permitted"),
            Map.entry("invalid_request_object", "The request object is invalid"),
            Map.entry("use_attestation_challenge", "The client attestation proof must carry a current challenge"),
            Map.entry("use_fresh_attestation", "The client attestation must be renewed"),
            Map.entry("insufficient_disclosure", "The client attestation does not disclose what this request needs"),
            Map.entry("invalid_client_metadata", "The client metadata is invalid"),
            Map.entry("invalid_redirect_uri", "A redirect URI is invalid"),
            Map.entry("invalid_software_statement", "The software statement is invalid"),
            Map.entry("unapproved_software_statement", "The software statement is not approved"),
            Map.entry("invalid_issuer", "The issuer is not known here"),
            Map.entry("invalid_subject", "The subject is not known here"),
            Map.entry("invalid_trust_anchor", "The trust anchor is not one this server accepts"),
            Map.entry("invalid_trust_chain", "No valid trust chain was found"),
            Map.entry("invalid_metadata", "The metadata is invalid"),
            Map.entry("not_found", "The requested resource was not found"),
            Map.entry("unsupported_parameter", "A parameter is not supported"),
            Map.entry("server_error", "The server encountered an unexpected condition"),
            Map.entry("temporarily_unavailable", "The service is temporarily unavailable; try again later"));

    private PublicErrors() {
    }

    /** The fixed description of {@code error}, or {@link #DEFAULT} for a code the list does not name. */
    public static String generic(String error) {
        String text = error == null ? null : GENERIC.get(error);
        return text == null ? DEFAULT : text;
    }

    /** PingFederate's tracking id for this request thread, or a generated {@code oidf-<8 hex>}. */
    public static String correlationId() {
        return PfTracking.trackingIdOr(GENERATED_PREFIX);
    }

    /** What the caller reads: {@code error}'s fixed description and the correlation id to quote. */
    public static String description(String error, String correlationId) {
        return generic(error) + " (reference " + correlationId + ")";
    }

    /**
     * Logs the refusal's {@code detail} under {@code correlationId} - INFO for a refusal, WARN for a server error - and
     * returns what the caller is told. {@code where} names the endpoint or filter for the log line.
     */
    public static String refused(String where, int status, String error, String detail, String correlationId) {
        String line = where + " refused a request: ref=" + correlationId + " status=" + status + " error="
                + LogSafe.value(error) + " detail=" + LogSafe.quoted(String.valueOf(detail));
        if (status >= 500) {
            LOGGER.warn((Object) line);
        } else {
            LOGGER.info((Object) line);
        }
        return description(error, correlationId);
    }
}
