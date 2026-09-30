/*
 * At the authorization endpoint: an attestation-required client's authorization_details come through PAR or not at all.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationEvents;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyException;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationPolicy;
import com.pingidentity.ps.oidf.servlet.oauth.FederationErrorPage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An authorization request that did not come through PAR carries no attestation - the front channel has no place for
 * one - so the details it asks for are held to nothing. For a client that authenticates only with an attestation
 * ({@code attestation_required}), that is a way round the ceiling: PingFederate would store the details at the
 * authorization endpoint and issue them at the token endpoint whatever the token request says (U-0019). Such a request
 * is refused here when it carries {@code authorization_details}, a request object ({@code request}) with them or one
 * this filter cannot read, or a {@code request_uri} that is not a PAR reference (a request object by reference, which
 * this filter never dereferences). The same client's details pushed at PAR, where its attestation is verified and its
 * details are held to it, are unaffected; so is a request with none.
 *
 * <p>The refusal is a page, never a redirect: the request has not been authenticated, and a redirect would send the
 * error to a redirect URI nothing has vouched for - the front-channel registration filter answers OpenID Federation
 * 1.0 §12.1.3 the same way ({@link FederationErrorPage}). No attestation is verified here.
 */
final class PushedDetailsRule {
    private static final Log LOGGER = LogFactory.getLog(PushedDetailsRule.class);

    /** How PingFederate 13.1.3 spells the request_uri PAR returns (seen on the rig, 2026-09-30); RFC 9126 §2.2's example. */
    static final String PAR_REFERENCE_PREFIX = "urn:ietf:params:oauth:request_uri:";
    /** The error the page shows. */
    static final String ERROR = "invalid_request";
    /** What the page tells the End-User, and the client, it was. */
    static final String DESCRIPTION = "this client must send authorization_details in a pushed authorization request (PAR)";

    private final AttestationPolicyResolver policies;
    private final Supplier<FederationErrorPage> page;

    PushedDetailsRule(AttestationPolicyResolver policies, Supplier<FederationErrorPage> page) {
        this.policies = policies;
        this.page = page;
    }

    /**
     * Refuses {@code request} with a page when it names an attestation-required client and asks for details the
     * attestation was never held to; a client whose {@code attestation_required} cannot be read is refused too, and a
     * client manager that cannot answer is 503. A request that asks for none is never looked up.
     *
     * @return whether the request was refused
     */
    boolean refused(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!asksForUnpushedDetails(request)) {
            return false;
        }
        for (String clientId : namedClients(request)) {
            ClientAttestationPolicy client;
            try {
                client = this.policies.policy(clientId);
                if (client.invalid() != null && ClientAttestationPolicy.REQUIRED.equals(client.invalid().property())) {
                    throw client.invalid();
                }
            } catch (AttestationPolicyException e) {
                AttestationEvents.policyInvalid(AttestationEvents.FILTER, e);
                this.refuse(response, e.clientId(), 400, ERROR, AttestationPolicyException.CLIENT_DESCRIPTION);
                return true;
            } catch (AttestationPolicyResolver.Unavailable e) {
                LOGGER.warn((Object) ("attest_jwt_client_auth: " + e.getMessage()), e.getCause());
                this.refuse(response, clientId, 503, "temporarily_unavailable", "the client's attestation policy could not be read");
                return true;
            }
            if (client.attestationRequired()) {
                LOGGER.info((Object) ("attest_jwt_client_auth: client_id=" + LogSafe.value(clientId) + " has "
                        + ClientAttestationPolicy.REQUIRED + "=true and sent authorization_details to the authorization"
                        + " endpoint without PAR; refused with a page"));
                this.refuse(response, clientId, 400, ERROR, DESCRIPTION);
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the request asks for details that did not come through PAR: an {@code authorization_details} parameter
     * (blank is absent), a request object that carries the claim or cannot be read, or a {@code request_uri} that is not
     * a PAR reference.
     */
    static boolean asksForUnpushedDetails(HttpServletRequest request) {
        String details = request.getParameter(GrantedDetails.PARAMETER);
        if (details != null && !details.isBlank()) {
            return true;
        }
        String requestObject = request.getParameter("request");
        if (requestObject != null && !requestObject.isBlank()) {
            Map<?, ?> claims = GrantedDetails.payload(requestObject);
            if (claims == null || claims.get(GrantedDetails.PARAMETER) != null) {
                return true;
            }
        }
        String requestUri = request.getParameter("request_uri");
        return requestUri != null && !requestUri.isBlank() && !requestUri.startsWith(PAR_REFERENCE_PREFIX);
    }

    /**
     * The clients the request names, unverified, in order and without repeats: its {@code client_id}, and a readable
     * request object's {@code client_id} and {@code iss}. Whichever PingFederate goes on to serve is among them; each
     * extra name can only refuse.
     */
    static Set<String> namedClients(HttpServletRequest request) {
        Set<String> ids = new LinkedHashSet<>();
        add(ids, request.getParameter("client_id"));
        Map<?, ?> claims = GrantedDetails.payload(request.getParameter("request"));
        if (claims != null) {
            add(ids, claims.get("client_id"));
            add(ids, claims.get("iss"));
        }
        return ids;
    }

    private static void add(Set<String> ids, Object id) {
        if (id instanceof String s && !s.isBlank()) {
            ids.add(s);
        }
    }

    private void refuse(HttpServletResponse response, String clientId, int status, String error, String description)
            throws IOException {
        AttestationEvents.refused(AttestationEvents.FILTER, clientId, error);
        this.page.get().write(response, status, error, description, PfTracking.trackingIdOr("oidf"));
    }
}
