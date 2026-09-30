/*
 * The authorization server's attestation challenge endpoint (draft-ietf-oauth-attestation-based-client-auth-10 §6.1).
 */
package com.pingidentity.ps.oidf.clientattestation.servlet;

import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;

/**
 * The authorization server's challenge endpoint. ABCA-10 §6.1 has the client fetch a challenge by "sending an HTTP
 * POST request to the URL provided in the challenge_endpoint parameter" of the authorization server's metadata
 * (read 2026-09-27; draft -11 says the same). A client {@code POST}s here (no body required) and receives
 * {@code {"attestation_challenge": "...", "expires_in": N}} with {@code Cache-Control: no-store}. It echoes the
 * value in the {@code challenge} claim of a Client Attestation PoP JWT, or the {@code nonce} of a combined-mode
 * DPoP proof, at the token endpoint; {@link AttestationSupport} shares the {@code oidf:as:challenge:*} store with
 * the token-endpoint filter and the issuance-criteria hook that consume it.
 *
 * <p>The client attestation service has an endpoint of its own ({@code GET /federation/attestation/challenge}),
 * issuing into {@code oidf:cas:challenge:*}: a challenge from here is unknown to the attester, and one from there
 * is unknown to the token endpoint (CAS §4.1). A {@code GET} here answers 405 with {@code Allow: POST}, as does any
 * other method but {@code POST}; see {@link ChallengeEndpointServlet}.
 *
 * <p>Advertised as {@code challenge_endpoint} in the OP metadata of the federation Entity Configuration. Besides
 * the endpoint's own init-params, {@code replayCacheMaxEntries} sizes the authorization server's in-memory replay
 * cache.
 */
@WebServlet(urlPatterns = {ClientAttestationChallengeServlet.PATH})
public class ClientAttestationChallengeServlet extends ChallengeEndpointServlet {
    private static final long serialVersionUID = 1L;

    /** Where the authorization server's challenge endpoint is mapped, under the context path. */
    public static final String PATH = "/federation/attestation-challenge";

    public ClientAttestationChallengeServlet() {
        super(StoreNamespace.AS, "POST");
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String replayMax = config.getInitParameter("replayCacheMaxEntries");
        if (replayMax != null && !replayMax.isBlank()) {
            try {
                AttestationSupport.configureReplayCache(Integer.parseInt(replayMax.trim()));
            } catch (NumberFormatException e) {
                org.apache.commons.logging.LogFactory.getLog(ClientAttestationChallengeServlet.class)
                        .warn((Object) ("Ignoring non-integer servlet parameter value: " + replayMax));
            }
        }
    }
}
