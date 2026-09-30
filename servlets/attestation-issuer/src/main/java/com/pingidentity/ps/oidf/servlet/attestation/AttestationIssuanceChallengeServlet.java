/*
 * The client attestation service's challenge endpoint (docs/openid-client-attestation-service-1_0.md §4.1).
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.clientattestation.servlet.ChallengeEndpointServlet;
import jakarta.servlet.annotation.WebServlet;

/**
 * The client attestation service's challenge endpoint. CAS §4.1 gives the request as
 * {@code GET /attestation-challenge} and the response as {@code {"attestation_challenge": "...", "expires_in": N}},
 * and says the challenge "freshens the Instance Key Proof presented *to the CAS*" and that "a challenge issued by
 * one party MUST NOT be accepted by the other". A workload {@code GET}s here and puts the value in the
 * {@code challenge} claim of the instance-key proof it sends to {@link AttestationIssuanceServlet}, which consumes
 * it from the same {@code oidf:cas:challenge:*} store, once.
 *
 * <p>The authorization server's endpoint ({@code POST /federation/attestation-challenge}, ABCA-10 §6.1) issues into
 * {@code oidf:as:challenge:*}; neither store knows the other's challenges, so a challenge from one surface is
 * refused at the other. A {@code POST} here answers 405 with {@code Allow: GET}, as does any other method but
 * {@code GET}; see {@link ChallengeEndpointServlet}, which also lists the init-params.
 *
 * <p>Advertised as {@code challenge_endpoint} by {@link ClientAttestationServiceMetadataServlet} (CAS §5.1) and
 * {@link AttesterConfigurationServlet}; the path sits under {@code /federation/attestation}, the issuance
 * endpoint it serves.
 */
// loadOnStartup: its part of ATTESTATION_ISSUER registers at deploy, not on the first request (finding F-0193); its
// init never throws.
@WebServlet(urlPatterns = {AttestationIssuanceChallengeServlet.PATH}, loadOnStartup = 1)
public class AttestationIssuanceChallengeServlet extends ChallengeEndpointServlet {
    private static final long serialVersionUID = 1L;

    /** Where the client attestation service's challenge endpoint is mapped, under the context path. */
    public static final String PATH = "/federation/attestation/challenge";

    public AttestationIssuanceChallengeServlet() {
        super(StoreNamespace.CAS, "GET");
    }
}
