/*
 * The authorization_details ClientAttestationAuthFilter forwards to PingFederate, and the request objects it cannot
 * rewrite.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What an attested request's {@code authorization_details} become on the way to PingFederate (plan item S4d, F-0032).
 *
 * <p>PingFederate issues the details stored at PAR and at CIBA's backchannel endpoint, and ignores a token request's
 * {@code authorization_details} on the code and CIBA grants in both directions (the device grant is taken to do the same
 * with what its endpoint stored; not driven, U-0330): on the rig (2026-09-30, 13.1.3, U-0019) a code pushed with {@code sales_agent} [EMEA, AMER] up to 500 and redeemed with [EMEA] up
 * to 100 was issued [EMEA, AMER] up to 500, one pushed with the narrower set and redeemed with the wider was issued the
 * narrower, and CIBA did the same. So the details are held where they arrive: the filter grants
 * {@code authorize(requested, ceiling, INHERIT)} - a constrained field the request leaves out takes the attestation's
 * value, and the grant is within the attestation's details by the model's post-condition - and forwards
 * {@link #forwarded the granted details} in place of the request's, never the request's own.
 *
 * <p>A signed request object cannot be rewritten without breaking its signature, so its details are held to the
 * attestation's as they stand: {@link #requestObjectWithin}, the strict {@code contains}.
 */
final class GrantedDetails {
    /** The RFC 9396 parameter, and the request object claim of the same name. */
    static final String PARAMETER = "authorization_details";
    /** The BFF's principal marker, which the RAR plugin reads only in development; carried over from the request. */
    static final String PRINCIPAL_MARKER = "_principal_sub";
    /** RFC 9101 §7: "invalid_request_object - The request parameter contains an invalid Request Object." */
    static final String INVALID_REQUEST_OBJECT = "invalid_request_object";
    /** The fixed description of a request object whose details are outside the attestation's (the token gate's text). */
    static final String EXCEEDS = "authorization_details exceeds what the client attestation allows";
    /** The fixed description of a request object whose details the model refuses. */
    static final String MALFORMED = "the request object's authorization_details is not one this server accepts";
    /** The fixed description of a request object this filter cannot read. */
    static final String UNREADABLE = "the request object cannot be read to hold its authorization_details to the client attestation";

    private GrantedDetails() {
    }

    /**
     * The {@code authorization_details} text to forward: {@code granted} in order, each with the verified agent under
     * {@link ClientAttestationAuthFilter#AGENT_MARKER} (over anything a client wrote there) and the request's
     * {@value #PRINCIPAL_MARKER}, when the detail at the same place in {@code requested} carried one. The model's
     * canonical JSON: members by name, plain decimals, so the numbers PingFederate stores are the ones the model compared.
     *
     * @param granted   what the token gate granted, one per requested detail and in the request's order
     * @param requested the request's own details, parsed; read only for the principal marker
     * @return the text, or {@code null} when nothing was granted: the parameter is then not forwarded at all
     */
    static String forwarded(List<Map<String, Object>> granted, List<Map<String, Object>> requested, String agentId) {
        if (granted == null || granted.isEmpty()) {
            return null;
        }
        List<Map<String, Object>> out = new ArrayList<>(granted.size());
        for (int i = 0; i < granted.size(); i++) {
            Map<String, Object> detail = new LinkedHashMap<>(granted.get(i));
            detail.remove(ClientAttestationAuthFilter.AGENT_MARKER);
            detail.remove(PRINCIPAL_MARKER);
            Object principal = i < requested.size() ? requested.get(i).get(PRINCIPAL_MARKER) : null;
            if (principal != null) {
                detail.put(PRINCIPAL_MARKER, principal);
            }
            if (agentId != null && !agentId.isBlank()) {
                detail.put(ClientAttestationAuthFilter.AGENT_MARKER, agentId);
            }
            out.add(detail);
        }
        return Json.write(out);
    }

    /**
     * The request's details as the model reads them, for {@link #forwarded}; empty when there are none or they cannot be
     * read (the token gate refused those before this is asked).
     */
    static List<Map<String, Object>> requested(String text) {
        try {
            return RarModels.parseDetails(text);
        } catch (RarModelException e) {
            return List.of();
        }
    }

    /**
     * Holds a signed request object's {@code authorization_details} to the attestation's, strictly: every detail must be
     * within the attestation's as it stands. What the model refuses is RFC 9396 §5's: "The AS MUST abort processing and
     * respond with an error invalid_authorization_details to the client if any of the following are true of the objects
     * in the authorization_details structure". The object is not verified here -
     * PingFederate verifies it against the client's keys - and a failed signature only refuses a request this check let
     * through. A request object with no {@code authorization_details} asks for none and passes.
     *
     * @param models         the model set the filter enforces
     * @param requestObject  the {@code request} parameter
     * @param attestationJwt the verified Client Attestation
     * @throws ClientAttestationException 400 {@code invalid_authorization_details} for details outside the attestation's
     *                                    or ones the model refuses; 400 {@code invalid_request_object} for an object this
     *                                    filter cannot read (an encrypted one, say)
     */
    static void requestObjectWithin(RarModels models, String requestObject, String attestationJwt)
            throws ClientAttestationException {
        List<Map<String, Object>> details = requestObjectDetails(requestObject);
        if (details.isEmpty()) {
            return;
        }
        List<Map<String, Object>> ceiling;
        try {
            ceiling = models.validate(ceilingOf(attestationJwt), "attestation");
        } catch (RarModelException e) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_CLIENT,
                    "the client attestation's authorization_details cannot be evaluated by this server", e);
        }
        boolean within;
        try {
            within = models.contains(ceiling, details);
        } catch (RarModelException e) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, MALFORMED, e);
        }
        if (!within) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, EXCEEDS);
        }
    }

    /**
     * A request object's {@code authorization_details}, read from its payload unverified by the model's own reader (so a
     * decimal is compared as the client wrote it): the claim as a JSON array, or as a string holding one. Empty when the
     * claim is absent.
     *
     * @throws ClientAttestationException {@value #INVALID_REQUEST_OBJECT} when the object is not a compact JWS whose
     *                                    payload is a JSON object; {@code invalid_authorization_details} when the claim is
     *                                    not a list of details
     */
    static List<Map<String, Object>> requestObjectDetails(String requestObject) throws ClientAttestationException {
        Map<?, ?> claims = payload(requestObject);
        if (claims == null) {
            throw new ClientAttestationException(INVALID_REQUEST_OBJECT, UNREADABLE);
        }
        Object claim = claims.get(PARAMETER);
        if (claim == null) {
            return List.of();
        }
        try {
            return claim instanceof String text ? RarModels.parseDetails(text) : RarModels.details(claim);
        } catch (RarModelException e) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, MALFORMED, e);
        }
    }

    /**
     * The attestation's {@code authorization_details}, read from its payload by the model's reader, as the token gate
     * reads them; absent is empty, and nothing is within an empty ceiling.
     */
    static List<Map<String, Object>> ceilingOf(String attestationJwt) throws RarModelException {
        Map<?, ?> claims = payload(attestationJwt);
        if (claims == null) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the client attestation's claims could not be read");
        }
        return claims.containsKey(PARAMETER) ? RarModels.details(claims.get(PARAMETER)) : List.of();
    }

    /** A compact JWS's payload as a JSON object, or null when it is not one (a JWE has five parts, not three). */
    static Map<?, ?> payload(String jws) {
        if (jws == null) {
            return null;
        }
        String[] parts = jws.split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        try {
            Object parsed = Json.parse(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            return parsed instanceof Map<?, ?> map ? map : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
