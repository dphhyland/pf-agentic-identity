/*
 * The authorization server's ceiling check: a token or PAR request's authorization_details against the Client
 * Attestation's.
 */
package com.pingidentity.ps.oidf.clientattestation;

import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.Omission;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CAS §7.1 at the authorization server: "an authorization server participating in a deployment of this
 * specification MUST, when authenticating a client via an attestation containing {@code authorization_details},
 * ensure that any authority granted in issued tokens is a subset of the attestation's
 * {@code authorization_details} (same subset semantics as Section 7 rule 1), and MUST reject requests exceeding
 * it with {@code invalid_authorization_details} [RFC9396]."
 *
 * <p>The request's details must be within the attestation's by the model's strict {@link RarModels#contains}:
 * every field of every detail is compared by its type's rule, and a field the attestation constrains and the
 * request leaves out is not contained. The request is not filled in from the attestation, because what this
 * check passes is what PingFederate goes on to issue: the filter forwards the request's own details, so a detail
 * granted here with a field filled in would reach the token without it - wider than the attestation, since a
 * field a detail leaves out constrains nothing. A client restates every field the attestation constrains.
 *
 * <p>A request with no {@code authorization_details} is not checked here. What PingFederate issues from details
 * stored at PAR or at the authorization endpoint is plan item S4d (Phase 3; the plan's "Found while designing"
 * item 3, F-0032).
 *
 * <p>Two names this repository writes into a request's details are taken off before the model is asked, because
 * they are bookkeeping, not authority, and the model refuses both as {@code forbidden}:
 * <ul>
 *   <li>{@value #PRINCIPAL_MARKER}, the principal a BFF folds into a detail. The RAR plugin reads it (only when
 *       "Trust a client-asserted principal" is on) and takes it off itself; PingFederate still receives it.</li>
 *   <li>{@value #AGENT_MARKER}, the agent marker. The token-endpoint filter writes the verified agent into every
 *       detail of the request it forwards, after this check, over whatever a client wrote under that name.</li>
 * </ul>
 * The attestation's own details are not stripped: an attester never writes either name, and a ceiling carrying
 * one is malformed.
 *
 * <p>Every refusal is a {@link ClientAttestationException} with a fixed description - the texts below - and the
 * model's own message as its cause, for the log. The message names the detail and the field and never the value;
 * the description names neither.
 *
 * <table>
 *   <caption>What each refusal answers</caption>
 *   <tr><th>Why</th><th>Error</th><th>Description</th></tr>
 *   <tr><td>not valid JSON, not an array of objects, a value its rule cannot compare, a detail with no type</td>
 *       <td>{@code invalid_authorization_details}</td><td>{@code authorization_details is malformed}</td></tr>
 *   <tr><td>past a size limit</td><td>{@code invalid_authorization_details}</td>
 *       <td>{@code authorization_details exceeds a size limit}</td></tr>
 *   <tr><td>a field the type's model does not declare</td><td>{@code invalid_authorization_details}</td>
 *       <td>{@code authorization_details carries a field its type does not define}</td></tr>
 *   <tr><td>a type no model names</td><td>{@code invalid_authorization_details}</td>
 *       <td>{@code authorization_details names a type this server does not support}</td></tr>
 *   <tr><td>not within the attestation's</td><td>{@code invalid_authorization_details}</td>
 *       <td>{@value #EXCEEDS}</td></tr>
 *   <tr><td>the attestation's own details are ones the model refuses</td><td>{@code invalid_client}</td>
 *       <td>{@value #CEILING_UNUSABLE}</td></tr>
 * </table>
 *
 * <p>RFC 9396 §5 is the first four: "The AS MUST refuse to process any unknown authorization details type or
 * authorization details not conforming to the respective type definition." §6 is the fifth, at the token
 * endpoint: "Otherwise, the AS refuses the request with the error code invalid_authorization_details (similar to
 * invalid_scope)." The last is the attestation's fault, not the request's - the attester wrote details this
 * server has no model for, or the two disagree about a type - so it is the credential that is refused.
 */
final class AuthorizationDetailsGate {
    /** The client-asserted principal a BFF folds into a detail (the RAR plugin's {@code PRINCIPAL_DETAIL_KEY}). */
    static final String PRINCIPAL_MARKER = "_principal_sub";
    /**
     * The verified agent the token-endpoint filter writes into every detail it forwards (its {@code AGENT_MARKER},
     * the RAR plugin's {@code AGENT_DETAIL_KEY}).
     */
    static final String AGENT_MARKER = "_agent_id";
    /** The description of a request that is well formed and not within the attestation's details. */
    static final String EXCEEDS = "authorization_details exceeds what the client attestation allows";
    /** The description of an attestation whose own details the model refuses. */
    static final String CEILING_UNUSABLE =
            "the client attestation's authorization_details cannot be evaluated by this server";
    private static final String CLAIM = "authorization_details";

    private AuthorizationDetailsGate() {
    }

    /**
     * Checks a request's {@code authorization_details} against the attestation's.
     *
     * @param models         the model set this classloader enforces
     * @param requested      the request parameter's text, or {@code null}
     * @param attestationJwt the Client Attestation, already verified: its payload is read again here by the
     *                       model's own reader, so its numbers are compared exactly as the attester wrote them
     * @return the details granted: the request's own, in its order, without the two markers; empty when the
     *         request asks for none
     * @throws ClientAttestationException {@code invalid_authorization_details} for a request the model refuses
     *                                    or finds outside the attestation's details; {@code invalid_client} for
     *                                    an attestation whose details the model refuses
     */
    static List<Map<String, Object>> check(RarModels models, String requested, String attestationJwt)
            throws ClientAttestationException {
        List<Map<String, Object>> candidate;
        try {
            candidate = withoutMarkers(RarModels.parseDetails(requested));
        } catch (RarModelException e) {
            throw refused(e);
        }
        if (candidate.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> ceiling;
        try {
            ceiling = models.validate(ceilingOf(attestationJwt), "attestation");
        } catch (RarModelException e) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_CLIENT, CEILING_UNUSABLE, e);
        }
        boolean within;
        try {
            within = models.contains(ceiling, candidate);
        } catch (RarModelException e) {
            // The attestation's details passed the same check a moment ago, so this is the request's.
            throw refused(e);
        }
        if (!within) {
            throw new ClientAttestationException(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, EXCEEDS,
                    whyNotWithin(models, ceiling, candidate));
        }
        return candidate;
    }

    /**
     * Which detail is not within the attestation's, for the log line: the model's own refusal from a strict
     * {@code authorize} over the same lists, which names the first such detail and its type and never a value.
     * Asked only after {@code contains} has said no, so it refuses; the decision is {@code contains}'s.
     */
    static RarModelException whyNotWithin(RarModels models, List<Map<String, Object>> ceiling,
                                          List<Map<String, Object>> candidate) {
        RarModelException why = new RarModelException(RarModelException.Reason.EXCEEDS_CEILING,
                "authorization_details is not within the client attestation's");
        try {
            models.authorize(candidate, ceiling, Omission.STRICT);
        } catch (RarModelException e) {
            why = e;
        }
        return why;
    }

    /** Copies of the details without {@value #PRINCIPAL_MARKER} and {@value #AGENT_MARKER}. */
    static List<Map<String, Object>> withoutMarkers(List<Map<String, Object>> details) {
        List<Map<String, Object>> out = new ArrayList<>(details.size());
        for (Map<String, Object> detail : details) {
            Map<String, Object> copy = new LinkedHashMap<>(detail);
            copy.remove(PRINCIPAL_MARKER);
            copy.remove(AGENT_MARKER);
            out.add(copy);
        }
        return out;
    }

    /**
     * The attestation's {@code authorization_details}, read from its payload by the model's reader rather than
     * taken from jose4j's parse, which reads a decimal as a {@code double} and drops a list entry that is not an
     * object: the ceiling is compared as the attester wrote it, and an entry that is not a detail is refused, not
     * skipped. Absent is empty, and nothing is within an empty ceiling.
     */
    static List<Map<String, Object>> ceilingOf(String attestationJwt) throws RarModelException {
        String[] parts = attestationJwt.split("\\.", -1);
        if (parts.length != 3) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the client attestation is not a compact JWS");
        }
        Object claims;
        try {
            claims = Json.parse(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        } catch (Json.TooLarge e) {
            throw new RarModelException(RarModelException.Reason.TOO_LARGE,
                    "the client attestation's claims are too large to read: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new RarModelException(RarModelException.Reason.MALFORMED,
                    "the client attestation's claims could not be read: " + e.getMessage());
        }
        if (!(claims instanceof Map<?, ?> set)) {
            throw new RarModelException(RarModelException.Reason.MALFORMED,
                    "the client attestation's claims are not a JSON object");
        }
        return set.containsKey(CLAIM) ? RarModels.details(set.get(CLAIM)) : List.of();
    }

    /** A request the model refused, as the error the token endpoint answers with. */
    static ClientAttestationException refused(RarModelException e) {
        return new ClientAttestationException(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS,
                describe(e.reason()), e);
    }

    /** The fixed description of a refusal: what was wrong, never where or with what value. */
    static String describe(RarModelException.Reason reason) {
        switch (reason) {
            case TOO_LARGE:
                return "authorization_details exceeds a size limit";
            case UNDECLARED_FIELD:
                return "authorization_details carries a field its type does not define";
            case UNMODELLED_TYPE:
                return "authorization_details names a type this server does not support";
            case EXCEEDS_CEILING:
                return EXCEEDS;
            default:
                // MALFORMED; MODEL_INVALID comes only from loading a models document, never from a request.
                return "authorization_details is malformed";
        }
    }
}
