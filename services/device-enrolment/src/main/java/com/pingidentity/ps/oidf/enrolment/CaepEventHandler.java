/*
 * Applies inbound CAEP signals to the instance registry.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache;
import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.RegistryException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Turns a verified CAEP Security Event Token into a change in the instance registry.
 *
 * <p>This is what closes the loop: a device falls out of compliance, the signal arrives, every agent
 * instance on that device is suspended, and the next token request fails — without the agent
 * re-authenticating, without waiting for its attestation to expire, and without reaching the device.
 *
 * <p>Handled, with the event-specific claims verified against CAEP 1.0 Final:
 *
 * <table><caption>Events</caption>
 *   <tr><td>{@code device-compliance-change}</td>
 *       <td>{@code previous_status}, {@code current_status} — both required, each
 *           {@code compliant} or {@code not-compliant}</td></tr>
 *   <tr><td>{@code session-revoked}</td><td>no event-specific claims</td></tr>
 *   <tr><td>{@code credential-change}</td>
 *       <td>{@code credential_type}, {@code change_type}; only a revoked
 *           {@code fido2-platform} credential is acted on</td></tr>
 * </table>
 *
 * <p><strong>Verification is the caller's job.</strong> This class applies an event it is told is
 * genuine. Signature, issuer, audience and freshness belong at the transport edge, and passing an
 * unverified SET here would let anyone suspend anyone. The one thing it does own is replay: SETs are
 * redelivered by design in SSF, so {@code jti} is checked here where the registry side effects are.
 *
 * <p>The event-type dispatch and JSON decoding are this class's own; the actual registry mutation for
 * each event is {@link CaepSignalApplier}, shared with {@code servlets/ssf}'s SSF receiver so the two
 * transports (this endpoint's direct SET POST, and an SSF push/poll delivery) apply CAEP identically.
 */
public final class CaepEventHandler {

    private static final Log LOGGER = LogFactory.getLog(CaepEventHandler.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    /** Redelivery is normal in SSF; this bounds how long a repeat is recognised as one. */
    private static final long JTI_TTL_SECONDS = 3600L;

    private final CaepSignalApplier applier;
    private final AttestationReplayCache seenEvents;

    public CaepEventHandler(InstanceRegistry registry, AttestationReplayCache seenEvents) {
        this.applier = new CaepSignalApplier(Objects.requireNonNull(registry, "registry"));
        this.seenEvents = Objects.requireNonNull(seenEvents, "seenEvents");
    }

    /**
     * Applies a verified SET.
     *
     * @param setClaims the decoded, already-verified Security Event Token claims
     * @return what changed, for the transmitter's acknowledgement and the audit log
     */
    public Outcome apply(JsonNode setClaims) throws EnrolmentException {
        if (setClaims == null || !setClaims.isObject()) {
            throw EnrolmentException.invalidRequest("the security event token is not a JSON object");
        }
        String jti = text(setClaims, "jti");
        if (jti == null) {
            throw EnrolmentException.invalidRequest("the security event token has no jti");
        }
        // Redelivery is expected. Recognising it keeps the audit log honest about what actually
        // happened, rather than recording the same suspension five times.
        if (!this.seenEvents.firstSeen("caep", jti, JTI_TTL_SECONDS)) {
            LOGGER.info((Object) ("CAEP event " + jti + " already applied; ignoring redelivery"));
            return new Outcome(jti, List.of(), true);
        }

        JsonNode events = setClaims.get("events");
        if (events == null || !events.isObject() || events.isEmpty()) {
            throw EnrolmentException.invalidRequest("the security event token carries no events");
        }

        List<String> applied = new ArrayList<>();
        events.fields().forEachRemaining(entry -> {
            try {
                applied.addAll(applyOne(entry.getKey(), entry.getValue()));
            } catch (EnrolmentException | RegistryException e) {
                // One bad event must not discard the others in the same SET.
                LOGGER.warn((Object) ("CAEP event " + entry.getKey() + " in " + jti
                        + " could not be applied: " + e.getMessage()));
            }
        });
        return new Outcome(jti, List.copyOf(applied), false);
    }

    private List<String> applyOne(String eventType, JsonNode event)
            throws EnrolmentException, RegistryException {
        return switch (eventType.substring(eventType.lastIndexOf('/') + 1)) {
            case "device-compliance-change" -> deviceComplianceChange(event);
            case "session-revoked" -> sessionRevoked(event);
            case "credential-change" -> credentialChange(event);
            default -> {
                LOGGER.info((Object) ("CAEP event type not acted on: " + eventType));
                yield List.of();
            }
        };
    }

    /** The milestone's loop: compliance drops, every instance on the device stops minting. */
    private List<String> deviceComplianceChange(JsonNode event)
            throws EnrolmentException, RegistryException {
        String deviceId = subjectIdentifier(event);
        if (deviceId == null) {
            throw EnrolmentException.invalidRequest("device-compliance-change has no usable subject");
        }
        String current = text(event, "current_status");
        if (current == null) {
            // Required by CAEP 1.0. Without it we cannot tell which direction the change went, and
            // guessing "compliant" would be the dangerous guess.
            throw EnrolmentException.invalidRequest(
                    "device-compliance-change has no current_status");
        }
        return this.applier.deviceComplianceChange(deviceId, current);
    }

    /**
     * A revoked session takes the agent instances with it. The subject may name a device directly, or —
     * unlike {@code device-compliance-change} and {@code credential-change}, which are only ever
     * device-scoped — the human whose session it was, in which case every instance on every device they
     * own is revoked. Mirrors {@code servlets/ssf}'s {@code ReceiverActionHandler.userKeyOf} so both
     * CAEP transports resolve a human subject the same way.
     */
    private List<String> sessionRevoked(JsonNode event) throws EnrolmentException, RegistryException {
        JsonNode subject = event.get("subject");
        String format = subject != null && subject.isObject() ? text(subject, "format") : null;
        // opaque (or no format at all, the shape every existing device-scoped test and caller uses) is
        // device-scoped; anything else that names a human falls through to the owner-scoped path below.
        if (subject != null && (subject.isTextual() || format == null || "opaque".equals(format))) {
            String deviceId = subjectIdentifier(event);
            if (deviceId != null) {
                return this.applier.sessionRevokedForDevice(deviceId);
            }
        }
        String ownerKey = ownerSubjectIdentifier(subject, format);
        if (ownerKey != null) {
            return this.applier.sessionRevokedForOwner(ownerKey);
        }
        throw EnrolmentException.invalidRequest("session-revoked has no usable subject");
    }

    /**
     * RFC 9493 owner-identifying subject formats: {@code iss_sub} → {@code sub}, {@code email} → the
     * address, {@code phone_number} → the number, {@code account} → {@code uri}. Mirrors
     * {@code servlets/ssf}'s {@code ReceiverActionHandler.userKeyOf} so both CAEP transports resolve a
     * human subject identically. Device-scoped formats ({@code opaque}, or no format at all) are
     * handled by {@link #subjectIdentifier} instead — this only resolves formats that name a human.
     */
    private static String ownerSubjectIdentifier(JsonNode subject, String format) {
        if (subject == null || format == null) {
            return null;
        }
        return switch (format) {
            case "iss_sub" -> text(subject, "sub");
            case "email" -> text(subject, "email");
            case "phone_number" -> text(subject, "phone_number");
            case "account" -> text(subject, "uri");
            default -> null;
        };
    }

    /**
     * A revoked platform passkey invalidates the binding it authorised. Only {@code revoke} and
     * {@code delete} act — a {@code create} is somebody adding a second authenticator, not losing one.
     */
    private List<String> credentialChange(JsonNode event) throws EnrolmentException, RegistryException {
        String deviceId = subjectIdentifier(event);
        if (deviceId == null) {
            return List.of();
        }
        return this.applier.credentialChange(deviceId, text(event, "change_type"), text(event, "credential_type"));
    }

    /**
     * Reads the subject. RFC 9493 allows several formats; the ones that reach us carry the registry's
     * own device identifier, so {@code opaque} and a bare {@code sub} are both accepted.
     */
    private static String subjectIdentifier(JsonNode event) {
        JsonNode subject = event.get("subject");
        if (subject == null) {
            return null;
        }
        if (subject.isTextual()) {
            return subject.asText();
        }
        for (String field : new String[]{"id", "sub", "uri"}) {
            String value = text(subject, field);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    /** Parses a SET body that has already been verified elsewhere. */
    public static JsonNode parseClaims(String json) throws EnrolmentException {
        try {
            return JSON.readTree(json);
        } catch (Exception e) {
            throw EnrolmentException.invalidRequest("the security event token is not valid JSON");
        }
    }

    /** What an inbound event actually changed. */
    public record Outcome(String jti, List<String> affectedInstances, boolean duplicate) {
    }
}
