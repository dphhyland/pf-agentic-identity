/*
 * Maps verified inbound CAEP SETs to agent-instance registry changes.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.RegistryException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The {@link SsfReceiverService.ReceivedSetHandler} that turns inbound CAEP signals into agent-instance
 * registry changes: {@code device-compliance-change} suspends every active instance on the device that
 * fell out of compliance, {@code session-revoked} revokes every instance on the named device (or, for a
 * user-scoped subject, on every device that user owns), and {@code credential-change} revokes instances
 * bound by a passkey that was itself revoked or deleted.
 *
 * <p>The event-type dispatch mirrors {@link ReceiverActionHandler} (the sibling handler that revokes PF
 * OAuth grants for the same signals); the registry mutation itself is {@link CaepSignalApplier}, shared
 * with {@code services/device-enrolment}'s direct compliance endpoint so both transports apply CAEP
 * identically. Best-effort like {@link ReceiverActionHandler}: action failures are logged, never thrown
 * — a broken instance action must not fail grant revocation or cause SET redelivery loops.
 */
public final class InstanceRegistryReceiverHandler implements SsfReceiverService.ReceivedSetHandler {

    private static final Log LOGGER = LogFactory.getLog(InstanceRegistryReceiverHandler.class);

    private final CaepSignalApplier applier;

    public InstanceRegistryReceiverHandler(CaepSignalApplier applier) {
        this.applier = Objects.requireNonNull(applier, "applier");
    }

    @Override
    public void onSet(ReceivedSet set) {
        SubjectId subject = set.subjectId();
        if (subject == null) {
            return; // e.g. a verification event — nothing to resolve
        }
        for (String eventType : set.events().keySet()) {
            String shortType = shortType(eventType);
            if (!isHandled(shortType)) {
                continue;
            }
            try {
                List<String> affected = applyOne(shortType, subject, set.eventPayload(eventType));
                if (!affected.isEmpty()) {
                    LOGGER.info((Object) ("SSF receiver: instance registry " + shortType + " affected "
                            + affected + " (jti " + set.jti() + ")"));
                }
            } catch (RegistryException | RuntimeException e) {
                LOGGER.warn((Object) ("SSF receiver: instance registry action for " + shortType
                        + " (jti " + set.jti() + ") failed: " + e.getMessage()));
            }
        }
    }

    private List<String> applyOne(String shortType, SubjectId subject, Map<String, Object> event)
            throws RegistryException {
        return switch (shortType) {
            case "device-compliance-change" -> deviceComplianceChange(subject, event);
            case "session-revoked" -> sessionRevoked(subject);
            case "credential-change" -> credentialChange(subject, event);
            default -> List.of();
        };
    }

    private List<String> deviceComplianceChange(SubjectId subject, Map<String, Object> event)
            throws RegistryException {
        String deviceId = deviceIdOf(subject);
        if (deviceId == null) {
            LOGGER.warn((Object) "device-compliance-change: subject is not device-scoped (opaque); ignoring");
            return List.of();
        }
        String current = stringField(event, "current_status");
        if (current == null) {
            LOGGER.warn((Object) "device-compliance-change: no current_status; ignoring");
            return List.of();
        }
        return this.applier.deviceComplianceChange(deviceId, current);
    }

    private List<String> sessionRevoked(SubjectId subject) throws RegistryException {
        String deviceId = deviceIdOf(subject);
        if (deviceId != null) {
            return this.applier.sessionRevokedForDevice(deviceId);
        }
        String pingOneSubject = ReceiverActionHandler.userKeyOf(subject);
        if (pingOneSubject == null) {
            return List.of();
        }
        return this.applier.sessionRevokedForOwner(pingOneSubject);
    }

    private List<String> credentialChange(SubjectId subject, Map<String, Object> event) throws RegistryException {
        String deviceId = deviceIdOf(subject);
        if (deviceId == null) {
            return List.of();
        }
        return this.applier.credentialChange(deviceId, stringField(event, "change_type"),
                stringField(event, "credential_type"));
    }

    /** The registry's device id, when the subject names a device directly ({@code opaque.id}). */
    private static String deviceIdOf(SubjectId subject) {
        if (!SubjectId.FORMAT_OPAQUE.equals(subject.format())) {
            return null;
        }
        return stringField(subject.toMap(), "id");
    }

    private static boolean isHandled(String shortType) {
        return "device-compliance-change".equals(shortType) || "session-revoked".equals(shortType)
                || "credential-change".equals(shortType);
    }

    private static String shortType(String eventTypeUri) {
        return eventTypeUri.substring(eventTypeUri.lastIndexOf('/') + 1);
    }

    private static String stringField(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof String && !((String) v).isBlank() ? (String) v : null;
    }
}
