/*
 * Maps verified inbound CAEP SETs to agent-instance registry changes.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.RegistryException;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.signals.ReceivedSet;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
 *
 * <p>Subjects are mapped by {@link SsfSubjects}: a device by {@link SsfSubjects#deviceId} (an {@code opaque} subject,
 * a complex subject's {@code device} member, or an aliases subject's {@code opaque} identifier), and, for a
 * {@code session-revoked} with no device, a user by {@link SsfSubjects#userKey} (a complex subject's {@code user}
 * member), in that order. A subject that maps to neither is logged with the reason and counted
 * ({@value #SUBJECT_UNMAPPED}).
 */
public final class InstanceRegistryReceiverHandler implements SsfReceiverService.ReceivedSetHandler {

    private static final Log LOGGER = LogFactory.getLog(InstanceRegistryReceiverHandler.class);

    static final String EVENTS = "ssf-receiver";
    static final String SUBJECT_UNMAPPED = "ssf.receiver.subject_unmapped";

    private final CaepSignalApplier applier;
    private final Set<String> localIssuers;

    /** A handler that honours only the SET's own issuer in an {@code iss_sub} subject. */
    public InstanceRegistryReceiverHandler(CaepSignalApplier applier) {
        this(applier, Set.of());
    }

    /** @param localIssuers the issuers, besides the SET's own, whose {@code iss_sub} subjects name a user here */
    public InstanceRegistryReceiverHandler(CaepSignalApplier applier, Set<String> localIssuers) {
        this.applier = Objects.requireNonNull(applier, "applier");
        this.localIssuers = Set.copyOf(localIssuers);
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
                List<String> affected = applyOne(shortType, set, set.eventPayload(eventType));
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

    private List<String> applyOne(String shortType, ReceivedSet set, Map<String, Object> event)
            throws RegistryException {
        SubjectId subject = set.subjectId();
        return switch (shortType) {
            case "device-compliance-change" -> deviceComplianceChange(subject, event);
            case "session-revoked" -> sessionRevoked(set);
            default -> credentialChange(subject, event);
        };
    }

    private List<String> deviceComplianceChange(SubjectId subject, Map<String, Object> event)
            throws RegistryException {
        SsfSubjects.Mapping device = SsfSubjects.deviceId(subject);
        if (!device.mapped()) {
            unmapped("device-compliance-change", subject, device.refusal());
            return List.of();
        }
        String deviceId = device.value();
        String current = stringField(event, "current_status");
        if (current == null) {
            LOGGER.warn((Object) "device-compliance-change: no current_status; ignoring");
            return List.of();
        }
        return this.applier.deviceComplianceChange(deviceId, current);
    }

    private List<String> sessionRevoked(ReceivedSet set) throws RegistryException {
        SubjectId subject = set.subjectId();
        SsfSubjects.Mapping device = SsfSubjects.deviceId(subject);
        if (device.mapped()) {
            return this.applier.sessionRevokedForDevice(device.value());
        }
        SsfSubjects.Mapping owner = SsfSubjects.userKey(subject, ReceiverActionHandler.issuers(set, this.localIssuers));
        if (!owner.mapped()) {
            unmapped("session-revoked", subject, device.refusal() + "; " + owner.refusal());
            return List.of();
        }
        return this.applier.sessionRevokedForOwner(owner.value());
    }

    private List<String> credentialChange(SubjectId subject, Map<String, Object> event) throws RegistryException {
        SsfSubjects.Mapping device = SsfSubjects.deviceId(subject);
        if (!device.mapped()) {
            unmapped("credential-change", subject, device.refusal());
            return List.of();
        }
        return this.applier.credentialChange(device.value(), stringField(event, "change_type"),
                stringField(event, "credential_type"));
    }

    private static void unmapped(String eventType, SubjectId subject, String reason) {
        LOGGER.warn((Object) (eventType + ": the subject names no device or owner here (" + LogSafe.value(reason)
                + "); ignoring"));
        Events.event(EVENTS, SUBJECT_UNMAPPED).failure("unmapped").field("handler", "instance_registry")
                .field("format", subject.format()).emit();
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
