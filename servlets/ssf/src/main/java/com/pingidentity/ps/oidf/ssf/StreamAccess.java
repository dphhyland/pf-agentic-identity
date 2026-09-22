/*
 * Which receiver a stream answers to.
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * The one place that decides whether a receiver is admitted to a stream. Holding the receiver scope gets a
 * client to the stream endpoints; it does not make every stream its own. SSF 1.0 §8.1.1.2 lists the streams
 * "available to this Receiver", and every per-stream operation answers 404 when there is none with that id
 * "for this Event Receiver" - so a stream is its creator's, and to anyone else it does not exist.
 *
 * <p>Both services that act for a receiver - {@link StreamManagementService} and {@link ScimSubjectService} -
 * ask here, so the rule cannot be right behind one endpoint and missing behind another. The event emitter
 * and the push executor do not: they act for the transmitter, across every receiver's streams.
 */
final class StreamAccess {

    private final SsfConfiguration config;

    StreamAccess(SsfConfiguration config) {
        this.config = config;
    }

    /**
     * The client a token identifies, or {@code null} when it names none. RFC 7662 makes {@code client_id}
     * OPTIONAL in an introspection response, so an active token carrying the receiver scope and no client
     * is a caller this code can be handed.
     */
    static String clientIdOf(AuthContext caller) {
        String id = caller == null ? null : caller.clientId();
        return id == null || id.isBlank() ? null : id;
    }

    /**
     * Whether {@code caller} is the receiver {@code stream} belongs to.
     *
     * <p>The unidentified caller is refused before any comparison is made. A stream that pre-dates
     * ownership has a null owner and that caller has a null client, and the two must never be allowed to
     * meet in an {@code equals}: that match would hand every unowned stream to exactly the callers the
     * transmitter knows least about.
     */
    boolean admits(Stream stream, AuthContext caller) {
        String callerId = clientIdOf(caller);
        if (callerId == null) {
            return false;
        }
        String owner = stream.ownerClientId() != null ? stream.ownerClientId() : this.config.unownedStreamOwner();
        return callerId.equals(owner);
    }
}
