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
 * <p>A provisioner is the other kind of caller, and is decided here too ({@link #provisions}): it owns no
 * streams and acts across all of them, which is what {@link ScimSubjectService} does and why a receiver may
 * not use it. The event emitter and the push executor ask nothing: they act for the transmitter.
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
     * Whether {@code caller} is a provisioner: it holds the configured provisioner scope. With none
     * configured nobody is. {@link SsfConfiguration} refuses a provisioner scope equal to the receiver
     * scope, so holding the receiver scope never answers this.
     */
    boolean provisions(AuthContext caller) {
        String scope = this.config.provisionerScope();
        return scope != null && caller != null && caller.hasScope(scope);
    }

    /**
     * Whether {@code caller} may name {@code audience} as the {@code aud} of a stream it creates: it is the
     * caller's own client id, or one the operator has agreed for that client.
     */
    boolean mayAddress(AuthContext caller, String audience) {
        String callerId = clientIdOf(caller);
        return callerId != null
                && (callerId.equals(audience) || this.config.allowedAudiences(callerId).contains(audience));
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
