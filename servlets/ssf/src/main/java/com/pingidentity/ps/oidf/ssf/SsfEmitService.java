/*
 * Raises an event on the transmitter's behalf, for a provisioner and nobody else.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.lang.JoseException;

/**
 * What {@code POST /ssf/events:emit} does once the request has been parsed: has the transmitter sign the
 * event about the named subject and enqueue it to every stream that subscribes. The caller is a
 * provisioner ({@link StreamAccess#provisions}) for the same reason the SCIM endpoint's is: what it asks
 * for is a SET the transmitter signs about a subject of the caller's choosing, to every receiver, and a
 * receiver that could ask for that could carry the JWS to any other receiver of this transmitter. So the
 * receiver scope never answers here, and no scope configured means nobody does.
 *
 * <p>It grants nothing the emitter does not: {@link SsfEventEmitter#subscribes} is the whole rule, and a
 * {@code stream_id} only narrows the fan-out to one existing stream. A fan-out of zero is an answer, not an
 * error - nothing subscribed - and is returned as such.
 */
public final class SsfEmitService {

    private static final Log LOGGER = LogFactory.getLog(SsfEmitService.class);

    private final SsfStore store;
    private final SsfEventEmitter emitter;
    private final StreamAccess access;

    public SsfEmitService(SsfStore store, SsfEventEmitter emitter, SsfConfiguration config) {
        this.store = store;
        this.emitter = emitter;
        this.access = new StreamAccess(config);
    }

    /**
     * @throws StreamManagementService.ForbiddenException when {@code caller} is not a provisioner
     * @throws StreamManagementService.NotFoundException  when the request names a stream that does not exist
     */
    public List<SsfEventEmitter.Emitted> emit(EmitRequest request, AuthContext caller) throws JoseException {
        if (!this.access.provisions(caller)) {
            throw new StreamManagementService.ForbiddenException(
                    "raising an event needs the provisioner scope, which the receiver scope is not");
        }
        if (request.streamId() != null && this.store.getStream(request.streamId()).isEmpty()) {
            throw new StreamManagementService.NotFoundException("no such stream: " + request.streamId());
        }
        List<SsfEventEmitter.Emitted> emitted = this.emitter.emit(request.eventType(), request.subject(),
                request.payload(), request.streamId());
        LOGGER.info((Object) ("SSF emit by provisioner '" + StreamAccess.clientIdOf(caller) + "': "
                + request.eventType() + " about " + request.subject().canonicalKey() + " reached "
                + emitted.size() + " stream(s)"));
        return emitted;
    }

    /** The response body: the event type and one entry per stream a SET was enqueued for. */
    public static Map<String, Object> toJson(String eventType, List<SsfEventEmitter.Emitted> emitted) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (SsfEventEmitter.Emitted e : emitted) {
            LinkedHashMap<String, Object> item = new LinkedHashMap<>();
            item.put("stream_id", e.streamId());
            item.put("jti", e.jti());
            item.put("delivery", e.deliveryMethod().urn());
            items.add(item);
        }
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("event_type", eventType);
        body.put("emitted", items);
        body.put("count", items.size());
        return body;
    }
}
