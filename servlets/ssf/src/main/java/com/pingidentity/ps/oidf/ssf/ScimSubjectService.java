/*
 * SCIM 2.0 subject management: provisioning flows drive which subjects a stream monitors.
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
 * Bridges SCIM 2.0 provisioning to SSF stream subjects, so "who is being monitored" is a provisioning concern
 * rather than an API-scripting one. A SCIM {@code User} carries the custom extension
 * {@code urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject} with the stream id(s) to assign the user to;
 * provisioning/updating the user adds it as a subject of those streams, and deprovisioning (delete) or disabling
 * ({@code active:false}) removes the subject from every stream <em>and</em> emits a RISC {@code account-disabled}.
 * Transport-free so it unit-tests without a servlet.
 *
 * <p>"Every stream" means every stream of the receiver asking. This endpoint admits the same token as the
 * Stream Management API, so it is held to the same rule ({@link StreamAccess}); otherwise it is a second
 * door onto other receivers' subjects, and one that also makes the transmitter tell them an account of the
 * caller's choosing has been disabled - a signal a receiving PingFederate revokes grants on.
 */
public final class ScimSubjectService {

    private static final Log LOGGER = LogFactory.getLog(ScimSubjectService.class);

    public static final String SSF_EXT = "urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject";
    private static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    private final SsfStore store;
    private final SsfEventEmitter emitter;
    private final SsfConfiguration config;
    private final StreamAccess access;

    public ScimSubjectService(SsfStore store, SsfEventEmitter emitter, SsfConfiguration config) {
        this.store = store;
        this.emitter = emitter;
        this.config = config;
        this.access = new StreamAccess(config);
    }

    /**
     * Provision/replace a SCIM user: assign it as a subject of the streams named in its SSF extension. If the
     * user is {@code active:false}, deprovision instead. Returns the SCIM resource representation.
     */
    public Map<String, Object> provision(Map<String, Object> scimUser, AuthContext caller) throws JoseException {
        SubjectId subject = subjectOf(scimUser);
        if (!isActive(scimUser)) {
            deprovision(subject, caller);
            return scimResource(subject, scimUser, false);
        }
        assign(subject, streamIdsOf(scimUser), caller);
        return scimResource(subject, scimUser, true);
    }

    /**
     * Add {@code subject} to each named stream (validating that it exists and is the caller's - another
     * receiver's stream is reported as absent). Used by PATCH and provisioning.
     */
    public void assign(SubjectId subject, List<String> streamIds, AuthContext caller) {
        for (String streamId : streamIds) {
            Stream stream = this.store.getStream(streamId).orElse(null);
            if (stream == null || !this.access.admits(stream, caller)) {
                throw new StreamManagementService.NotFoundException("no such stream: " + streamId);
            }
            this.store.addSubject(streamId, subject);
        }
    }

    /**
     * Deprovision a subject: emit a RISC {@code account-disabled} to each of the caller's subscribed streams,
     * then remove the subject from them. (Emit first, so streams still holding the subject actually receive
     * the event.) Another receiver's streams get neither the event nor the removal.
     *
     * <p>Returns how many streams hold the subject and were left alone because they are not the caller's.
     * That is the cost of the rule, and it is not hidden: a provisioning client that owns no streams used to
     * reach every receiver with this call and now reaches none, which the caller is not told (its own
     * request did succeed) but the operator is.
     */
    public int deprovision(SubjectId subject, AuthContext caller) throws JoseException {
        this.emitter.accountDisabled(subject, "scim-deprovision", s -> this.access.admits(s, caller));
        int leftAlone = 0;
        for (Stream s : this.store.listStreams()) {
            if (this.access.admits(s, caller)) {
                this.store.removeSubject(s.id(), subject);
            } else if (this.store.hasSubject(s.id(), subject)) {
                leftAlone++;
            }
        }
        if (leftAlone > 0) {
            LOGGER.warn((Object) ("SSF SCIM deprovision by client '" + StreamAccess.clientIdOf(caller) + "' did not reach "
                    + leftAlone + " stream(s) that hold the subject but belong to other receivers: no "
                    + "account-disabled was sent to them and the subject is still on them"));
        }
        return leftAlone;
    }

    // ─────────────────────────────── SCIM parsing ───────────────────────────────

    /** Derive the SSF subject from a SCIM user: primary/first email, else userName as iss_sub, else externalId. */
    @SuppressWarnings("unchecked")
    SubjectId subjectOf(Map<String, Object> scimUser) {
        Object emails = scimUser.get("emails");
        if (emails instanceof List) {
            String primary = null;
            String first = null;
            for (Object e : (List<Object>) emails) {
                if (e instanceof Map) {
                    Map<String, Object> em = (Map<String, Object>) e;
                    String value = str(em.get("value"));
                    if (value != null && first == null) {
                        first = value;
                    }
                    if (value != null && Boolean.TRUE.equals(em.get("primary"))) {
                        primary = value;
                    }
                }
            }
            String chosen = primary != null ? primary : first;
            if (chosen != null) {
                return SubjectId.email(chosen);
            }
        }
        String userName = str(scimUser.get("userName"));
        if (userName != null) {
            return SubjectId.issSub(this.config.issuer(), userName);
        }
        String externalId = str(scimUser.get("externalId"));
        if (externalId != null) {
            return SubjectId.opaque(externalId);
        }
        throw new IllegalArgumentException("SCIM user has no email, userName, or externalId to key a subject on");
    }

    private static boolean isActive(Map<String, Object> scimUser) {
        Object active = scimUser.get("active");
        return !(active instanceof Boolean) || (Boolean) active; // default active
    }

    @SuppressWarnings("unchecked")
    private static List<String> streamIdsOf(Map<String, Object> scimUser) {
        Object ext = scimUser.get(SSF_EXT);
        List<String> ids = new ArrayList<>();
        if (ext instanceof Map) {
            Object streams = ((Map<String, Object>) ext).get("streams");
            if (streams instanceof List) {
                for (Object s : (List<Object>) streams) {
                    if (s != null) {
                        ids.add(s.toString());
                    }
                }
            }
        }
        return ids;
    }

    private Map<String, Object> scimResource(SubjectId subject, Map<String, Object> scimUser, boolean active) {
        LinkedHashMap<String, Object> r = new LinkedHashMap<>();
        r.put("schemas", List.of(USER_SCHEMA, SSF_EXT));
        r.put("id", subject.canonicalKey());
        Object userName = scimUser.get("userName");
        if (userName != null) {
            r.put("userName", userName);
        }
        r.put("active", active);
        r.put(SSF_EXT, Map.of("subject", subject.toMap()));
        r.put("meta", Map.of("resourceType", "User", "location",
                this.config.issuer() + this.config.basePath() + "/scim/v2/Users/" + subject.canonicalKey()));
        return r;
    }

    private static String str(Object o) {
        return o instanceof String && !((String) o).isBlank() ? (String) o : null;
    }
}
