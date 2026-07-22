/*
 * SCIM 2.0 subject management: provisioning flows drive which subjects a stream monitors.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.lang.JoseException;

/**
 * Bridges SCIM 2.0 provisioning to SSF stream subjects, so "who is being monitored" is a provisioning concern
 * rather than an API-scripting one. A SCIM {@code User} carries the custom extension
 * {@code urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject} with the stream id(s) to assign the user to;
 * provisioning/updating the user adds it as a subject of those streams, and deprovisioning (delete) or disabling
 * ({@code active:false}) removes the subject from every stream <em>and</em> emits a RISC {@code account-disabled}.
 * Transport-free so it unit-tests without a servlet.
 */
public final class ScimSubjectService {

    public static final String SSF_EXT = "urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject";
    private static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    private final SsfStore store;
    private final SsfEventEmitter emitter;
    private final SsfConfiguration config;

    public ScimSubjectService(SsfStore store, SsfEventEmitter emitter, SsfConfiguration config) {
        this.store = store;
        this.emitter = emitter;
        this.config = config;
    }

    /**
     * Provision/replace a SCIM user: assign it as a subject of the streams named in its SSF extension. If the
     * user is {@code active:false}, deprovision instead. Returns the SCIM resource representation.
     */
    public Map<String, Object> provision(Map<String, Object> scimUser) throws JoseException {
        SubjectId subject = subjectOf(scimUser);
        if (!isActive(scimUser)) {
            deprovision(subject);
            return scimResource(subject, scimUser, false);
        }
        assign(subject, streamIdsOf(scimUser));
        return scimResource(subject, scimUser, true);
    }

    /** Add {@code subject} to each named stream (validating existence). Used by PATCH and provisioning. */
    public void assign(SubjectId subject, List<String> streamIds) {
        for (String streamId : streamIds) {
            if (this.store.getStream(streamId).isEmpty()) {
                throw new StreamManagementService.NotFoundException("no such stream: " + streamId);
            }
            this.store.addSubject(streamId, subject);
        }
    }

    /**
     * Deprovision a subject: emit a RISC {@code account-disabled} to every subscribed stream, then remove the
     * subject from all streams. (Emit first, so streams still holding the subject actually receive the event.)
     */
    public void deprovision(SubjectId subject) throws JoseException {
        this.emitter.accountDisabled(subject, "scim-deprovision");
        for (Stream s : this.store.listStreams()) {
            this.store.removeSubject(s.id(), subject);
        }
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
