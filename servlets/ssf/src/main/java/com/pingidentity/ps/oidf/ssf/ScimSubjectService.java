/*
 * SCIM 2.0 subject management: provisioning flows drive which subjects a stream monitors.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.lang.JoseException;

/**
 * Bridges SCIM 2.0 provisioning to SSF stream subjects, so "who is being monitored" is a provisioning concern
 * rather than an API-scripting one. A SCIM {@code User} carries the custom extension {@value #SSF_EXT} with the
 * stream id(s) to assign the user to; provisioning a user adds it as a subject of those streams, and deactivating
 * it ({@code active:false}) or deleting it removes the subject from every stream <em>and</em> emits a RISC
 * {@code account-disabled}. Reactivating it ({@code active} false to true) puts it back on the streams it was taken
 * off and emits {@code account-enabled}. Transport-free so it unit-tests without a servlet.
 *
 * <p>The resource (plan item H-SSF-4). The SCIM {@code id} is the subject's canonical key. A user exists when this
 * endpoint keeps a record of it ({@link ScimUser}: {@code userName}, {@code externalId}, {@code active}, and the
 * streams a deactivation took it off) or when any stream holds its subject, whoever added it there. An active user's
 * streams are the streams that hold its subject; an inactive user's are the ones a reactivation restores.
 *
 * <ul>
 *   <li>{@code POST} creates (RFC 7644 §3.3): a user this endpoint already keeps a record of is 409
 *       {@code uniqueness}; the streams named are added to whatever already holds the subject.</li>
 *   <li>{@code GET /Users/{id}} (§3.4.1) and {@code GET /Users} with an optional {@code filter} (§3.4.2.2, the subset
 *       {@link ScimFilter} lists), {@code startIndex} and {@code count} (§3.4.2.4), answering a ListResponse.</li>
 *   <li>{@code PUT} replaces (§3.5.1): "HTTP PUT MUST NOT be used to create new resources", so an unknown id is 404;
 *       an attribute the body leaves out is removed - no {@code userName} clears it, and no SSF extension takes the
 *       subject off every stream. The body's subject must be the one the path names ({@code mutability} otherwise):
 *       a subject is the id, and changing it is a delete and a create.</li>
 *   <li>{@code PATCH} (§3.5.2) applies {@code add}, {@code replace} and {@code remove} to {@code active},
 *       {@code userName}, {@code externalId} and the extension's {@code streams}; operations on attributes this
 *       endpoint does not keep are ignored.</li>
 *   <li>{@code DELETE} (§3.6) deactivates the subject if it is active and forgets the user; an unknown id is 404.</li>
 * </ul>
 *
 * <p>Every refusal is a {@link ScimException}, rendered in the RFC 7644 §3.12 error schema.
 *
 * <p>The caller is a provisioner ({@link StreamAccess#provisions}) and "every stream" means every
 * receiver's. A receiver is refused outright, not confined to its own streams: a deprovision has the
 * transmitter sign an account-disabled about a subject of the caller's choosing - a signal a receiving
 * PingFederate revokes grants on - and a receiver handed that SET on its own stream, under an {@code aud}
 * it picked, could carry it to another receiver. The servlet applies the same scope; it is asked again
 * here so that the rule holds for any caller of this class and not only for that one.
 */
public final class ScimSubjectService {

    private static final Log LOGGER = LogFactory.getLog(ScimSubjectService.class);

    public static final String SSF_EXT = "urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject";
    static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    static final String LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    static final String PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    /** The most resources one list answer carries, whatever {@code count} asks for (RFC 7644 §3.4.2.4 lets the server cap it). */
    static final int MAX_PAGE = 200;

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

    // ─────────────────────────────── operations ───────────────────────────────

    /** {@code POST /Users}: create a user, assigning it to the streams its extension names. Returns the resource. */
    public Map<String, Object> create(Map<String, Object> scimUser, AuthContext caller) throws JoseException {
        requireProvisioner(caller);
        SubjectId subject = subjectOf(scimUser);
        Current now = current(subject);
        if (now.record() != null) {
            throw new ScimException(409, "uniqueness", "a user with id " + subject.canonicalKey() + " already exists");
        }
        Desired want = new Desired(str(scimUser.get("userName")), str(scimUser.get("externalId")), isActive(scimUser),
                streamIdsOf(scimUser));
        return apply(subject, now, want, true);
    }

    /** {@code GET /Users/{id}}. */
    public Map<String, Object> get(String id, AuthContext caller) {
        requireProvisioner(caller);
        SubjectId subject = subjectOfId(id);
        Current now = current(subject);
        if (!now.exists()) {
            throw ScimException.notFound("no user with id " + id);
        }
        return representation(subject, now);
    }

    /**
     * {@code GET /Users}: the users matching {@code filter} (every user when it is {@code null}), ordered by id, as an
     * RFC 7644 §3.4.2 ListResponse page. {@code startIndex} is 1-based, and less than 1 is 1; {@code count} is at most
     * {@value #MAX_PAGE}, and negative is 0 (§3.4.2.4: "A negative value SHALL be interpreted as "0"").
     */
    public Map<String, Object> query(String filter, Integer startIndex, Integer count, AuthContext caller) {
        requireProvisioner(caller);
        ScimFilter parsed = filter == null ? null : ScimFilter.parse(filter);
        TreeMap<String, List<String>> held = new TreeMap<>();
        Map<String, SubjectId> subjects = new LinkedHashMap<>();
        for (Stream s : this.store.listStreams()) {
            for (SubjectId subject : this.store.listSubjects(s.id())) {
                held.computeIfAbsent(subject.canonicalKey(), k -> new ArrayList<>()).add(s.id());
                subjects.putIfAbsent(subject.canonicalKey(), subject);
            }
        }
        TreeMap<String, Current> all = new TreeMap<>();
        for (ScimUser u : this.store.listScimUsers()) {
            all.put(u.id(), new Current(u, held.getOrDefault(u.id(), List.of())));
        }
        for (Map.Entry<String, List<String>> e : held.entrySet()) {
            all.putIfAbsent(e.getKey(), new Current(null, e.getValue()));
        }
        List<Map<String, Object>> matched = new ArrayList<>();
        for (Map.Entry<String, Current> e : all.entrySet()) {
            Current c = e.getValue();
            SubjectId subject = c.record() != null ? c.record().subject() : subjects.get(e.getKey());
            Map<String, Object> resource = representation(subject, c);
            if (parsed == null || parsed.matches(attributes(resource))) {
                matched.add(resource);
            }
        }
        int start = startIndex == null || startIndex < 1 ? 1 : startIndex;
        int size = count == null ? MAX_PAGE : Math.max(0, Math.min(count, MAX_PAGE));
        List<Map<String, Object>> page = new ArrayList<>();
        for (int i = start - 1; i < matched.size() && page.size() < size; i++) {
            page.add(matched.get(i));
        }
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("schemas", List.of(LIST_SCHEMA));
        out.put("totalResults", matched.size());
        out.put("startIndex", start);
        out.put("itemsPerPage", page.size());
        out.put("Resources", page);
        return out;
    }

    /** {@code PUT /Users/{id}}: replace the user's attributes (RFC 7644 §3.5.1). */
    public Map<String, Object> replace(String id, Map<String, Object> scimUser, AuthContext caller) throws JoseException {
        requireProvisioner(caller);
        SubjectId subject = subjectOfId(id);
        Current now = current(subject);
        if (!now.exists()) {
            throw ScimException.notFound("no user with id " + id + "; PUT does not create one (RFC 7644 §3.5.1), POST does");
        }
        if (!subject.equals(subjectOf(scimUser))) {
            throw ScimException.badRequest("mutability", "the user's emails, userName or externalId name another subject"
                    + " than " + id + "; the subject is the id and cannot be replaced: delete the user and create another");
        }
        List<String> streams = streamIdsOf(scimUser);
        Desired want = new Desired(str(scimUser.get("userName")), str(scimUser.get("externalId")), isActive(scimUser),
                streams == null ? List.of() : streams);
        return apply(subject, now, want, false);
    }

    /** {@code PATCH /Users/{id}}: apply a PatchOp (RFC 7644 §3.5.2) to the attributes this endpoint keeps. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> patch(String id, Map<String, Object> patchOp, AuthContext caller) throws JoseException {
        requireProvisioner(caller);
        SubjectId subject = subjectOfId(id);
        Current now = current(subject);
        if (!now.exists()) {
            throw ScimException.notFound("no user with id " + id);
        }
        Object operations = patchOp.get("Operations");
        if (!(operations instanceof List)) {
            throw ScimException.badRequest("invalidSyntax", "a PatchOp needs an Operations array");
        }
        Working w = new Working(now);
        for (Object o : (List<Object>) operations) {
            if (!(o instanceof Map)) {
                throw ScimException.badRequest("invalidSyntax", "each operation is a JSON object");
            }
            w.apply((Map<String, Object>) o);
        }
        return apply(subject, now, w.desired(), false);
    }

    /** {@code DELETE /Users/{id}}: deactivate the subject if it is active, and forget the user. */
    public void delete(String id, AuthContext caller) throws JoseException {
        requireProvisioner(caller);
        SubjectId subject = subjectOfId(id);
        Current now = current(subject);
        if (!now.exists()) {
            throw ScimException.notFound("no user with id " + id);
        }
        if (now.active()) {
            deactivate(subject, now);
        }
        this.store.deleteScimUser(subject.canonicalKey());
    }

    // ─────────────────────────────── state ───────────────────────────────

    /** What the endpoint holds for a subject: its record, if any, and the streams holding it now. */
    record Current(ScimUser record, List<String> streams) {
        boolean exists() {
            return this.record != null || !this.streams.isEmpty();
        }

        /** A subject a stream holds with no record was put there by a receiver or before 0.6.0: an active user. */
        boolean active() {
            return this.record == null || this.record.active();
        }
    }

    /** What a request asks for. {@code streams} {@code null} leaves the streams as they are (or, reactivating, restores them). */
    record Desired(String userName, String externalId, boolean active, List<String> streams) {
    }

    private Current current(SubjectId subject) {
        List<String> streams = new ArrayList<>();
        for (Stream s : this.store.listStreams()) {
            if (this.store.hasSubject(s.id(), subject)) {
                streams.add(s.id());
            }
        }
        return new Current(this.store.getScimUser(subject.canonicalKey()).orElse(null), streams);
    }

    /**
     * Moves the subject from what {@code now} holds to what {@code want} asks for, emitting the RISC event a change of
     * {@code active} calls for, and writes the record. {@code additive}: the named streams are added to the ones holding
     * the subject (a create) rather than replacing them.
     *
     * <p>Deactivating: {@code account-disabled} first, so the streams still holding the subject hear it, then the
     * subject comes off every stream, and those streams are kept to restore. A subject this endpoint has never seen
     * counts as active, as every {@code active:false} did before 0.6.0: the event is emitted. One already inactive
     * emits nothing again. Reactivating (a record that is inactive): the subject goes back on the streams named, or
     * those it was taken off, then {@code account-enabled} (RISC 1.0 §2.4: "Account Enabled signals that the account
     * identified by the subject has been enabled"), after, so those streams hear it.
     */
    private Map<String, Object> apply(SubjectId subject, Current now, Desired want, boolean additive) throws JoseException {
        if (want.streams() != null) {
            requireStreamsExist(want.streams());
        }
        long ts = SetMinter.nowSeconds();
        long created = now.record() != null ? now.record().createdAt() : ts;
        ScimUser written;
        if (want.active()) {
            boolean reactivating = now.record() != null && !now.record().active();
            List<String> target;
            if (want.streams() != null) {
                target = additive ? union(now.streams(), want.streams()) : want.streams();
            } else if (reactivating) {
                target = existingOnly(now.record().restoreStreams());
            } else {
                target = now.streams();
            }
            for (String s : now.streams()) {
                if (!target.contains(s)) {
                    this.store.removeSubject(s, subject);
                }
            }
            for (String s : target) {
                this.store.addSubject(s, subject);
            }
            written = new ScimUser(subject, want.userName(), want.externalId(), true, List.of(), created, ts);
            this.store.putScimUser(written);
            if (reactivating) {
                this.emitter.accountEnabled(subject);
                LOGGER.info((Object) ("SSF SCIM reactivation: account-enabled raised and the subject put back on "
                        + target.size() + " stream(s)"));
            }
            return representation(subject, new Current(written, target));
        }
        List<String> restore;
        if (now.active()) {
            List<String> removed = deactivate(subject, now);
            restore = want.streams() != null ? want.streams() : removed;
        } else {
            restore = want.streams() != null ? want.streams() : now.record().restoreStreams();
        }
        written = new ScimUser(subject, want.userName(), want.externalId(), false, restore, created, ts);
        this.store.putScimUser(written);
        return representation(subject, new Current(written, List.of()));
    }

    /** Emits {@code account-disabled} and takes the subject off every stream holding it; returns those streams. */
    private List<String> deactivate(SubjectId subject, Current now) throws JoseException {
        this.emitter.accountDisabled(subject, "scim-deprovision");
        for (String s : now.streams()) {
            this.store.removeSubject(s, subject);
        }
        LOGGER.info((Object) ("SSF SCIM deactivation: account-disabled raised and the subject removed from "
                + now.streams().size() + " stream(s)"));
        return now.streams();
    }

    private void requireStreamsExist(Collection<String> streamIds) {
        for (String id : streamIds) {
            if (this.store.getStream(id).isEmpty()) {
                throw ScimException.badRequest("invalidValue", "no such stream: " + id);
            }
        }
    }

    /** The streams of {@code ids} that still exist: a stream deleted while its subject was inactive is not restored. */
    private List<String> existingOnly(List<String> ids) {
        List<String> out = new ArrayList<>();
        for (String id : ids) {
            if (this.store.getStream(id).isPresent()) {
                out.add(id);
            }
        }
        return out;
    }

    private static List<String> union(List<String> a, List<String> b) {
        LinkedHashSet<String> out = new LinkedHashSet<>(a);
        out.addAll(b);
        return new ArrayList<>(out);
    }

    private void requireProvisioner(AuthContext caller) {
        if (!this.access.provisions(caller)) {
            throw new ScimException(403, null, "provisioning needs the provisioner scope, which the receiver scope is not");
        }
    }

    // ─────────────────────────────── PATCH ───────────────────────────────

    /** A PATCH's working copy of the attributes this endpoint keeps. */
    private static final class Working {
        private String userName;
        private String externalId;
        private boolean active;
        private final LinkedHashSet<String> streams;
        private boolean streamsTouched;

        Working(Current now) {
            this.userName = now.record() != null ? now.record().userName() : null;
            this.externalId = now.record() != null ? now.record().externalId() : null;
            this.active = now.active();
            this.streams = new LinkedHashSet<>(now.active() ? now.streams() : now.record().restoreStreams());
        }

        Desired desired() {
            return new Desired(this.userName, this.externalId, this.active,
                    this.streamsTouched ? new ArrayList<>(this.streams) : null);
        }

        @SuppressWarnings("unchecked")
        void apply(Map<String, Object> op) {
            String kind = op.get("op") instanceof String k ? k.toLowerCase(Locale.ROOT) : "";
            if (!List.of("add", "replace", "remove").contains(kind)) {
                throw ScimException.badRequest("invalidSyntax", "op must be add, replace or remove");
            }
            String path = op.get("path") instanceof String p && !p.isBlank() ? p : null;
            Object value = op.get("value");
            if (path == null) {
                if ("remove".equals(kind)) {
                    throw ScimException.badRequest("noTarget", "a remove operation needs a path");
                }
                if (!(value instanceof Map)) {
                    throw ScimException.badRequest("invalidValue", "an operation with no path takes an object value");
                }
                Map<String, Object> v = (Map<String, Object>) value;
                for (Map.Entry<String, Object> e : v.entrySet()) {
                    if (e.getKey().equalsIgnoreCase(SSF_EXT) && e.getValue() instanceof Map) {
                        Object streams = ((Map<String, Object>) e.getValue()).get("streams");
                        if (streams != null) {
                            attribute(kind, "streams", streams);
                        }
                    } else {
                        attribute(kind, e.getKey(), e.getValue());
                    }
                }
                return;
            }
            if (path.contains("[")) {
                throw ScimException.badRequest("invalidPath", "value filters in a path are not supported");
            }
            String name = path;
            String lower = path.toLowerCase(Locale.ROOT);
            String ext = SSF_EXT.toLowerCase(Locale.ROOT) + ":";
            if (lower.startsWith(ext)) {
                name = path.substring(ext.length());
            } else if (lower.startsWith(USER_SCHEMA.toLowerCase(Locale.ROOT) + ":")) {
                name = path.substring(USER_SCHEMA.length() + 1);
            }
            attribute(kind, name, value);
        }

        private void attribute(String kind, String name, Object value) {
            switch (name.toLowerCase(Locale.ROOT)) {
                case "active" -> {
                    if ("remove".equals(kind)) {
                        throw ScimException.badRequest("invalidValue", "active cannot be removed; replace it with true or false");
                    }
                    this.active = booleanValue(value);
                }
                case "username" -> this.userName = "remove".equals(kind) ? null : stringValue("userName", value);
                case "externalid" -> this.externalId = "remove".equals(kind) ? null : stringValue("externalId", value);
                case "streams" -> {
                    List<String> ids = value == null ? List.of() : streamList(value);
                    if ("replace".equals(kind)) {
                        this.streams.clear();
                        this.streams.addAll(ids);
                    } else if ("add".equals(kind)) {
                        this.streams.addAll(ids);
                    } else if (value == null) {
                        this.streams.clear();
                    } else {
                        ids.forEach(this.streams::remove);
                    }
                    this.streamsTouched = true;
                }
                default -> {
                    // An attribute this endpoint does not keep (name, displayName, emails...): nothing here to change.
                }
            }
        }

        /** {@code true} or {@code false}, as a JSON boolean or the string some provisioners send ("False"). */
        private static boolean booleanValue(Object v) {
            if (v instanceof Boolean b) {
                return b;
            }
            if (v instanceof String s && ("true".equalsIgnoreCase(s) || "false".equalsIgnoreCase(s))) {
                return Boolean.parseBoolean(s.toLowerCase(Locale.ROOT));
            }
            throw ScimException.badRequest("invalidValue", "active must be true or false");
        }

        private static String stringValue(String name, Object v) {
            if (v == null || v instanceof String) {
                return str(v);
            }
            throw ScimException.badRequest("invalidValue", name + " must be a string");
        }

        private static List<String> streamList(Object v) {
            if (!(v instanceof List<?> list)) {
                throw ScimException.badRequest("invalidValue", "streams must be an array of stream ids");
            }
            List<String> out = new ArrayList<>();
            for (Object o : list) {
                if (!(o instanceof String s)) {
                    throw ScimException.badRequest("invalidValue", "streams must be an array of stream ids");
                }
                out.add(s);
            }
            return out;
        }
    }

    // ─────────────────────────────── SCIM representation ───────────────────────────────

    /** The SCIM resource for {@code subject} as {@code now} holds it. */
    private Map<String, Object> representation(SubjectId subject, Current now) {
        ScimUser r = now.record();
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("schemas", List.of(USER_SCHEMA, SSF_EXT));
        m.put("id", subject.canonicalKey());
        if (r != null && r.externalId() != null) {
            m.put("externalId", r.externalId());
        }
        if (r != null && r.userName() != null) {
            m.put("userName", r.userName());
        }
        m.put("active", now.active());
        if (SubjectId.FORMAT_EMAIL.equals(subject.format())) {
            m.put("emails", List.of(Map.of("value", subject.toMap().get("email"), "primary", true)));
        }
        LinkedHashMap<String, Object> ext = new LinkedHashMap<>();
        ext.put("subject", subject.toMap());
        List<String> streams = new ArrayList<>(now.active() ? now.streams() : r.restoreStreams());
        streams.sort(null);
        ext.put("streams", streams);
        m.put(SSF_EXT, ext);
        LinkedHashMap<String, Object> meta = new LinkedHashMap<>();
        meta.put("resourceType", "User");
        if (r != null) {
            meta.put("created", Instant.ofEpochSecond(r.createdAt()).toString());
            meta.put("lastModified", Instant.ofEpochSecond(r.updatedAt()).toString());
        }
        meta.put("location", this.config.issuer() + SsfPaths.SCIM_USERS + "/" + pathSegment(subject.canonicalKey()));
        m.put("meta", meta);
        return m;
    }

    /** The resource's attributes as {@link ScimFilter} reads them. */
    @SuppressWarnings("unchecked")
    private static ScimFilter.Resource attributes(Map<String, Object> resource) {
        return attr -> switch (attr) {
            case ID -> List.of(resource.get("id"));
            case USER_NAME -> optional(resource.get("userName"));
            case EXTERNAL_ID -> optional(resource.get("externalId"));
            case ACTIVE -> List.of(resource.get("active"));
            case EMAILS_VALUE -> resource.get("emails") == null ? List.of()
                    : List.of(((List<Map<String, Object>>) resource.get("emails")).get(0).get("value"));
            case STREAMS -> new ArrayList<>((List<Object>) ((Map<String, Object>) resource.get(SSF_EXT)).get("streams"));
        };
    }

    private static List<Object> optional(Object v) {
        return v == null ? List.of() : List.of(v);
    }

    /**
     * {@code s} as one RFC 3986 path segment: unreserved characters, the sub-delimiters, {@code :} and {@code @} as
     * they are, every other octet of its UTF-8 percent-encoded. The container decodes the path before the servlet
     * reads it, so the id comes back as it went out.
     */
    static String pathSegment(String s) {
        StringBuilder out = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "-._~!$&'()*+,;=:@".indexOf(c) >= 0) {
                out.append(c);
            } else {
                out.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return out.toString();
    }

    // ─────────────────────────────── SCIM parsing ───────────────────────────────

    /** The subject a path's id names; an id that is no subject key is a user that cannot exist (404). */
    private static SubjectId subjectOfId(String id) {
        try {
            return SsfSubjects.fromCanonicalKey(id);
        } catch (IllegalArgumentException e) {
            throw ScimException.notFound("no user with id " + id);
        }
    }

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
        throw ScimException.badRequest("invalidValue", "a SCIM user needs an email, userName or externalId to key a subject on");
    }

    /** {@code active}, true when absent (RFC 7643 leaves it to the service provider); anything but a boolean is a 400. */
    private static boolean isActive(Map<String, Object> scimUser) {
        Object active = scimUser.get("active");
        if (active == null) {
            return true;
        }
        if (active instanceof Boolean b) {
            return b;
        }
        throw ScimException.badRequest("invalidValue", "active must be true or false");
    }

    /** The extension's {@code streams}, or {@code null} when the user carries no extension or it names none. */
    @SuppressWarnings("unchecked")
    private static List<String> streamIdsOf(Map<String, Object> scimUser) {
        Object ext = scimUser.get(SSF_EXT);
        if (!(ext instanceof Map)) {
            return null;
        }
        Object streams = ((Map<String, Object>) ext).get("streams");
        return streams == null ? null : Working.streamList(streams);
    }

    private static String str(Object o) {
        return o instanceof String && !((String) o).isBlank() ? (String) o : null;
    }
}
