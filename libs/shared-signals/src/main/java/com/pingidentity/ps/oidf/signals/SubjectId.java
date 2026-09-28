/*
 * RFC 9493 Subject Identifiers for Security Event Tokens, and the Shared Signals Framework's complex subject.
 */
package com.pingidentity.ps.oidf.signals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * A subject of a Security Event Token: an RFC 9493 Subject Identifier, or a Shared Signals Framework 1.0 complex
 * subject. Carried as the {@code sub_id} member of a SET and as the add/remove-subject request body of the SSF
 * stream API. Each has a {@code format} discriminator and format-specific members; this type round-trips them
 * to and from the JSON object representation.
 *
 * <p>Formats: RFC 9493 §3.2's eight ({@code account}, {@code email}, {@code iss_sub}, {@code opaque},
 * {@code phone_number}, {@code did}, {@code uri}, {@code aliases}); SSF 1.0 §3.5's three ({@code jwt_id},
 * {@code saml_assertion_id}, {@code ip-addresses}); and SSF 1.0 §3.3's {@code complex}, which is not a Subject
 * Identifier but "a JSON [RFC7159] object that has a format field, and one or more Simple Subject Members", each
 * member's value a Subject Identifier. Any other format is refused: SSF 1.0 §3.4 allows "a proprietary subject
 * identifier format that is agreed to between parties", and there is no such agreement here.
 *
 * <p>Members a format does not describe are dropped when parsing, not refused (RFC 9493 §3 says a Subject
 * Identifier "MUST NOT contain any members prohibited or not described by its Identifier Format"; a receiver
 * that refused on that ground would drop events for a transmitter's extra field, which SSF 1.0 §4.2.3 tells it
 * to ignore). A complex subject keeps every member name, since SSF 1.0 §3.3 says "Additional Subject Member
 * names MAY be used in Complex Subjects".
 */
public final class SubjectId {

    public static final String FORMAT_ISS_SUB = "iss_sub";
    public static final String FORMAT_EMAIL = "email";
    public static final String FORMAT_PHONE_NUMBER = "phone_number";
    public static final String FORMAT_OPAQUE = "opaque";
    public static final String FORMAT_ACCOUNT = "account";
    /** RFC 9493 §3.2.6. */
    public static final String FORMAT_DID = "did";
    /** RFC 9493 §3.2.7. */
    public static final String FORMAT_URI = "uri";
    /** RFC 9493 §3.2.8. */
    public static final String FORMAT_ALIASES = "aliases";
    /** SSF 1.0 §3.5.1. */
    public static final String FORMAT_JWT_ID = "jwt_id";
    /** SSF 1.0 §3.5.2. */
    public static final String FORMAT_SAML_ASSERTION_ID = "saml_assertion_id";
    /** SSF 1.0 §3.5.3. */
    public static final String FORMAT_IP_ADDRESSES = "ip-addresses";
    /** SSF 1.0 §3.3: a complex subject, whose members are Subject Identifiers. */
    public static final String FORMAT_COMPLEX = "complex";

    /** Every format {@link #fromMap(Map)} parses. */
    public static final Set<String> FORMATS = Set.of(FORMAT_ISS_SUB, FORMAT_EMAIL, FORMAT_PHONE_NUMBER,
            FORMAT_OPAQUE, FORMAT_ACCOUNT, FORMAT_DID, FORMAT_URI, FORMAT_ALIASES, FORMAT_JWT_ID,
            FORMAT_SAML_ASSERTION_ID, FORMAT_IP_ADDRESSES, FORMAT_COMPLEX);

    /** The complex-subject member names SSF 1.0 §3.3 lists; others are allowed too. */
    public static final List<String> COMPLEX_MEMBERS = List.of("user", "device", "session", "application",
            "tenant", "org_unit", "group");

    private final Map<String, Object> members;

    private SubjectId(Map<String, Object> members) {
        this.members = Collections.unmodifiableMap(new LinkedHashMap<>(members));
    }

    private static SubjectId of(String format, Object... pairs) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", format);
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], Objects.requireNonNull(pairs[i + 1], (String) pairs[i]));
        }
        return new SubjectId(m);
    }

    /** RFC 9493 §3.2.3 — an issuer and subject pair. */
    public static SubjectId issSub(String iss, String sub) {
        return of(FORMAT_ISS_SUB, "iss", iss, "sub", sub);
    }

    /** RFC 9493 §3.2.2 — an email address. */
    public static SubjectId email(String email) {
        return of(FORMAT_EMAIL, "email", email);
    }

    /** RFC 9493 §3.2.5 — an E.164 phone number. */
    public static SubjectId phoneNumber(String phoneNumber) {
        return of(FORMAT_PHONE_NUMBER, "phone_number", phoneNumber);
    }

    /** RFC 9493 §3.2.4 — an opaque, transmitter-defined identifier. */
    public static SubjectId opaque(String id) {
        return of(FORMAT_OPAQUE, "id", id);
    }

    /** RFC 9493 §3.2.1 — an {@code acct:} URI. */
    public static SubjectId account(String acctUri) {
        return of(FORMAT_ACCOUNT, "uri", acctUri);
    }

    /** RFC 9493 §3.2.6 — a DID URL, or a bare DID, in the {@code url} member. */
    public static SubjectId did(String url) {
        return of(FORMAT_DID, "url", url);
    }

    /** RFC 9493 §3.2.7 — a URI. */
    public static SubjectId uri(String uri) {
        return of(FORMAT_URI, "uri", uri);
    }

    /** SSF 1.0 §3.5.1 — the {@code iss} and {@code jti} of a JWT. */
    public static SubjectId jwtId(String iss, String jti) {
        return of(FORMAT_JWT_ID, "iss", iss, "jti", jti);
    }

    /** SSF 1.0 §3.5.2 — the Issuer and ID of a SAML 2.0 assertion. */
    public static SubjectId samlAssertionId(String issuer, String assertionId) {
        return of(FORMAT_SAML_ASSERTION_ID, "issuer", issuer, "assertion_id", assertionId);
    }

    /**
     * SSF 1.0 §3.5.3 — the IP addresses the transmitter observed. "The value MUST be in the format of an array of
     * strings"; at least one, none blank.
     */
    public static SubjectId ipAddresses(List<String> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            throw new IllegalArgumentException("an ip-addresses subject identifier needs at least one address");
        }
        for (String a : addresses) {
            if (a == null || a.isBlank()) {
                throw new IllegalArgumentException("an ip-addresses subject identifier holds only non-blank strings");
            }
        }
        return of(FORMAT_IP_ADDRESSES, "ip-addresses", List.copyOf(addresses));
    }

    /**
     * RFC 9493 §3.2.8 — several identifiers of one entity. "The "identifiers" member is REQUIRED and MUST NOT be
     * null or empty", and aliases "MUST NOT be nested"; a complex subject is not a Subject Identifier, so it cannot
     * be an alias either.
     */
    public static SubjectId aliases(List<SubjectId> identifiers) {
        if (identifiers == null || identifiers.isEmpty()) {
            throw new IllegalArgumentException("an aliases subject identifier needs at least one identifier");
        }
        List<Object> maps = new ArrayList<>();
        for (SubjectId id : identifiers) {
            if (id.isComplex() || FORMAT_ALIASES.equals(id.format())) {
                throw new IllegalArgumentException("an aliases subject identifier cannot hold a " + id.format()
                        + " subject");
            }
            maps.add(id.members);
        }
        return of(FORMAT_ALIASES, "identifiers", List.copyOf(maps));
    }

    /**
     * SSF 1.0 §3.3 — a complex subject: one or more named members, each a Subject Identifier. The names are
     * usually from {@link #COMPLEX_MEMBERS}; "format" is the discriminator and cannot be a member name, and a
     * complex subject cannot be a member of another.
     */
    public static SubjectId complex(Map<String, SubjectId> subjectMembers) {
        if (subjectMembers == null || subjectMembers.isEmpty()) {
            throw new IllegalArgumentException("a complex subject needs at least one member");
        }
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_COMPLEX);
        for (Map.Entry<String, SubjectId> e : subjectMembers.entrySet()) {
            String name = e.getKey();
            if (name == null || name.isBlank() || "format".equals(name)) {
                throw new IllegalArgumentException("a complex subject member needs a name other than \"format\"");
            }
            SubjectId value = Objects.requireNonNull(e.getValue(), name);
            if (value.isComplex()) {
                throw new IllegalArgumentException("complex subject member \"" + name + "\" is itself complex");
            }
            m.put(name, value.members);
        }
        return new SubjectId(m);
    }

    /**
     * Parse a subject from its JSON object form: any format in {@link #FORMATS}.
     *
     * @throws IllegalArgumentException if {@code format} is missing, blank or unsupported, or a member the format
     *                                  requires is absent or of the wrong shape
     */
    public static SubjectId fromMap(Map<String, Object> json) {
        return parse(json, FORMATS);
    }

    /**
     * Parse a subject, accepting only the formats in {@code accepted} at the top level. A caller that has not yet
     * learnt to act on a format - the ssf module keeps to the five it handles until H-SSF-1 - refuses it here with
     * the same message an unknown format gets. The members of a complex or aliases subject are not held to
     * {@code accepted}: once a caller accepts the container it accepts what the container may hold.
     */
    public static SubjectId fromMap(Map<String, Object> json, Set<String> accepted) {
        return parse(json, accepted);
    }

    @SuppressWarnings("unchecked")
    static SubjectId parse(Map<String, Object> json, Set<String> accepted) {
        if (json == null) {
            throw new IllegalArgumentException("subject identifier is required");
        }
        Object format = json.get("format");
        if (!(format instanceof String) || ((String) format).isBlank()) {
            throw new IllegalArgumentException("subject identifier requires a non-blank \"format\"");
        }
        if (!accepted.contains(format)) {
            throw new IllegalArgumentException("unsupported subject identifier format: " + format);
        }
        if (!FORMAT_COMPLEX.equals(format)) {
            return parseSimple(json);
        }
        LinkedHashMap<String, SubjectId> subjectMembers = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : json.entrySet()) {
            if ("format".equals(e.getKey())) {
                continue;
            }
            if (!(e.getValue() instanceof Map)) {
                throw new IllegalArgumentException("complex subject member \"" + e.getKey()
                        + "\" is not a subject identifier");
            }
            subjectMembers.put(e.getKey(), parseSimple((Map<String, Object>) e.getValue()));
        }
        return complex(subjectMembers);
    }

    /** A Subject Identifier: anything but a complex subject, which is where a complex subject's members come from. */
    @SuppressWarnings("unchecked")
    static SubjectId parseSimple(Map<String, Object> json) {
        Object format = json.get("format");
        if (!(format instanceof String) || ((String) format).isBlank()) {
            throw new IllegalArgumentException("subject identifier requires a non-blank \"format\"");
        }
        switch ((String) format) {
            case FORMAT_ISS_SUB:
                return issSub(requireString(json, "iss"), requireString(json, "sub"));
            case FORMAT_EMAIL:
                return email(requireString(json, "email"));
            case FORMAT_PHONE_NUMBER:
                return phoneNumber(requireString(json, "phone_number"));
            case FORMAT_OPAQUE:
                return opaque(requireString(json, "id"));
            case FORMAT_ACCOUNT:
                return account(requireString(json, "uri"));
            case FORMAT_DID:
                return did(requireString(json, "url"));
            case FORMAT_URI:
                return uri(requireString(json, "uri"));
            case FORMAT_JWT_ID:
                return jwtId(requireString(json, "iss"), requireString(json, "jti"));
            case FORMAT_SAML_ASSERTION_ID:
                return samlAssertionId(requireString(json, "issuer"), requireString(json, "assertion_id"));
            case FORMAT_IP_ADDRESSES:
                return ipAddresses(stringList(json.get("ip-addresses")));
            case FORMAT_ALIASES:
                Object identifiers = json.get("identifiers");
                if (!(identifiers instanceof List)) {
                    throw new IllegalArgumentException("an aliases subject identifier requires an \"identifiers\" array");
                }
                List<SubjectId> parsed = new ArrayList<>();
                for (Object o : (List<Object>) identifiers) {
                    if (!(o instanceof Map)) {
                        throw new IllegalArgumentException("an aliases identifier is not a subject identifier");
                    }
                    parsed.add(parseSimple((Map<String, Object>) o));
                }
                return aliases(parsed);
            case FORMAT_COMPLEX:
                throw new IllegalArgumentException("a complex subject cannot be a subject identifier's value");
            default:
                throw new IllegalArgumentException("unsupported subject identifier format: " + format);
        }
    }

    private static List<String> stringList(Object v) {
        if (!(v instanceof List)) {
            throw new IllegalArgumentException("an ip-addresses subject identifier requires an \"ip-addresses\" array");
        }
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            out.add(o instanceof String ? (String) o : null);
        }
        return out;
    }

    static String requireString(Map<String, Object> json, String key) {
        Object v = json.get(key);
        if (!(v instanceof String) || ((String) v).isBlank()) {
            throw new IllegalArgumentException("subject identifier of this format requires a non-blank \"" + key + "\"");
        }
        return (String) v;
    }

    /**
     * Inverse of {@link #canonicalKey()} — reconstruct a subject from its canonical-key string.
     *
     * @throws IllegalArgumentException if {@code key} is not a canonical key this class writes
     */
    @SuppressWarnings("unchecked")
    public static SubjectId fromCanonicalKey(String key) {
        if (key == null || key.indexOf(':') < 0) {
            throw new IllegalArgumentException("not a subject canonical key: " + key);
        }
        int i = key.indexOf(':');
        String fmt = key.substring(0, i);
        String rest = key.substring(i + 1);
        switch (fmt) {
            case FORMAT_ISS_SUB:
                int sp = rest.indexOf(' ');
                if (sp < 0) {
                    throw new IllegalArgumentException("malformed iss_sub canonical key: " + key);
                }
                return issSub(rest.substring(0, sp), rest.substring(sp + 1));
            case FORMAT_EMAIL:
                return email(rest);
            case FORMAT_PHONE_NUMBER:
                return phoneNumber(rest);
            case FORMAT_OPAQUE:
                return opaque(rest);
            case FORMAT_ACCOUNT:
                return account(rest);
            case FORMAT_DID:
                return did(rest);
            case FORMAT_URI:
                return uri(rest);
            case FORMAT_JWT_ID:
            case FORMAT_SAML_ASSERTION_ID:
            case FORMAT_IP_ADDRESSES:
            case FORMAT_ALIASES:
            case FORMAT_COMPLEX:
                Map<String, Object> json;
                try {
                    json = JsonUtil.parseJson(rest);
                } catch (JoseException | RuntimeException e) {
                    throw new IllegalArgumentException("malformed " + fmt + " canonical key: " + key);
                }
                if (json.containsKey("format")) {
                    throw new IllegalArgumentException("malformed " + fmt + " canonical key: " + key);
                }
                LinkedHashMap<String, Object> withFormat = new LinkedHashMap<>();
                withFormat.put("format", fmt);
                withFormat.putAll(json);
                return parse(withFormat, FORMATS);
            default:
                throw new IllegalArgumentException("unsupported subject format in canonical key: " + fmt);
        }
    }

    public String format() {
        return (String) this.members.get("format");
    }

    /** True for an SSF 1.0 §3.3 complex subject. */
    public boolean isComplex() {
        return FORMAT_COMPLEX.equals(format());
    }

    /**
     * A complex subject's member, as a Subject Identifier, or null when it has none by that name (or is not
     * complex).
     */
    @SuppressWarnings("unchecked")
    public SubjectId member(String name) {
        if (!isComplex() || "format".equals(name) || !this.members.containsKey(name)) {
            return null;
        }
        return new SubjectId((Map<String, Object>) this.members.get(name));
    }

    /** The subject as a JSON-serialisable map (a copy; nested members are read-only). */
    public Map<String, Object> toMap() {
        return new LinkedHashMap<>(this.members);
    }

    /**
     * A stable string key for this subject, suitable for use as a store key or Kafka message key. Deterministic
     * across equal subjects and distinct across formats. The five formats the ssf module stored before 0.5.0 keep
     * the keys they had; the others are the format, a colon and their members (less {@code format}) as JSON with
     * object members in name order, so a complex subject's key does not depend on the order its members arrived
     * in. An aliases list keeps its order: RFC 9493 gives the order no meaning, but two orders are two keys.
     */
    public String canonicalKey() {
        switch (format()) {
            case FORMAT_ISS_SUB:
                return FORMAT_ISS_SUB + ":" + this.members.get("iss") + " " + this.members.get("sub");
            case FORMAT_EMAIL:
                return FORMAT_EMAIL + ":" + this.members.get("email");
            case FORMAT_PHONE_NUMBER:
                return FORMAT_PHONE_NUMBER + ":" + this.members.get("phone_number");
            case FORMAT_OPAQUE:
                return FORMAT_OPAQUE + ":" + this.members.get("id");
            case FORMAT_ACCOUNT:
                return FORMAT_ACCOUNT + ":" + this.members.get("uri");
            case FORMAT_DID:
                return FORMAT_DID + ":" + this.members.get("url");
            case FORMAT_URI:
                return FORMAT_URI + ":" + this.members.get("uri");
            default:
                Map<String, Object> rest = new LinkedHashMap<>(this.members);
                rest.remove("format");
                return format() + ":" + JsonUtil.toJson((Map<String, ?>) sorted(rest));
        }
    }

    @SuppressWarnings("unchecked")
    private static Object sorted(Object v) {
        if (v instanceof Map) {
            TreeMap<String, Object> t = new TreeMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                t.put(e.getKey(), sorted(e.getValue()));
            }
            return t;
        }
        if (v instanceof List) {
            List<Object> l = new ArrayList<>();
            for (Object o : (List<Object>) v) {
                l.add(sorted(o));
            }
            return l;
        }
        return v;
    }

    /**
     * SSF 1.0 §8.1.3.1 subject matching: "In the case of Simple Subjects, two subjects match if they are exactly
     * identical. For Complex Subjects, two subjects match if, for all fields in the Complex Subject (i.e. user,
     * group, device, etc.), at least one of the following statements is true: Subject 1's field is not defined;
     * Subject 2's field is not defined; Subject 1's field is identical to Subject 2's field". The section says
     * nothing of a simple subject against a complex one, so those match only when identical, which they never
     * are.
     */
    public boolean matches(SubjectId other) {
        if (other == null) {
            return false;
        }
        if (!isComplex() || !other.isComplex()) {
            return equals(other);
        }
        for (Map.Entry<String, Object> e : this.members.entrySet()) {
            Object theirs = other.members.get(e.getKey());
            if (theirs != null && !theirs.equals(e.getValue())) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SubjectId)) {
            return false;
        }
        return this.members.equals(((SubjectId) o).members);
    }

    @Override
    public int hashCode() {
        return this.members.hashCode();
    }

    @Override
    public String toString() {
        return canonicalKey();
    }
}
