/*
 * RFC 9493 Subject Identifiers for Security Event Tokens.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A Subject Identifier as defined by RFC 9493. Carried as the {@code sub_id} member of a SET and as the
 * add/remove-subject request body of the SSF stream API. Each identifier has a {@code format} discriminator
 * and format-specific members; this type models the formats this transmitter uses and round-trips them to
 * and from the JSON object representation.
 *
 * <p>Supported formats: {@code iss_sub}, {@code email}, {@code phone_number}, {@code opaque}, {@code account}.
 */
public final class SubjectId {

    public static final String FORMAT_ISS_SUB = "iss_sub";
    public static final String FORMAT_EMAIL = "email";
    public static final String FORMAT_PHONE_NUMBER = "phone_number";
    public static final String FORMAT_OPAQUE = "opaque";
    public static final String FORMAT_ACCOUNT = "account";

    private final Map<String, Object> members;

    private SubjectId(Map<String, Object> members) {
        this.members = Map.copyOf(members);
    }

    /** RFC 9493 §3.2.1 — an issuer and subject pair. */
    public static SubjectId issSub(String iss, String sub) {
        Objects.requireNonNull(iss, "iss");
        Objects.requireNonNull(sub, "sub");
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_ISS_SUB);
        m.put("iss", iss);
        m.put("sub", sub);
        return new SubjectId(m);
    }

    /** RFC 9493 §3.2.2 — an email address. */
    public static SubjectId email(String email) {
        Objects.requireNonNull(email, "email");
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_EMAIL);
        m.put("email", email);
        return new SubjectId(m);
    }

    /** RFC 9493 §3.2.3 — an E.164 phone number. */
    public static SubjectId phoneNumber(String phoneNumber) {
        Objects.requireNonNull(phoneNumber, "phoneNumber");
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_PHONE_NUMBER);
        m.put("phone_number", phoneNumber);
        return new SubjectId(m);
    }

    /** RFC 9493 §3.2.6 — an opaque, transmitter-defined identifier. */
    public static SubjectId opaque(String id) {
        Objects.requireNonNull(id, "id");
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_OPAQUE);
        m.put("id", id);
        return new SubjectId(m);
    }

    /** RFC 9493 §3.2.5 — an {@code acct:} URI. */
    public static SubjectId account(String acctUri) {
        Objects.requireNonNull(acctUri, "acctUri");
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("format", FORMAT_ACCOUNT);
        m.put("uri", acctUri);
        return new SubjectId(m);
    }

    /**
     * Parse a Subject Identifier from its JSON object form. Requires a non-blank {@code format} and the
     * members that format mandates.
     *
     * @throws IllegalArgumentException if {@code format} is missing/blank/unsupported or a required member is absent
     */
    @SuppressWarnings("unchecked")
    public static SubjectId fromMap(Map<String, Object> json) {
        if (json == null) {
            throw new IllegalArgumentException("subject identifier is required");
        }
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
            default:
                throw new IllegalArgumentException("unsupported subject identifier format: " + format);
        }
    }

    private static String requireString(Map<String, Object> json, String key) {
        Object v = json.get(key);
        if (!(v instanceof String) || ((String) v).isBlank()) {
            throw new IllegalArgumentException("subject identifier of this format requires a non-blank \"" + key + "\"");
        }
        return (String) v;
    }

    /** Inverse of {@link #canonicalKey()} — reconstruct a subject from its canonical-key string. */
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
            default:
                throw new IllegalArgumentException("unsupported subject format in canonical key: " + fmt);
        }
    }

    public String format() {
        return (String) this.members.get("format");
    }

    /** The identifier as a JSON-serialisable map (defensive copy). */
    public Map<String, Object> toMap() {
        return new LinkedHashMap<>(this.members);
    }

    /**
     * A stable string key for this subject, suitable for use as a store key or Kafka message key. Deterministic
     * across equal identifiers and distinct across formats.
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
            default:
                return format() + ":" + this.members;
        }
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
