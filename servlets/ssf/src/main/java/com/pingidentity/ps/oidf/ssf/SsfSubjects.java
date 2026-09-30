/*
 * The subject formats the SSF transmitter and receiver accept, and how the receiver maps a subject to someone it can act on.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The subject formats this module accepts from outside, and the receiver's mapping of an inbound subject to the
 * PingFederate user key or registry device id its handlers act on (plan item H-SSF-1).
 *
 * <p>A stream's add and remove subject bodies, the emit API and a SCIM subject id keep to {@link #FORMATS}, the five
 * RFC 9493 formats the transmitter has always stored and matched: a complex subject there needs SSF 1.0 §8.1.3.1's
 * matching in the stream store, not the exact key it compares (HSSF2). An inbound SET's {@code sub_id} takes
 * {@link #RECEIVER_FORMATS}: those five, RFC 9493's {@code did}, {@code uri} and {@code aliases}, and SSF 1.0 §3.3's
 * complex subject. SSF 1.0's own three ({@code jwt_id}, {@code saml_assertion_id}, {@code ip-addresses}) name a token
 * or an address, never a user or a device, so they stay refused at the top level; inside a complex subject they may
 * appear as a member the receiver does not act on.
 *
 * <p>How a subject maps ({@link #userKey}, {@link #deviceId}), written down because a complex or aliases subject has
 * more than one candidate:
 *
 * <ul>
 *   <li>{@code iss_sub} maps to its {@code sub} only when its {@code iss} is one the receiver honours - the SET's own
 *       issuer, this PingFederate's SSF issuer, or one named in {@code OIDF_SSF_RECEIVER_SUBJECT_ISSUERS}. RFC 9493 §3.2.3 has the members "follow the formats of the "iss"
 *       member and "sub" member defined by [RFC7519]", and RFC 7519 §4.1.2 scopes a subject "to be locally unique
 *       in the context of the issuer or be globally unique": a {@code sub} another issuer assigned could name a
 *       different person who happens to share the value here.</li>
 *   <li>{@code email}, {@code phone_number}, {@code opaque}, {@code account}, {@code did} and {@code uri} map to their
 *       one member's value, as the first four always have.</li>
 *   <li>{@code aliases} (RFC 9493 §3.2.8: every identifier "MUST identify the same entity", and it is "unknown which
 *       of those identifiers they will recognize") maps by the first of its identifiers that maps, taken in
 *       {@link #USER_PREFERENCE} order - the issuer-qualified {@code iss_sub} first, the free-form {@code uri} last -
 *       not in the order the transmitter listed them.</li>
 *   <li>A complex subject maps a user by its {@code user} member and a device by its {@code device} member (SSF 1.0
 *       §3.3); the instance-registry handler asks for the device first and falls back to the user. Its other members
 *       ({@code session}, {@code application}, {@code tenant}, {@code org_unit}, {@code group} and any other name)
 *       narrow the subject and are not acted on.</li>
 * </ul>
 *
 * A subject that does not map is refused with a {@link Mapping#refusal() reason} that names why; the handler logs it
 * and counts it, and acts on nothing.
 */
public final class SsfSubjects {

    /** The formats accepted from outside by the transmitter: a stream's subjects, the emit API, SCIM. */
    public static final Set<String> FORMATS = Set.of(SubjectId.FORMAT_ISS_SUB, SubjectId.FORMAT_EMAIL,
            SubjectId.FORMAT_PHONE_NUMBER, SubjectId.FORMAT_OPAQUE, SubjectId.FORMAT_ACCOUNT);

    /** The formats an inbound SET's {@code sub_id} may take at the top level (H-SSF-1). */
    public static final Set<String> RECEIVER_FORMATS = Set.of(SubjectId.FORMAT_ISS_SUB, SubjectId.FORMAT_EMAIL,
            SubjectId.FORMAT_PHONE_NUMBER, SubjectId.FORMAT_OPAQUE, SubjectId.FORMAT_ACCOUNT, SubjectId.FORMAT_DID,
            SubjectId.FORMAT_URI, SubjectId.FORMAT_ALIASES, SubjectId.FORMAT_COMPLEX);

    /** The order an aliases subject's identifiers are tried in when mapping a user. */
    public static final List<String> USER_PREFERENCE = List.of(SubjectId.FORMAT_ISS_SUB, SubjectId.FORMAT_EMAIL,
            SubjectId.FORMAT_ACCOUNT, SubjectId.FORMAT_PHONE_NUMBER, SubjectId.FORMAT_OPAQUE, SubjectId.FORMAT_DID,
            SubjectId.FORMAT_URI);

    /** The complex-subject members the receiver acts on; any other member narrows the subject and is not acted on. */
    public static final Set<String> ACTED_ON_MEMBERS = Set.of("user", "device");

    /** A subject's mapping: the value it maps to, or why it maps to nothing. */
    public record Mapping(String value, String refusal) {

        static Mapping to(String value) {
            return new Mapping(value, null);
        }

        static Mapping refused(String reason) {
            return new Mapping(null, reason);
        }

        /** Whether the subject mapped. */
        public boolean mapped() {
            return this.value != null;
        }
    }

    private SsfSubjects() {
    }

    /** {@link SubjectId#fromMap(Map, Set)} with {@link #FORMATS}. */
    public static SubjectId parse(Map<String, Object> json) {
        return SubjectId.fromMap(json, FORMATS);
    }

    /** {@link SubjectId#fromCanonicalKey}, refusing a format outside {@link #FORMATS}. */
    public static SubjectId fromCanonicalKey(String key) {
        SubjectId subject = SubjectId.fromCanonicalKey(key);
        if (!FORMATS.contains(subject.format())) {
            throw new IllegalArgumentException("unsupported subject format in canonical key: " + subject.format());
        }
        return subject;
    }

    /**
     * The PingFederate user key {@code subject} names, honouring an {@code iss_sub}'s issuer: it maps only when its
     * {@code iss} is in {@code issuers}.
     */
    public static Mapping userKey(SubjectId subject, Set<String> issuers) {
        if (subject == null) {
            return Mapping.refused("the SET has no subject");
        }
        if (subject.isComplex()) {
            SubjectId user = subject.member("user");
            if (user == null) {
                return Mapping.refused("the complex subject has no user member");
            }
            Mapping m = userKey(user, issuers);
            return m.mapped() ? m : Mapping.refused("the complex subject's user member: " + m.refusal());
        }
        if (SubjectId.FORMAT_ALIASES.equals(subject.format())) {
            return firstOf(aliases(subject), issuers);
        }
        return simpleUserKey(subject, issuers);
    }

    /**
     * The registry device id {@code subject} names: an {@code opaque} subject's {@code id}, a complex subject's
     * {@code device} member when that is {@code opaque}, or an aliases subject's first {@code opaque} identifier.
     */
    public static Mapping deviceId(SubjectId subject) {
        if (subject == null) {
            return Mapping.refused("the SET has no subject");
        }
        if (subject.isComplex()) {
            SubjectId device = subject.member("device");
            if (device == null) {
                return Mapping.refused("the complex subject has no device member");
            }
            Mapping m = deviceId(device);
            return m.mapped() ? m : Mapping.refused("the complex subject's device member: " + m.refusal());
        }
        if (SubjectId.FORMAT_ALIASES.equals(subject.format())) {
            for (SubjectId id : aliases(subject)) {
                if (SubjectId.FORMAT_OPAQUE.equals(id.format())) {
                    return deviceId(id);
                }
            }
            return Mapping.refused("no identifier of the aliases subject is opaque, the format a device is named in");
        }
        if (!SubjectId.FORMAT_OPAQUE.equals(subject.format())) {
            return Mapping.refused("a " + subject.format() + " subject does not name a device (only opaque does)");
        }
        return valueOf(subject, "id");
    }

    private static Mapping firstOf(List<SubjectId> identifiers, Set<String> issuers) {
        List<String> refusals = new ArrayList<>();
        for (String format : USER_PREFERENCE) {
            for (SubjectId id : identifiers) {
                if (!format.equals(id.format())) {
                    continue;
                }
                Mapping m = simpleUserKey(id, issuers);
                if (m.mapped()) {
                    return m;
                }
                refusals.add(m.refusal());
            }
        }
        return Mapping.refused("no identifier of the aliases subject maps to a user"
                + (refusals.isEmpty() ? "" : " (" + String.join("; ", refusals) + ")"));
    }

    private static Mapping simpleUserKey(SubjectId subject, Set<String> issuers) {
        switch (subject.format()) {
            case SubjectId.FORMAT_ISS_SUB: {
                Object iss = subject.toMap().get("iss");
                if (!issuers.contains(iss)) {
                    return Mapping.refused("the iss_sub subject's iss '" + iss + "' is neither the SET's issuer nor this"
                            + " PingFederate's, so its sub names nobody here");
                }
                return valueOf(subject, "sub");
            }
            case SubjectId.FORMAT_EMAIL:
                return valueOf(subject, "email");
            case SubjectId.FORMAT_OPAQUE:
                return valueOf(subject, "id");
            case SubjectId.FORMAT_PHONE_NUMBER:
                return valueOf(subject, "phone_number");
            case SubjectId.FORMAT_ACCOUNT:
            case SubjectId.FORMAT_URI:
                return valueOf(subject, "uri");
            case SubjectId.FORMAT_DID:
                return valueOf(subject, "url");
            default:
                return Mapping.refused("a " + subject.format() + " subject names a token or an address, not a user");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<SubjectId> aliases(SubjectId subject) {
        List<SubjectId> out = new ArrayList<>();
        for (Object o : (List<Object>) subject.toMap().get("identifiers")) {
            out.add(SubjectId.fromMap((Map<String, Object>) o));
        }
        return out;
    }

    private static Mapping valueOf(SubjectId subject, String member) {
        Object v = subject.toMap().get(member);
        return Mapping.to((String) v);
    }
}
