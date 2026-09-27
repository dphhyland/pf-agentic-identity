/*
 * The subject formats the SSF transmitter and receiver act on, until H-SSF-1 widens them.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.Map;
import java.util.Set;

/**
 * The subject formats this module accepts from outside - a stream's add and remove subject bodies, the emit API,
 * a SCIM subject id and an inbound SET's {@code sub_id}: the five RFC 9493 formats it has always handled.
 * shared-signals' {@link SubjectId} parses more (did, uri, aliases, SSF 1.0's three and the complex subject), but
 * nothing here stores, matches or acts on them yet - a complex subject needs SSF 1.0 §8.1.3.1's matching, not the
 * exact key a store compares - so they are refused as before, with the same message. Plan item H-SSF-1 widens
 * this set when the receiver and the stream store handle them.
 */
public final class SsfSubjects {

    /** The formats accepted from outside. */
    public static final Set<String> FORMATS = Set.of(SubjectId.FORMAT_ISS_SUB, SubjectId.FORMAT_EMAIL,
            SubjectId.FORMAT_PHONE_NUMBER, SubjectId.FORMAT_OPAQUE, SubjectId.FORMAT_ACCOUNT);

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
}
