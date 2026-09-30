/*
 * What the SCIM endpoint keeps about a user it was given.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.List;
import java.util.Objects;

/**
 * The SCIM endpoint's record of a user (plan item H-SSF-4): the subject its representation keys on, the two identifiers
 * a provisioner looks a user up by, and whether it is active. Which streams an active user is on is not kept here - the
 * stream subjects are the truth for that, whoever added them. {@code restoreStreams} is what a deactivation took the
 * subject off, so that a reactivation can put it back; it is empty while the user is active.
 *
 * <p>The SCIM {@code id} is the subject's canonical key ({@link #id()}), as it was before 0.6.0.
 *
 * @param subject        the SSF subject the user is
 * @param userName       the SCIM {@code userName}, or {@code null}
 * @param externalId     the SCIM {@code externalId}, or {@code null}
 * @param active         the SCIM {@code active}
 * @param restoreStreams the streams a deactivation removed the subject from; empty while active
 * @param createdAt      epoch seconds the record was first written
 * @param updatedAt      epoch seconds it was last written
 */
public record ScimUser(SubjectId subject, String userName, String externalId, boolean active, List<String> restoreStreams,
        long createdAt, long updatedAt) {

    public ScimUser {
        Objects.requireNonNull(subject, "subject");
        restoreStreams = restoreStreams == null ? List.of() : List.copyOf(restoreStreams);
    }

    /** The SCIM {@code id}: the subject's canonical key. */
    public String id() {
        return this.subject.canonicalKey();
    }
}
