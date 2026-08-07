/*
 * The human who owns a device. The only record that names a person.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;

/**
 * The owning user. This is the terminus of the pseudonymity chain: an instance identifier resolves to a
 * device, a device to one of these, and only here is there anything that identifies a person.
 *
 * @param id             the registry's own identifier, distinct from the IdP subject so the two can be
 *                       rotated independently and so a leaked registry key is not itself an IdP handle
 * @param pingOneSubject the authenticated subject from PingOne
 * @param createdAt      first enrolment by this user
 */
public record OwnerUser(String id, String pingOneSubject, Instant createdAt) {

    public OwnerUser {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (pingOneSubject == null || pingOneSubject.isBlank()) {
            throw new IllegalArgumentException("pingOneSubject must not be blank");
        }
    }
}
