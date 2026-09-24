/*
 * Trust Mark grants held in memory.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** A {@link TrustMarkRegistry} for tests and a single-node demo: nothing survives a restart. */
public final class InMemoryTrustMarkRegistry implements TrustMarkRegistry {
    private final Clock clock;
    private final Map<String, TrustMarkGrant> grants = new LinkedHashMap<>();
    private final List<TrustMarkAuditEntry> audit = new ArrayList<>();

    public InMemoryTrustMarkRegistry(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    private static String key(String type, String subject) {
        return type + "\n" + subject;
    }

    @Override
    public synchronized TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) {
        Instant now = this.clock.instant();
        TrustMarkGrant granted = new TrustMarkGrant(type, subject, TrustMarkGrant.Status.ACTIVE, now, notAfter, null, null, actor);
        this.grants.put(key(type, subject), granted);
        this.audit.add(new TrustMarkAuditEntry(type, subject, TrustMarkAuditEntry.GRANTED, notAfter == null ? null : "not_after=" + notAfter,
                actor, now));
        return granted;
    }

    @Override
    public synchronized Optional<TrustMarkGrant> find(String type, String subject) {
        return Optional.ofNullable(this.grants.get(key(type, subject)));
    }

    @Override
    public synchronized List<TrustMarkGrant> grantsTo(String subject) {
        return this.grants.values().stream().filter(g -> g.subject().equals(subject)).toList();
    }

    @Override
    public synchronized List<TrustMarkGrant> grantsOf(String type) {
        return this.grants.values().stream().filter(g -> g.type().equals(type)).toList();
    }

    @Override
    public synchronized TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException {
        TrustMarkGrant current = this.grants.get(key(type, subject));
        if (current == null) {
            throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND, "no grant of " + type + " to " + subject);
        }
        if (current.status() == TrustMarkGrant.Status.REVOKED) {
            return current;
        }
        Instant now = this.clock.instant();
        TrustMarkGrant revoked = new TrustMarkGrant(type, subject, TrustMarkGrant.Status.REVOKED, current.grantedAt(), current.notAfter(),
                now, reason, actor);
        this.grants.put(key(type, subject), revoked);
        this.audit.add(new TrustMarkAuditEntry(type, subject, TrustMarkAuditEntry.REVOKED, reason, actor, now));
        return revoked;
    }

    @Override
    public synchronized List<TrustMarkAuditEntry> auditTrail(String type, String subject) {
        return this.audit.stream().filter(e -> e.type().equals(type) && e.subject().equals(subject)).toList();
    }
}
