package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** What every {@link TrustMarkRegistry} does, whatever keeps the grants. */
abstract class TrustMarkRegistryContract {
    static final String CERTIFIED = "https://pf.example.com/marks/certified";
    static final String AUDITED = "https://pf.example.com/marks/audited";
    static final String AGENT = "https://pf.example.com/federation/agents/a1";
    static final String OTHER = "https://pf.example.com/federation/agents/a2";

    protected final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));

    protected abstract TrustMarkRegistry newRegistry() throws Exception;

    @Test
    void aGrantIsFoundAsItWasGiven() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        Instant notAfter = this.clock.instant().plus(Duration.ofDays(30));

        TrustMarkGrant granted = registry.grant(CERTIFIED, AGENT, notAfter, "admin:1234");

        assertEquals(granted, registry.find(CERTIFIED, AGENT).orElseThrow());
        assertEquals(TrustMarkGrant.Status.ACTIVE, granted.status());
        assertEquals(this.clock.instant(), granted.grantedAt());
        assertEquals(notAfter, granted.notAfter());
        assertNull(granted.revokedAt());
        assertEquals("admin:1234", granted.actor());
        assertTrue(registry.find(AUDITED, AGENT).isEmpty());
    }

    @Test
    void grantsAreListedBySubjectAndByType() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        registry.grant(CERTIFIED, AGENT, null, null);
        registry.grant(AUDITED, AGENT, null, null);
        registry.grant(CERTIFIED, OTHER, null, null);

        assertEquals(List.of(AUDITED, CERTIFIED), registry.grantsTo(AGENT).stream().map(TrustMarkGrant::type).sorted().toList());
        assertEquals(List.of(AGENT, OTHER), registry.grantsOf(CERTIFIED).stream().map(TrustMarkGrant::subject).sorted().toList());
        assertEquals(List.of(), registry.grantsTo("https://pf.example.com/federation/agents/none"));
    }

    @Test
    void aRevokedGrantIsKeptMarkedRevokedAndRevokingItAgainChangesNothing() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        registry.grant(CERTIFIED, AGENT, null, "admin:1");
        this.clock.advance(Duration.ofMinutes(5));

        TrustMarkGrant revoked = registry.revoke(CERTIFIED, AGENT, "audit failed", "admin:2");
        this.clock.advance(Duration.ofMinutes(5));

        assertEquals(TrustMarkGrant.Status.REVOKED, revoked.status());
        assertEquals(this.clock.instant().minus(Duration.ofMinutes(5)), revoked.revokedAt());
        assertEquals("audit failed", revoked.reason());
        assertEquals("admin:2", revoked.actor());
        assertEquals(revoked, registry.revoke(CERTIFIED, AGENT, "again", "admin:3"));
        assertEquals(revoked, registry.find(CERTIFIED, AGENT).orElseThrow());
    }

    @Test
    void grantingAgainStartsTheGrantAfresh() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        registry.grant(CERTIFIED, AGENT, null, null);
        registry.revoke(CERTIFIED, AGENT, "lapsed", null);
        this.clock.advance(Duration.ofHours(1));

        TrustMarkGrant again = registry.grant(CERTIFIED, AGENT, null, "admin:9");

        assertEquals(TrustMarkGrant.Status.ACTIVE, again.status());
        assertEquals(this.clock.instant(), again.grantedAt());
        assertNull(again.revokedAt());
        assertNull(again.reason());
    }

    @Test
    void onlyAGrantThatExistsCanBeRevoked() throws Exception {
        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class,
                () -> this.newRegistry().revoke(CERTIFIED, AGENT, "no such grant", null));

        assertEquals(AuthorityRegistryException.NOT_FOUND, e.reason());
    }

    @Test
    void everyChangeLeavesAnAuditLine() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        Instant notAfter = this.clock.instant().plus(Duration.ofDays(1));
        registry.grant(CERTIFIED, AGENT, notAfter, "admin:1");
        this.clock.advance(Duration.ofMinutes(1));
        registry.revoke(CERTIFIED, AGENT, "audit failed", "admin:2");
        registry.revoke(CERTIFIED, AGENT, "again", "admin:3");
        registry.grant(CERTIFIED, OTHER, null, null);

        List<TrustMarkAuditEntry> trail = registry.auditTrail(CERTIFIED, AGENT);

        assertEquals(List.of(TrustMarkAuditEntry.GRANTED, TrustMarkAuditEntry.REVOKED), trail.stream().map(TrustMarkAuditEntry::eventCode).toList(),
                "revoking a revoked grant changes nothing, so records nothing");
        assertEquals("not_after=" + notAfter, trail.get(0).detail());
        assertEquals("admin:1", trail.get(0).actor());
        assertEquals("audit failed", trail.get(1).detail());
        assertEquals("admin:2", trail.get(1).actor());
        assertEquals(this.clock.instant(), trail.get(1).at());
        assertNull(registry.auditTrail(CERTIFIED, OTHER).get(0).detail(), "a grant with no end says nothing of one");
    }
}
