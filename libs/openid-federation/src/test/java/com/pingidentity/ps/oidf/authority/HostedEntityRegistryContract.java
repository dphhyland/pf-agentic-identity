/*
 * The semantics every HostedEntityRegistry implementation must satisfy identically.
 */
package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The registry's semantics, which the JDBC implementation must satisfy identically to the in-memory
 * one. Revocation, idempotency, the multi-type/list/listable filtering, and the append-only audit log
 * are the properties the rest of the authority relies on.
 */
abstract class HostedEntityRegistryContract {

    private HostedEntityRegistry registry;
    private String entityId;

    /** The implementation under test. Each subclass supplies a freshly-empty one. */
    protected abstract HostedEntityRegistry newRegistry() throws Exception;

    @BeforeEach
    void setUp() throws Exception {
        this.registry = newRegistry();
        this.entityId = "https://as.example.com/agents/agent-1";
        this.registry.register(newEntity(this.entityId));
    }

    private static HostedEntity newEntity(String entityId) {
        return HostedEntity.hosted(entityId, "openbao-key-ref-1",
                Map.of("oauth_client", Map.of("client_name", "Payment Agent"),
                        "oauth_resource", Map.of("resource", entityId)),
                "operator:dave");
    }

    @Test
    void aRegisteredEntityResolvesImmediately() throws Exception {
        HostedEntity found = this.registry.find(this.entityId).orElseThrow();
        assertEquals(EntityStatus.ACTIVE, found.status());
        assertTrue(found.resolvable(Instant.now()));
        assertTrue(found.hasType("oauth_client"));
        assertTrue(found.hasType("oauth_resource"));
        assertFalse(found.hasType("oauth_client_attester"));
    }

    @Test
    void registeringTheSameEntityIdTwiceIsRejected() {
        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class,
                () -> this.registry.register(newEntity(this.entityId)));
        assertEquals(AuthorityRegistryException.DUPLICATE, e.reason());
    }

    @Test
    void revocationStopsResolutionOnTheVeryNextLookup() throws Exception {
        assertTrue(this.registry.find(this.entityId).orElseThrow().resolvable(Instant.now()));
        this.registry.setStatus(this.entityId, EntityStatus.REVOKED, "compromised hosting key");
        assertFalse(this.registry.find(this.entityId).orElseThrow().resolvable(Instant.now()));
    }

    @Test
    void revokingTwiceIsIdempotentAndDoesNotDuplicateTheAuditEntry() throws Exception {
        this.registry.setStatus(this.entityId, EntityStatus.REVOKED, "first");
        this.registry.setStatus(this.entityId, EntityStatus.REVOKED, "retried");

        long revocations = this.registry.auditTrail(this.entityId).stream()
                .filter(e -> AuthorityAuditEntry.ENTITY_REVOKED.equals(e.eventCode()))
                .count();
        assertEquals(1L, revocations, "a retried revocation must not inflate the audit log");
    }

    @Test
    void aRevokedEntityCannotBeBroughtBack() throws Exception {
        this.registry.setStatus(this.entityId, EntityStatus.REVOKED, "compromised");
        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class,
                () -> this.registry.setStatus(this.entityId, EntityStatus.ACTIVE, "oops"));
        assertEquals(AuthorityRegistryException.STALE_UPDATE, e.reason());
    }

    @Test
    void suspensionIsReversible() throws Exception {
        this.registry.setStatus(this.entityId, EntityStatus.SUSPENDED, "under review");
        assertFalse(this.registry.find(this.entityId).orElseThrow().resolvable(Instant.now()));
        this.registry.setStatus(this.entityId, EntityStatus.ACTIVE, "review cleared");
        assertTrue(this.registry.find(this.entityId).orElseThrow().resolvable(Instant.now()));
    }

    @Test
    void unknownEntityIsNotFound() {
        assertEquals(AuthorityRegistryException.NOT_FOUND,
                assertThrows(AuthorityRegistryException.class,
                        () -> this.registry.setStatus("nope", EntityStatus.REVOKED, "x")).reason());
    }

    @Test
    void anEntityPastItsNotAfterIsNotResolvableEvenWhileActive() throws Exception {
        HostedEntity expiring = new HostedEntity("https://as.example.com/agents/expiring",
                HostingMode.AUTHORITY_SIGNED, "key-2", Map.of("oauth_client", Map.of()), Map.of(),
                EntityStatus.ACTIVE, false, "operator:dave", Instant.now().minusSeconds(120),
                Instant.now().minusSeconds(60));
        this.registry.register(expiring);
        assertFalse(this.registry.find(expiring.entityId()).orElseThrow().resolvable(Instant.now()));
    }

    // ---- listing --------------------------------------------------------------------------------

    @Test
    void listingDefaultsToNothingBecauseAgentsAreNotListableByDefault() throws Exception {
        assertTrue(this.registry.list(null).isEmpty(),
                "HostedEntity.hosted() defaults to listable=false; nothing should appear unrequested");
    }

    @Test
    void aListableEntityAppearsOnlyUnderItsOwnTypes() throws Exception {
        HostedEntity listable = new HostedEntity("https://as.example.com/resources/api-1",
                HostingMode.AUTHORITY_SIGNED, "key-3",
                Map.of("oauth_resource", Map.of("resource", "https://as.example.com/resources/api-1")),
                Map.of(), EntityStatus.ACTIVE, true, "operator:dave", Instant.now(), null);
        this.registry.register(listable);

        assertEquals(List.of(listable.entityId()),
                this.registry.list("oauth_resource").stream().map(HostedEntity::entityId).toList());
        assertTrue(this.registry.list("oauth_client").isEmpty(),
                "a resource-only entity must not appear under a type it does not hold");
        assertEquals(List.of(listable.entityId()),
                this.registry.list(null).stream().map(HostedEntity::entityId).toList(),
                "no type filter returns every listable entity");
    }

    @Test
    void aRevokedEntityDropsOutOfListingImmediately() throws Exception {
        HostedEntity listable = new HostedEntity("https://as.example.com/resources/api-2",
                HostingMode.AUTHORITY_SIGNED, "key-4", Map.of("oauth_resource", Map.of()), Map.of(),
                EntityStatus.ACTIVE, true, "operator:dave", Instant.now(), null);
        this.registry.register(listable);
        assertEquals(1, this.registry.list(null).size());

        this.registry.setStatus(listable.entityId(), EntityStatus.REVOKED, "decommissioned");
        assertTrue(this.registry.list(null).isEmpty());
    }

    // ---- metadata and key updates ----------------------------------------------------------------

    @Test
    void metadataCanBeReplacedWithoutChangingIdentityOrKey() throws Exception {
        Map<String, Object> updated = Map.of("oauth_client", Map.of("client_name", "Renamed Agent"));
        this.registry.updateMetadata(this.entityId, updated);

        HostedEntity found = this.registry.find(this.entityId).orElseThrow();
        assertEquals(updated, found.metadata());
        assertEquals("openbao-key-ref-1", found.hostingKeyRef(), "updating metadata must not touch the hosting key");
    }

    @Test
    void hostingKeyRotationChangesOnlyTheKeyReference() throws Exception {
        this.registry.rotateHostingKey(this.entityId, "openbao-key-ref-2");
        HostedEntity found = this.registry.find(this.entityId).orElseThrow();
        assertEquals("openbao-key-ref-2", found.hostingKeyRef());
        assertTrue(found.hasType("oauth_client"), "rotating the key must not touch published metadata");
    }

    // ---- audit ----------------------------------------------------------------------------------

    @Test
    void theAuditLogIsAppendOnlyAndOrdered() throws Exception {
        this.registry.updateMetadata(this.entityId, Map.of("oauth_client", Map.of()));
        this.registry.rotateHostingKey(this.entityId, "openbao-key-ref-2");
        this.registry.setStatus(this.entityId, EntityStatus.REVOKED, "done");

        List<String> codes = this.registry.auditTrail(this.entityId).stream()
                .map(AuthorityAuditEntry::eventCode).toList();
        assertEquals(List.of(
                AuthorityAuditEntry.ENTITY_REGISTERED,
                AuthorityAuditEntry.ENTITY_METADATA_UPDATED,
                AuthorityAuditEntry.ENTITY_KEY_ROTATED,
                AuthorityAuditEntry.ENTITY_REVOKED), codes);
    }

    @Test
    void anEntityConstructedWithConflictingHostingModeAndKeyIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new HostedEntity("https://as.example.com/x",
                HostingMode.AUTHORITY_SIGNED, null, Map.of(), Map.of(), EntityStatus.ACTIVE, false,
                null, Instant.now(), null));
        assertThrows(IllegalArgumentException.class, () -> new HostedEntity("https://as.example.com/x",
                HostingMode.SELF_SIGNED, "should-not-have-a-key", Map.of(), Map.of(), EntityStatus.ACTIVE,
                false, null, Instant.now(), null));
    }
}
