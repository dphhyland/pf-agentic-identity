package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.TrustMarkIssuing;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

/**
 * What this entity issues as a Trust Mark Issuer (§7, §8.4-§8.6): a mark only under a grant that stands, to a hosted
 * entity only while it is active, and a status (§8.4.2) worked out from the mark and the grant it was minted under.
 */
class TrustMarkIssuerTest {
    private static final String PF = "https://pf.example.com";
    private static final String HOSTED = "https://pf.example.com/marks/hosted";
    private static final String OPEN = "https://pf.example.com/marks/open";
    private static final String AGENT = "https://pf.example.com/federation/agents/a1";
    private static final String STRANGER = "https://rp.example.org";

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);
    private final Set<String> activeHosted = new HashSet<>(Set.of(AGENT));

    private TrustMarkIssuer issuer(Map<String, TrustMarkType> types) {
        return new TrustMarkIssuer(types, this.registry, this.activeHosted::contains, this.clock);
    }

    private TrustMarkIssuer issuer() {
        Map<String, TrustMarkType> types = new LinkedHashMap<>();
        types.put(HOSTED, new TrustMarkType(HOSTED, 3600, TrustMarkType.Subjects.HOSTED, null, null, null));
        types.put(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, "delegation.jwt.here", "https://pf.example.com/about",
                "https://pf.example.com/logo.svg"));
        return this.issuer(types);
    }

    private JwtClaims mark(TrustMarkIssuer issuer, String type, String subject) {
        return issuer.mintable(PF, type, subject).orElseThrow().claims();
    }

    @Test
    void aMarkIsIssuedOnlyUnderAGrantThatStands() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        assertTrue(issuer.mintable(PF, OPEN, STRANGER).isEmpty(), "no grant");

        this.registry.grant(OPEN, STRANGER, this.clock.instant().plus(Duration.ofDays(1)), null);
        assertTrue(issuer.mintable(PF, OPEN, STRANGER).isPresent());

        this.clock.advance(Duration.ofDays(1));
        assertTrue(issuer.mintable(PF, OPEN, STRANGER).isEmpty(), "the grant has ended");

        this.registry.grant(OPEN, STRANGER, null, null);
        this.registry.revoke(OPEN, STRANGER, "withdrawn", null);
        assertTrue(issuer.mintable(PF, OPEN, STRANGER).isEmpty(), "revoked");
        assertTrue(issuer.mintable(PF, "https://pf.example.com/marks/unconfigured", STRANGER).isEmpty(), "a type this entity does not issue");
    }

    @Test
    void aTypeForHostedEntitiesIsHeldOnlyByAnActiveOne() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(HOSTED, AGENT, null, null);
        this.registry.grant(HOSTED, STRANGER, null, null);

        assertTrue(issuer.mintable(PF, HOSTED, AGENT).isPresent());
        assertTrue(issuer.mintable(PF, HOSTED, STRANGER).isEmpty(), "not hosted here, whatever the grant says");

        this.activeHosted.remove(AGENT);
        assertTrue(issuer.mintable(PF, HOSTED, AGENT).isEmpty(), "suspended or revoked");
    }

    @Test
    @Requirement({"OIDFED §7.1(2.2)", "OIDFED §7.1(2.4)", "OIDFED §7.1(2.6)", "OIDFED §7.1(2.8)", "OIDFED §7.1(2.12)", "OIDFED §7.1(2.16)"})
    void aMarkCarriesWhatSection7Point1Lists() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, null, null);

        TrustMarkIssuing.Mintable mintable = issuer.mintable(PF, OPEN, STRANGER).orElseThrow();
        JwtClaims claims = mintable.claims();

        assertEquals(PF, claims.getIssuer());
        assertEquals(STRANGER, claims.getSubject());
        assertEquals(OPEN, claims.getClaimValue("trust_mark_type"));
        assertEquals(this.clock.epochSecond(), claims.getIssuedAt().getValue());
        assertEquals(this.clock.epochSecond() + 3600, claims.getExpirationTime().getValue());
        assertEquals("delegation.jwt.here", claims.getClaimValue("delegation"));
        assertEquals("https://pf.example.com/about", claims.getClaimValue("ref"));
        assertEquals("https://pf.example.com/logo.svg", claims.getClaimValue("logo_uri"));
        assertNotEquals(claims.getJwtId(), issuer.mintable(PF, OPEN, STRANGER).orElseThrow().claims().getJwtId(), "each mark has its own jti");
        assertEquals(this.registry.find(OPEN, STRANGER).orElseThrow().grantedAt(), mintable.grantedAt());
    }

    @Test
    void aMarkNeverOutlivesItsGrant() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(HOSTED, AGENT, this.clock.instant().plus(Duration.ofMinutes(10)), null);

        JwtClaims claims = this.mark(issuer, HOSTED, AGENT);

        assertEquals(this.clock.epochSecond() + 600, claims.getExpirationTime().getValue());
        assertFalse(claims.hasClaim("delegation"));
        assertFalse(claims.hasClaim("ref"));
        assertFalse(claims.hasClaim("logo_uri"));
    }

    @Test
    @Requirement({"OIDFED §8.5(1)", "OIDFED §8.5.1(2.2)", "OIDFED §8.5.1(2.4)"})
    void theMarkedEntitiesAreThoseHoldingAValidMarkOfTheType() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(HOSTED, AGENT, null, null);
        this.registry.grant(HOSTED, STRANGER, null, null);
        this.registry.grant(HOSTED, "https://pf.example.com/federation/agents/a2", this.clock.instant().minusSeconds(1), null);
        this.registry.grant(OPEN, STRANGER, null, null);

        assertEquals(List.of(AGENT), issuer.marked(HOSTED, null), "not the stranger, nor a grant already ended");
        assertEquals(List.of(AGENT), issuer.marked(HOSTED, AGENT));
        assertEquals(List.of(), issuer.marked(HOSTED, STRANGER));
        assertEquals(List.of(STRANGER), issuer.marked(OPEN, null));
        assertEquals(List.of(), issuer.marked("https://pf.example.com/marks/unconfigured", null));
    }

    @Test
    void anEntityIsMarkedWhenItHoldsAMarkOfTheTypeOrOfAnyType() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, null, null);

        assertTrue(issuer.isMarked(STRANGER, null));
        assertTrue(issuer.isMarked(STRANGER, OPEN));
        assertFalse(issuer.isMarked(STRANGER, HOSTED));
        assertFalse(issuer.isMarked(AGENT, null));
        assertEquals(List.of(OPEN), issuer.typesHeldBy(STRANGER));
        assertEquals(List.of(HOSTED, OPEN), List.copyOf(issuer.types()), "in the order configured");
        assertEquals(Optional.empty(), issuer.type(null));
        assertEquals(OPEN, issuer.type(OPEN).orElseThrow().id());
    }

    // ---- status (§8.4.2) ----------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §8.4.2(5.8)")
    void aMarkUnderAGrantThatStandsIsActive() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, null, null);

        assertEquals(Optional.of("active"), issuer.status(this.mark(issuer, OPEN, STRANGER)));
    }

    @Test
    @Requirement("OIDFED §8.4.2(5.8.2.6)")
    void aMarkWhoseGrantWasRevokedOrGivenAgainSinceIsRevoked() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, null, null);
        JwtClaims mark = this.mark(issuer, OPEN, STRANGER);

        this.registry.revoke(OPEN, STRANGER, "withdrawn", null);
        assertEquals(TrustMarkIssuer.Status.REVOKED, issuer.statusOf(mark));

        this.clock.advance(Duration.ofSeconds(1));
        this.registry.grant(OPEN, STRANGER, null, null);
        assertEquals(TrustMarkIssuer.Status.REVOKED, issuer.statusOf(mark), "granting again does not revive a mark minted before");
        assertEquals(TrustMarkIssuer.Status.ACTIVE, issuer.statusOf(this.mark(issuer, OPEN, STRANGER)));
    }

    @Test
    void aMarkForAHostedEntityThatNoLongerResolvesIsRevoked() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(HOSTED, AGENT, null, null);
        JwtClaims mark = this.mark(issuer, HOSTED, AGENT);

        this.activeHosted.remove(AGENT);

        assertEquals(TrustMarkIssuer.Status.REVOKED, issuer.statusOf(mark));
    }

    @Test
    void aMarkOfATypeNoLongerIssuedIsRevoked() throws Exception {
        this.registry.grant(OPEN, STRANGER, null, null);
        JwtClaims mark = this.mark(this.issuer(), OPEN, STRANGER);

        assertEquals(TrustMarkIssuer.Status.REVOKED, this.issuer(Map.of()).statusOf(mark));
    }

    @Test
    @Requirement("OIDFED §8.4.2(5.8.2.4)")
    void aMarkPastItsExpOrItsGrantsEndHasExpired() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, this.clock.instant().plus(Duration.ofDays(2)), null);
        JwtClaims mark = this.mark(issuer, OPEN, STRANGER);

        this.clock.advance(Duration.ofHours(1));
        assertEquals(TrustMarkIssuer.Status.EXPIRED, issuer.statusOf(mark), "its own exp");

        JwtClaims noExp = this.mark(issuer, OPEN, STRANGER);
        noExp.unsetClaim("exp");
        assertEquals(TrustMarkIssuer.Status.ACTIVE, issuer.statusOf(noExp));
        this.clock.advance(Duration.ofDays(2));
        assertEquals(TrustMarkIssuer.Status.EXPIRED, issuer.statusOf(noExp), "its grant's end");
    }

    /** §8.4.2: "something it did not issue or is not aware of" is a 404, which the endpoint answers for an empty status. */
    @Test
    @Requirement("OIDFED §8.4.2(12)")
    void aMarkThereIsNoGrantForIsUnknown() {
        TrustMarkIssuer issuer = this.issuer();
        JwtClaims mark = new JwtClaims();
        mark.setClaim("trust_mark_type", OPEN);
        mark.setSubject(STRANGER);
        mark.setIssuedAt(NumericDate.fromSeconds(this.clock.epochSecond()));

        assertEquals(Optional.empty(), issuer.status(mark));
        mark.unsetClaim("trust_mark_type");
        assertEquals(TrustMarkIssuer.Status.UNKNOWN, issuer.statusOf(mark));
        mark.setClaim("trust_mark_type", OPEN);
        mark.unsetClaim("sub");
        assertEquals(TrustMarkIssuer.Status.UNKNOWN, issuer.statusOf(mark));
    }

    @Test
    void aMarkWithoutIatWasNotMintedUnderTheGrant() throws Exception {
        TrustMarkIssuer issuer = this.issuer();
        this.registry.grant(OPEN, STRANGER, null, null);
        JwtClaims mark = this.mark(issuer, OPEN, STRANGER);
        mark.unsetClaim("iat");

        assertEquals(TrustMarkIssuer.Status.REVOKED, issuer.statusOf(mark));
    }

    @Test
    void aRegistryThatFailsIsThisServersFault() {
        TrustMarkRegistry failing = new TrustMarkRegistry() {
            @Override
            public TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }
        };
        TrustMarkIssuer issuer = new TrustMarkIssuer(Map.of(OPEN, new TrustMarkType(OPEN, 60, TrustMarkType.Subjects.ANY, null, null, null)),
                failing, id -> true, this.clock);

        assertEquals(FederationError.SERVER_ERROR, assertThrows(FederationException.class, () -> issuer.mintable(PF, OPEN, STRANGER)).error());
        assertEquals(FederationError.SERVER_ERROR, assertThrows(FederationException.class, () -> issuer.marked(OPEN, null)).error());
    }
}
