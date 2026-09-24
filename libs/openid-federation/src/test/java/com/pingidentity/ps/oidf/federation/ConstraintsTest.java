package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The {@code constraints} claim on its own (OpenID Federation 1.0 §6.2): parsing, and each check. */
class ConstraintsTest {

    @Test
    void anAbsentClaimConstrainsNothing() {
        Constraints none = Constraints.parse(null);
        assertTrue(none.isEmpty());
        assertNull(none.checkPathLength(9));
        assertNull(none.checkNames(List.of("https://anything.example")));
        assertNull(none.allowedEntityTypes());
        assertFalse(Constraints.parse(Map.of("max_path_length", 0)).isEmpty());
        assertFalse(Constraints.parse(Map.of("naming_constraints", Map.of("excluded", List.of("a.example")))).isEmpty());
        assertFalse(Constraints.parse(Map.of("naming_constraints", Map.of("permitted", List.of("a.example")))).isEmpty());
        assertFalse(Constraints.parse(Map.of("allowed_entity_types", List.of())).isEmpty());
    }

    @Test
    @Requirement("OIDFED §6.2.1(2)")
    void maxPathLengthIsAnIntegerOfZeroOrMore() {
        assertNull(Constraints.parse(Map.of("max_path_length", 0L)).checkPathLength(1));
        assertNull(Constraints.parse(Map.of("max_path_length", 2.0)).checkPathLength(3));
        for (Object bad : List.of(-1, 1.5, "2", List.of(1))) {
            assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("max_path_length", bad)), String.valueOf(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse("constraints"));
    }

    @Test
    @Requirement({"OIDFED §6.2.1(1)", "OIDFED §6.2.1(9.1)"})
    void maxPathLengthCountsTheIntermediatesBetweenTheSetterAndTheSubject() {
        Constraints one = Constraints.parse(Map.of("max_path_length", 1));
        assertNull(one.checkPathLength(1), "the statement about the subject has no intermediate below it");
        assertNull(one.checkPathLength(2));
        assertTrue(one.checkPathLength(3).contains("max_path_length is 1"), one.checkPathLength(3));
    }

    @Test
    @Requirement("OIDFED §6.2.2(3)")
    void aLeadingDotIsASubtreeOfAtLeastOneMoreLabel() {
        assertTrue(Constraints.matches("host.example.com", ".example.com"));
        assertTrue(Constraints.matches("my.host.example.com", ".example.com"));
        assertFalse(Constraints.matches("example.com", ".example.com"));
        assertFalse(Constraints.matches("badexample.com", ".example.com"));
        assertTrue(Constraints.matches("host.example.com", "host.example.com"));
        assertFalse(Constraints.matches("my.host.example.com", "host.example.com"));
    }

    @Test
    void anIpLiteralMatchesOnlyItself() {
        assertTrue(Constraints.matches("192.0.2.1", "192.0.2.1"));
        assertFalse(Constraints.matches("192.0.2.1", ".2.1"));
        assertFalse(Constraints.matches("[2001:db8::1]", ".db8::1]"));
    }

    @Test
    @Requirement({"OIDFED §6.2.2(1)", "OIDFED §6.2.2(2)", "OIDFED §6.2.2(3)"})
    void namesAreCheckedOnTheHostCaseInsensitivelyAndExcludedWins() {
        Constraints c = Constraints.parse(Map.of("naming_constraints", Map.of(
                "permitted", List.of(".Example.COM"), "excluded", List.of("east.example.com"))));
        assertNull(c.checkNames(List.of("https://West.Example.com:8443/tenants/a", "https://a.b.example.com")));
        assertTrue(c.checkNames(List.of("https://east.example.com/org")).contains("excluded"));
        assertTrue(c.checkNames(List.of("https://example.org")).contains("outside"));

        Constraints excludedOnly = Constraints.parse(Map.of("naming_constraints", Map.of("excluded", List.of(".evil.example"))));
        assertNull(excludedOnly.checkNames(List.of("https://good.example")));
        assertTrue(excludedOnly.checkNames(List.of("https://x.evil.example")).contains("excluded"));
    }

    @Test
    void anEmptyPermittedListPermitsNothing() {
        Constraints c = Constraints.parse(Map.of("naming_constraints", Map.of("permitted", List.of())));
        assertTrue(c.checkNames(List.of("https://any.example")).contains("outside"));
    }

    @Test
    @Requirement("OIDFED §6.2.2(3)")
    void aNameConstraintIsADomainNameNotAUrl() {
        for (Object bad : List.of("https://example.com", "example.com/path", "example.com:443", "exa mple.com", ".", "", 7)) {
            assertThrows(IllegalArgumentException.class,
                    () -> Constraints.parse(Map.of("naming_constraints", Map.of("permitted", List.of(bad)))), String.valueOf(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("naming_constraints", List.of())));
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("naming_constraints", Map.of("excluded", "a.example"))));
    }

    @Test
    @Requirement("OIDFED §6.2.3(1)")
    void allowedEntityTypesListsEntityTypesButNeverFederationEntity() {
        assertEquals(Set.of("openid_provider"), Constraints.parse(Map.of("allowed_entity_types", List.of("openid_provider"))).allowedEntityTypes());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Constraints.parse(Map.of("allowed_entity_types", List.of("federation_entity"))));
        assertTrue(e.getMessage().contains("federation_entity"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("allowed_entity_types", "openid_provider")));
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("allowed_entity_types", List.of(" "))));
        assertThrows(IllegalArgumentException.class, () -> Constraints.parse(Map.of("allowed_entity_types", List.of(1))));
    }

    @Test
    @Requirement("OIDFED §6.2.3(2)")
    void filteringKeepsFederationEntityAndReportsWhatWasRemoved() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("federation_entity", Map.of());
        metadata.put("openid_relying_party", Map.of());
        metadata.put("oauth_client", Map.of());
        Set<String> removed = new LinkedHashSet<>();

        Map<String, Object> filtered = Constraints.filterEntityTypes(metadata, Set.of("oauth_client"), removed);

        assertEquals(Set.of("federation_entity", "oauth_client"), filtered.keySet());
        assertEquals(Set.of("openid_relying_party"), removed);
        assertSame(metadata, Constraints.filterEntityTypes(metadata, null, removed), "no constraint, no change");
    }

    @Test
    @Requirement("OIDFED §6.2(4)")
    void unknownConstraintParametersAreIgnored() {
        assertTrue(Constraints.parse(Map.of("max_bananas", 3)).isEmpty());
    }
}
