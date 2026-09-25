package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * What a validated chain resolves the subject's metadata to (OpenID Federation 1.0 §6.1.4.2, §6.2): its
 * immediate superior's {@code metadata} first, then every Subordinate Statement's {@code constraints}, then
 * the merged {@code metadata_policy}.
 */
class ChainResolutionTest {
    private static final String TA = "https://ta.example";
    private static final String INT = "https://int.example";
    private static final String INT2 = "https://int2.example";
    private static final String LEAF = "https://rp.example";
    private static final String OP = "https://op.example";
    private static final String RP = "openid_relying_party";
    private static final String CLIENT = "oauth_client";

    private static TrustChainValidationResult resolve(Federation f) {
        return f.validator(TA).validate(ValidationRequest.forSubject(LEAF).opIssuer(OP).presentedChain(f.chain(LEAF, TA)).build());
    }

    private static TrustChainValidationException refusal(Federation f) {
        return assertThrows(TrustChainValidationException.class, () -> resolve(f));
    }

    private static Federation.Builder base() {
        return Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT)
                .metadata(LEAF, RP, Map.of("client_name", "rp", "grant_types", List.of("authorization_code", "refresh_token")))
                .metadata(LEAF, CLIENT, Map.of("client_name", "agent"));
    }

    // ---- the superior's metadata --------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.1.1(1.12)", "OIDFED §6.1.4.2(2)"})
    void theImmediateSuperiorsMetadataOverridesTheSubjectsForTypesItHas() {
        Federation f = base().subordinate(INT, LEAF, s -> s.claim("metadata", Map.of(
                RP, Map.of("client_name", "named by the intermediate", "contacts", List.of("ops@int.example")),
                "openid_provider", Map.of("issuer", "https://nope.example")))).build();

        TrustChainValidationResult result = resolve(f);

        assertEquals("named by the intermediate", result.metadataFor(RP).get("client_name"));
        assertEquals(List.of("ops@int.example"), result.metadataFor(RP).get("contacts"));
        assertEquals(List.of("authorization_code", "refresh_token"), result.metadataFor(RP).get("grant_types"));
        assertEquals("agent", result.metadataFor(CLIENT).get("client_name"));
        assertFalse(result.resolvedMetadata().containsKey("openid_provider"),
                "a superior's metadata applies only to Entity Types the subject has");
    }

    @Test
    @Requirement("OIDFED §3.1.1(1.12)")
    void metadataHigherUpTheChainDoesNotReachTheSubject() {
        Federation f = base().subordinate(TA, INT, s -> s.claim("metadata", Map.of(RP, Map.of("client_name", "from the anchor"))))
                .build();

        assertEquals("rp", resolve(f).metadataFor(RP).get("client_name"),
                "metadata applies only to the subject of the statement carrying it");
    }

    @Test
    @Requirement("OIDFED §6.1.4.2(1)")
    void theSuperiorsMetadataIsAppliedBeforeThePolicy() {
        Federation f = base()
                .subordinate(INT, LEAF, s -> s.claim("metadata", Map.of(RP, Map.of("grant_types", List.of("implicit", "refresh_token")))))
                .metadataPolicy(TA, INT, RP, Map.of("grant_types", Map.of("subset_of", List.of("refresh_token", "authorization_code"))))
                .build();

        assertEquals(List.of("refresh_token"), resolve(f).metadataFor(RP).get("grant_types"));
    }

    // ---- constraints ---------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §6.2.1(7.1)", "OIDFED §6.2.1(7.2)", "OIDFED §6.2.1(7.3)"})
    void pathLengthsThatHold() {
        Federation.Builder fourLevels = Federation.builder().anchor(TA).intermediate(INT2, TA).intermediate(INT, INT2).leaf(LEAF, INT);
        assertEquals(TA, resolve(fourLevels.constraints(TA, INT2, Map.of("max_path_length", 2)).build()).trustAnchorIssuer());

        Federation mixed = Federation.builder().anchor(TA).intermediate(INT2, TA).intermediate(INT, INT2).leaf(LEAF, INT)
                .constraints(TA, INT2, Map.of("max_path_length", 2))
                .constraints(INT2, INT, Map.of("max_path_length", 1)).build();
        assertEquals(TA, resolve(mixed).trustAnchorIssuer());

        Federation nearest = Federation.builder().anchor(TA).intermediate(INT2, TA).intermediate(INT, INT2).leaf(LEAF, INT)
                .constraints(INT, LEAF, Map.of("max_path_length", 0)).build();
        assertEquals(TA, resolve(nearest).trustAnchorIssuer());
    }

    @Test
    @Requirement({"OIDFED §6.2.1(9.1)", "OIDFED §6.2(7)"})
    void aPathLongerThanTheAnchorAllowsIsInvalid() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT2, TA).intermediate(INT, INT2).leaf(LEAF, INT)
                .constraints(TA, INT2, Map.of("max_path_length", 1)).build();

        TrustChainValidationException e = refusal(f);

        assertEquals(Kind.CONSTRAINT, e.kind());
        assertEquals(TA, e.issuer());
        assertEquals(FederationError.INVALID_TRUST_CHAIN, e.error());
    }

    @Test
    @Requirement({"OIDFED §6.2.2(1)", "OIDFED §6.2.2(3)"})
    void theSubjectAndEveryIntermediateBelowTheSetterMustBeInsideThePermittedNames() {
        assertEquals(TA, resolve(base().constraints(TA, INT, Map.of("naming_constraints", Map.of("permitted", List.of(".example"))))
                .build()).trustAnchorIssuer());

        TrustChainValidationException e = refusal(base()
                .constraints(TA, INT, Map.of("naming_constraints", Map.of("permitted", List.of("int.example")))).build());
        assertEquals(Kind.CONSTRAINT, e.kind());
        assertTrue(e.getMessage().contains(LEAF), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §6.2.2(2)")
    void anExcludedNameFailsWhateverThePermittedListSays() {
        TrustChainValidationException e = refusal(base().constraints(TA, INT, Map.of("naming_constraints", Map.of(
                "permitted", List.of(".example"), "excluded", List.of("rp.example")))).build());

        assertEquals(Kind.CONSTRAINT, e.kind());
        assertTrue(e.getMessage().contains("excluded"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §6.2(4)")
    void anUnknownConstraintIsIgnored() {
        assertEquals(TA, resolve(base().constraints(TA, INT, Map.of("max_bananas", 3)).build()).trustAnchorIssuer());
    }

    @Test
    @Requirement({"OIDFED §6.2.3(1)", "OIDFED §6.2.3(2)"})
    void allowedEntityTypesRemoveTheOthersButNeverFederationEntity() {
        Federation f = base().metadata(LEAF, "federation_entity", Map.of("organization_name", "RP Ltd"))
                .constraints(TA, INT, Map.of("allowed_entity_types", List.of(RP))).build();

        TrustChainValidationResult result = resolve(f);

        assertEquals(Set.of(RP, "federation_entity"), result.resolvedMetadata().keySet());
        assertEquals(Set.of(CLIENT), result.entityTypesRemovedByConstraint());
    }

    @Test
    @Requirement({"OIDFED §6.2(7)", "OIDFED §6.2.3(2)"})
    void twoAllowedEntityTypesConstraintsBothApply() {
        Federation f = base()
                .constraints(TA, INT, Map.of("allowed_entity_types", List.of(RP, CLIENT)))
                .constraints(INT, LEAF, Map.of("allowed_entity_types", List.of(CLIENT, "openid_provider"))).build();

        assertEquals(Set.of(CLIENT), resolve(f).resolvedMetadata().keySet());
    }

    @Test
    @Requirement("OIDFED §6.2.3(1)")
    void anEmptyAllowedEntityTypesLeavesOnlyFederationEntity() {
        Federation f = base().metadata(LEAF, "federation_entity", Map.of("organization_name", "RP Ltd"))
                .constraints(TA, INT, Map.of("allowed_entity_types", List.of())).build();

        assertEquals(Set.of("federation_entity"), resolve(f).resolvedMetadata().keySet());
    }

    @Test
    @Requirement("OIDFED §6.2.3(2)")
    void aTypeRemovedByConstraintIsNotPoliced() {
        Federation f = base()
                .constraints(TA, INT, Map.of("allowed_entity_types", List.of(RP)))
                .metadataPolicy(TA, INT, CLIENT, Map.of("client_name", Map.of("value", "policed"))).build();

        TrustChainValidationResult result = resolve(f);

        assertFalse(result.resolvedMetadata().containsKey(CLIENT));
        assertEquals(Set.of(), result.policedEntityTypes());
    }

    // ---- policy across the chain ---------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §6.1.4.1(3)", "OIDFED §6.1.4.1(14.1)"})
    void policiesMergeAnchorFirstDownTheChain() {
        Federation f = base()
                .metadataPolicy(TA, INT, RP, Map.of("grant_types", Map.of("subset_of", List.of("authorization_code", "refresh_token"))))
                .metadataPolicy(INT, LEAF, RP, Map.of("grant_types", Map.of("subset_of", List.of("authorization_code")))).build();

        TrustChainValidationResult result = resolve(f);

        assertEquals(List.of("authorization_code"), result.metadataFor(RP).get("grant_types"));
        assertEquals(Set.of(RP), result.policedEntityTypes());
        assertTrue(result.isPoliced(RP));
    }

    @Test
    @Requirement("OIDFED §6.1.4.1(14.1)")
    void aPolicyConflictRefusesTheChainEvenForATypeTheSubjectDoesNotHave() {
        Federation f = base()
                .metadataPolicy(TA, INT, "openid_provider", Map.of("issuer", Map.of("value", "https://a.example")))
                .metadataPolicy(INT, LEAF, "openid_provider", Map.of("issuer", Map.of("value", "https://b.example"))).build();

        TrustChainValidationException e = refusal(f);

        assertEquals(Kind.POLICY, e.kind());
        assertEquals(FederationError.INVALID_METADATA, e.error());
    }

    @Test
    @Requirement("OIDFED §6.1.4.2(3)")
    void aPolicyForATypeTheSubjectDoesNotHaveDoesNotGiveItThatType() {
        Federation f = base()
                .metadataPolicy(TA, INT, "openid_provider", Map.of("issuer", Map.of("default", "https://defaulted.example"))).build();

        TrustChainValidationResult result = resolve(f);

        assertFalse(result.resolvedMetadata().containsKey("openid_provider"));
        assertEquals(Set.of(), result.policedEntityTypes());
    }

    @Test
    @Requirement("OIDFED §6.1.4.2(4)")
    void metadataThatViolatesThePolicyIsNotUsed() {
        Federation f = base().metadataPolicy(TA, INT, RP, Map.of("contacts", Map.of("essential", true))).build();

        TrustChainValidationException e = refusal(f);

        assertEquals(Kind.POLICY, e.kind());
        assertEquals(INT, e.issuer(), "named after the statement about the subject");
    }

    @Test
    @Requirement("OIDFED §6.1.4.1(14.1)")
    void aMergeConflictNamesTheStatementThatCouldNotBeMerged() {
        TrustChainValidationException e = refusal(base()
                .metadataPolicy(TA, INT, RP, Map.of("client_name", Map.of("value", "a")))
                .metadataPolicy(INT, LEAF, RP, Map.of("client_name", Map.of("value", "b"))).build());

        assertEquals(INT, e.issuer());
        assertTrue(e.getCause() instanceof MetadataPolicy.PolicyException);
    }
}
