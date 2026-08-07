package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link FederationService#listSubordinates(String)} — Phase 1.7: the untyped list still surfaces the
 * statically configured subordinates (which carry no verified type of their own), a typed request never
 * guesses at their type, and hosted-entity ids (already filtered by {@code listable}/resolvable/type by
 * the injected function) are always merged in regardless of filter.
 */
class FederationServiceListSubordinatesTest {

    private static final String ANCHOR = "https://anchor.example.com";

    @Test
    void untypedListIncludesBothStaticSubordinatesAndHostedIds() throws Exception {
        FederationService anchor = anchorWithHostedIds(
                List.of("https://static.example.com"),
                entityType -> List.of("https://anchor.example.com/agents/hosted-1"));

        List<String> listed = anchor.listSubordinates(null);
        assertEquals(Set.of("https://static.example.com", "https://anchor.example.com/agents/hosted-1"),
                Set.copyOf(listed));
    }

    @Test
    void typedRequestOmitsTheStaticSubordinatesEntirely() throws Exception {
        // The static list has no verified type — a typed filter must fail closed rather than guess, so
        // only the hosted-entity function (which itself understands types) contributes to a typed list.
        FederationService anchor = anchorWithHostedIds(
                List.of("https://static.example.com"),
                entityType -> "oauth_client".equals(entityType)
                        ? List.of("https://anchor.example.com/agents/hosted-1") : List.of());

        List<String> listed = anchor.listSubordinates("oauth_client");
        assertEquals(List.of("https://anchor.example.com/agents/hosted-1"), listed);
        assertTrue(!listed.contains("https://static.example.com"));
    }

    @Test
    void noHostedIdsFunctionConfiguredBehavesExactlyAsBeforeThisChange() throws Exception {
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of("https://static.example.com"), null, false, false,
                null, null, null, 0, "RS256", null);
        FederationService anchor = new FederationService(anchorConfig, anchorKeys);

        assertEquals(List.of("https://static.example.com"), anchor.listSubordinates(null));
        assertEquals(List.of(), anchor.listSubordinates("oauth_client"));
    }

    private static FederationService anchorWithHostedIds(List<String> staticSubordinates,
            java.util.function.Function<String, List<String>> hostedSubordinateIds) throws Exception {
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), staticSubordinates, null, false, false, null, null, null, 0, "RS256", null);
        return new FederationService(anchorConfig, anchorKeys, null, null, hostedSubordinateIds);
    }

    private static SigningKeyProvider testSigningKeys(String keyId) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return keyId;
            }

            @Override
            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) keyPair.getPrivate();
            }

            @Override
            public RSAPublicKey publicKey() {
                return (RSAPublicKey) keyPair.getPublic();
            }
        };
    }
}
