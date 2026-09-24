package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * What the registration tests share: chains that parse (the validator is mocked, but the service reads the
 * chain it returns - the Immediate Superior, the stored first statement), the result that validator returns,
 * clients as this module stores them, and a service on a clock the test moves.
 */
final class RegistrationFixtures {
    static final String ANCHOR = "https://tc.example";
    static final String OP_ISSUER = "https://as.example.com";
    static final Map<String, Object> JWKS = jwks("k1", "abc");
    private static SigningKeyProvider signer;

    private RegistrationFixtures() {
    }

    static Map<String, Object> jwks(String kid, String x) {
        return Map.of("keys", List.of(Map.of("kty", "EC", "crv", "P-256", "x", x, "y", "def", "kid", kid)));
    }

    /** {@code subject}'s chain through {@code superior}: its Entity Configuration, then the statement about it. */
    static List<String> chain(String subject, String superior, Clock clock) {
        return chain(subject, superior, clock.instant().getEpochSecond() - 60L, JWKS, Map.of());
    }

    /** As above, the Entity Configuration issued at {@code leafIat} with these keys and metadata. */
    static List<String> chain(String subject, String superior, long leafIat, Map<String, Object> jwks, Map<String, Object> metadata) {
        String leaf = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", subject).claim("sub", subject)
                .claim("jwks", jwks).claim("metadata", metadata).claim("authority_hints", List.of(superior))
                .iat(leafIat).exp(leafIat + 3600L).unsigned().sign(null, Clock.systemUTC());
        String statement = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", superior).claim("sub", subject)
                .claim("jwks", jwks).iat(leafIat).exp(leafIat + 3600L).unsigned().sign(null, Clock.systemUTC());
        return List.of(leaf, statement);
    }

    /** What the validator returns for {@code chain}: this metadata by type, these types policed, expiring then (-1: unknown). */
    static TrustChainValidationResult result(String subject, List<String> chain, Map<String, Object> metadataByType,
                                             Set<String> policed, long expEpochSeconds) throws Exception {
        return new TrustChainValidationResult.Builder()
                .trustAnchorIssuer(ANCHOR)
                .leafSubject(subject)
                .resolvedMetadata(metadataByType)
                .trustChain(chain)
                .presentedTrustChain(chain)
                .leafEntityStatement(JwtCodec.parseUnverifiedClaims(chain.get(0)))
                .policedEntityTypes(policed)
                .expEpochSeconds(expEpochSeconds)
                .build();
    }

    /** Metadata an agent publishes to be registered automatically. */
    static Map<String, Object> agentMetadata(String... registrationTypes) {
        return Map.of(
                "client_registration_types", List.of(registrationTypes),
                "grant_types", List.of("client_credentials"),
                "token_endpoint_auth_method", "private_key_jwt",
                "scope", "read_accounts",
                "client_name", "Agent");
    }

    /** A client as this module stores it: its status, expiry (null: none recorded) and chain (null: none). */
    static Client federationClient(String clientId, String status, Long expiresAt, List<String> chain) {
        Client client = new Client();
        client.setClientId(clientId);
        Map<String, ParamValues> params = new HashMap<>();
        if (status != null) {
            params.put(FederationClientParams.STATUS, values(List.of(status)));
        }
        if (expiresAt != null) {
            params.put(FederationClientParams.EXPIRES_AT, values(List.of(Long.toString(expiresAt))));
        }
        if (chain != null) {
            params.put("trust_chain", values(chain));
        }
        client.setExtendedParams(params);
        return client;
    }

    static ParamValues values(List<String> elements) {
        ParamValues values = new ParamValues();
        values.setElements(new ArrayList<>(elements));
        return values;
    }

    static String param(Client client, String name) {
        return RegistrationService.extendedParamValue(client, name);
    }

    static RegistrationSettings settings(ExpiryEnforcement enforcement) {
        RegistrationSettings d = RegistrationSettings.DEFAULTS;
        return new RegistrationSettings(d.maxTtlSeconds(), d.minTtlSeconds(), d.refreshBeforeExpirySeconds(), enforcement,
                d.sweepIntervalSeconds(), d.failClosed());
    }

    static RegistrationService service(TrustChainValidator validator, ClientStore store, Clock clock, ExpiryEnforcement enforcement)
            throws JoseException {
        return new RegistrationService(new RegistrationConfiguration(ANCHOR, false), validator, store, signer(),
                new RegistrationLifetime(settings(enforcement), clock));
    }

    static synchronized SigningKeyProvider signer() throws JoseException {
        if (signer == null) {
            RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048);
            key.setKeyId("op-1");
            signer = new SigningKeyProvider() {
                @Override
                public String keyId() {
                    return "op-1";
                }

                @Override
                public RSAPrivateKey privateKey() {
                    return key.getRsaPrivateKey();
                }

                @Override
                public RSAPublicKey publicKey() {
                    return key.getRsaPublicKey();
                }
            };
        }
        return signer;
    }
}
