package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;

/**
 * The client an RP becomes when it registers at the authorization or PAR endpoint (OpenID Federation 1.0 §12.1.1):
 * authenticated by its keys, held to its redirect URIs and to what it declared, and to the way it proved itself.
 */
class FederationClientBuilderTest {

    private static final String RP = "https://rp.example.com";
    private static final RpKeyMaterial.Keys INLINE = new RpKeyMaterial.Keys(List.of(), "{\"keys\":[]}", null, "jwks");
    private static final RpKeyMaterial.Keys BY_REFERENCE = new RpKeyMaterial.Keys(List.of(), null, RP + "/jwks", "jwks_uri");
    private static final FederationClientBuilder.Provenance PROVENANCE = new FederationClientBuilder.Provenance(
            "auto_registered", List.of("leaf", "statement"), 1234L, "https://ta.example", "openid_relying_party");

    /**
     * Every JWE key-management {@code alg} in the IANA JSON Web Signature and Encryption Algorithms registry (RFC 7518
     * §4.1, RFC 8037 §3.2's ECDH-ES on X25519 and X448 among them): none is a JWS algorithm.
     */
    static final List<String> JWE_ALGORITHMS = List.of("RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512",
            "A128KW", "A192KW", "A256KW", "dir", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
            "A128GCMKW", "A192GCMKW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW");
    private static final FederationClientBuilder.Provenance EXPLICIT_RP = new FederationClientBuilder.Provenance(
            "registered", List.of("leaf", "statement"), 1234L, "https://ta.example", "openid_relying_party");
    private static final FederationClientBuilder.Provenance EXPLICIT_AGENT = new FederationClientBuilder.Provenance(
            "registered", List.of("leaf", "statement"), 1234L, "https://ta.example", "oauth_client");

    private static Map<String, Object> rp(Object... pairs) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("redirect_uris", List.of(RP + "/cb"));
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            metadata.put((String) pairs[i], pairs[i + 1]);
        }
        return metadata;
    }

    private static Client build(Map<String, Object> metadata, RequestObject.Kind proof) throws Exception {
        return FederationClientBuilder.relyingParty(RP, metadata, INLINE, PROVENANCE, AutoRegistrationSettings.DEFAULTS, proof, "ES256");
    }

    @Test
    @Requirement("OIDFED §12.1(4.2)")
    void anRpAuthenticatesWithItsKeys() throws Exception {
        Client client = build(rp(), RequestObject.Kind.REQUEST_OBJECT);

        assertEquals(RP, client.getClientId());
        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, client.getClientAuthnType());
        assertEquals("{\"keys\":[]}", client.getJwks());
        assertNull(client.getJwksUrl());
        Client byReference = FederationClientBuilder.relyingParty(RP, rp(), BY_REFERENCE, PROVENANCE, AutoRegistrationSettings.DEFAULTS,
                RequestObject.Kind.REQUEST_OBJECT, "ES256");
        assertEquals(RP + "/jwks", byReference.getJwksUrl());
    }

    @Test
    @Requirement("OIDFED §12.1(4.2)")
    void anRpThatWouldUseASharedSecretOrNothingIsRefused() {
        for (String method : List.of("none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "tls_client_auth",
                "self_signed_tls_client_auth")) {
            RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                    () -> build(rp("token_endpoint_auth_method", method), RequestObject.Kind.REQUEST_OBJECT), method);
            assertEquals("invalid_client_metadata", e.error());
            assertTrue(e.getMessage().contains(method), e.getMessage());
        }
    }

    @Test
    void anAttestingRpIsMarkedForTheBridge() throws Exception {
        Client client = build(rp("token_endpoint_auth_method", "attest_jwt_client_auth_dpop"), RequestObject.Kind.REQUEST_OBJECT);

        assertEquals("true", RegistrationFixtures.param(client, "attestation_required"));
        assertNull(RegistrationFixtures.param(client, "token_endpoint_auth_method"),
                "PingFederate 13.1 will not have that name declared as an extended property, so it is not written");
        assertNull(RegistrationFixtures.param(build(rp("token_endpoint_auth_method", "private_key_jwt"), RequestObject.Kind.REQUEST_OBJECT),
                "attestation_required"));
    }

    @Test
    void anRpNeedsRedirectUrisToRegisterHere() {
        Map<String, Object> none = rp();
        none.remove("redirect_uris");
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> build(none, RequestObject.Kind.REQUEST_OBJECT));

        assertEquals("invalid_client_metadata", e.error());
        assertTrue(e.getMessage().contains("redirect_uris"), e.getMessage());
    }

    @Test
    void whatItDidNotDeclareIsTheNarrowestDefault() throws Exception {
        Client client = build(rp(), RequestObject.Kind.REQUEST_OBJECT);

        assertEquals(List.of("code"), client.getRestrictedResponseTypes());
        assertTrue(client.isRestrictResponseTypes());
        assertEquals(Set.of("authorization_code"), client.getGrantTypes());
        assertEquals(List.of("openid"), client.getRestrictedScopes());
        assertTrue(client.isRestrictScopes());
        assertFalse(client.isBypassApprovalPage(), "a user is present: ask them");
    }

    @Test
    void whatItDeclaredIsWhatItGets() throws Exception {
        Client client = build(rp("response_types", List.of("code", "code id_token"), "grant_types", List.of("authorization_code", "refresh_token"),
                "scope", "openid profile", "client_name", "An RP", "id_token_signed_response_alg", "PS256",
                "token_endpoint_auth_signing_alg", "ES256", "request_object_signing_alg", "PS256"), RequestObject.Kind.REQUEST_OBJECT);

        assertEquals(List.of("code", "code id_token"), client.getRestrictedResponseTypes());
        assertEquals(Set.of("authorization_code", "refresh_token"), client.getGrantTypes());
        assertEquals(List.of("openid", "profile"), client.getRestrictedScopes());
        assertEquals("An RP", client.getName());
        assertEquals("PS256", client.getIdTokenSigningAlgorithm());
        assertEquals("ES256", client.getTokenEndpointAuthSigningAlgorithm());
        assertEquals("PS256", client.getRequestObjectSigningAlgorithm(), "its declared algorithm, not the proof's");
    }

    @Test
    @Requirement("OIDFED §12.1.1(2)")
    void anRpIsHeldToTheWayItProvedItself() throws Exception {
        Client byRequestObject = build(rp(), RequestObject.Kind.REQUEST_OBJECT);
        assertTrue(byRequestObject.isRequireSignedRequests());
        assertFalse(byRequestObject.isRequirePushedAuthorizationRequests());
        assertEquals("ES256", byRequestObject.getRequestObjectSigningAlgorithm(), "the proof's, when it declared none");

        Client byParAssertion = build(rp(), RequestObject.Kind.CLIENT_ASSERTION);
        assertFalse(byParAssertion.isRequireSignedRequests());
        assertTrue(byParAssertion.isRequirePushedAuthorizationRequests(), "every request pushed, and so authenticated");

        assertTrue(build(rp("require_pushed_authorization_requests", true), RequestObject.Kind.REQUEST_OBJECT).isRequirePushedAuthorizationRequests());
        AutoRegistrationSettings parOnly = new AutoRegistrationSettings(true, true, true, "openid", true, false, 65_536, 8, 2_000L, null);
        Client underPolicy = FederationClientBuilder.relyingParty(RP, rp(), INLINE, PROVENANCE, parOnly, RequestObject.Kind.REQUEST_OBJECT, "ES256");
        assertTrue(underPolicy.isRequirePushedAuthorizationRequests());
        assertFalse(underPolicy.isRequireProofKeyForCodeExchange());
        assertTrue(byRequestObject.isRequireProofKeyForCodeExchange(), "PKCE by default");
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void anRpCarriesItsProvenance() throws Exception {
        Client client = build(rp("application_type", "web", "contacts", List.of("ops@rp.example.com"), "subject_type", "pairwise"),
                RequestObject.Kind.REQUEST_OBJECT);

        assertEquals("auto_registered", RegistrationFixtures.param(client, FederationClientParams.STATUS));
        assertEquals("1234", RegistrationFixtures.param(client, FederationClientParams.EXPIRES_AT));
        assertEquals("https://ta.example", RegistrationFixtures.param(client, FederationClientParams.TRUST_ANCHOR));
        assertEquals("openid_relying_party", RegistrationFixtures.param(client, FederationClientParams.ENTITY_TYPE));
        assertEquals(List.of("leaf", "statement"), client.getExtendedParams().get("trust_chain").getElements());
        assertEquals("web", RegistrationFixtures.param(client, "application_type"));
        assertEquals("pairwise", RegistrationFixtures.param(client, "subject_type"));
        assertEquals("ops@rp.example.com", RegistrationFixtures.param(client, "contacts"));
    }

    @Test
    void metadataThatIsNotWhatItShouldBeIsNothing() throws Exception {
        Client client = build(rp("redirect_uris", List.of(RP + "/cb", 7), "response_types", "code", "grant_types", 3), RequestObject.Kind.REQUEST_OBJECT);

        assertEquals(List.of(RP + "/cb"), client.getRedirectUris());
        assertEquals(List.of("code"), client.getRestrictedResponseTypes(), "a string is not an array: the default");
        assertEquals(Set.of("authorization_code"), client.getGrantTypes());
    }

    /** At the token endpoint an attesting agent is PRIVATE_KEY_JWT, marked for the attestation bridge. */
    @Test
    void anAttestingAgentIsMarkedForTheBridge() {
        Client agent = FederationClientBuilder.agent(RP, Map.of("token_endpoint_auth_method", "attest_jwt_client_auth",
                "grant_types", List.of("client_credentials")), INLINE, PROVENANCE);

        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, agent.getClientAuthnType());
        assertEquals("true", RegistrationFixtures.param(agent, "attestation_required"));
        assertTrue(agent.isBypassApprovalPage(), "client_credentials alone: nobody to ask");
        Client byReference = FederationClientBuilder.agent(RP, Map.of(), BY_REFERENCE, PROVENANCE);
        assertEquals(RP + "/jwks", byReference.getJwksUrl());
    }

    // ---- H-FED-1: an encrypted proof, and request_object_signing_alg ----------------------------------------

    /**
     * OpenID Federation 1.0 §12.1.1: "Authentication requests MUST demonstrate that the requesting Entity controls the
     * Entity's RP keys". An encrypted request object - or client assertion - shows nothing this module can check before
     * the registration is written, so production registers nothing from one, and development registers it with a warning.
     */
    @Test
    @Requirement("OIDFED §12.1.1(2)")
    void anEncryptedProofRegistersOnlyInDevelopment() throws Exception {
        for (RequestObject.Kind kind : RequestObject.Kind.values()) {
            RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> FederationClientBuilder.relyingParty(RP, rp(),
                    INLINE, PROVENANCE, AutoRegistrationSettings.DEFAULTS, kind, null, DeploymentProfile.PRODUCTION), kind.name());
            assertEquals("invalid_request_object", e.error());
            assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind());
        }
        Client development = FederationClientBuilder.relyingParty(RP, rp(), INLINE, PROVENANCE, AutoRegistrationSettings.DEFAULTS,
                RequestObject.Kind.REQUEST_OBJECT, null, DeploymentProfile.DEVELOPMENT);
        assertEquals(RP, development.getClientId());
        assertTrue(development.isRequireSignedRequests());
        assertNull(development.getRequestObjectSigningAlgorithm(), "nothing is known of how the request inside is signed");
        assertEquals("ES256", FederationClientBuilder.relyingParty(RP, rp(), INLINE, PROVENANCE, AutoRegistrationSettings.DEFAULTS,
                RequestObject.Kind.REQUEST_OBJECT, "ES256", DeploymentProfile.PRODUCTION).getRequestObjectSigningAlgorithm(),
                "a signed proof registers in production, as before");
    }

    /** OpenID Connect Registration 1.0 §2: request_object_signing_alg is a "JWS [JWS] alg algorithm [JWA]" - never a JWE one. */
    @Test
    @Requirement("OIDC-REG §2")
    void requestObjectSigningAlgIsNeverAJweAlgorithm() throws Exception {
        for (String alg : JWE_ALGORITHMS) {
            assertNull(build(rp("request_object_signing_alg", alg), RequestObject.Kind.REQUEST_OBJECT).getRequestObjectSigningAlgorithm(),
                    "declared: " + alg);
            assertNull(FederationClientBuilder.relyingParty(RP, rp(), INLINE, PROVENANCE, AutoRegistrationSettings.DEFAULTS,
                    RequestObject.Kind.REQUEST_OBJECT, alg).getRequestObjectSigningAlgorithm(), "proof: " + alg);
            assertNull(FederationClientBuilder.agent(RP, Map.of("request_object_signing_alg", alg), INLINE, PROVENANCE)
                    .getRequestObjectSigningAlgorithm(), "agent: " + alg);
        }
        for (String alg : List.of("none", "HS256", "ES256K", "")) {
            assertNull(FederationClientBuilder.requestObjectSigningAlgorithm(RP, Map.of("request_object_signing_alg", alg), "ES256"), alg);
            assertNull(FederationClientBuilder.requestObjectSigningAlgorithm(RP, Map.of(), alg), alg);
        }
        for (String alg : FederationClientBuilder.REQUEST_OBJECT_SIGNING_ALGORITHMS) {
            assertEquals(alg, FederationClientBuilder.requestObjectSigningAlgorithm(RP, Map.of("request_object_signing_alg", alg), "ES256"));
            assertEquals(alg, FederationClientBuilder.requestObjectSigningAlgorithm(RP, Map.of(), alg));
        }
        assertNull(FederationClientBuilder.requestObjectSigningAlgorithm(RP, Map.of(), null));
    }

    // ---- H-FED-5: an explicitly registered relying party ----------------------------------------------------

    /**
     * OpenID Connect Registration 1.0 §2's defaults for what an explicitly registered RP's metadata omits:
     * response_types "If omitted, the default is that the Client will use only the code Response Type.", grant_types
     * "If omitted, the default is that the Client will use only the authorization_code Grant Type.", and
     * id_token_signed_response_alg "The default, if omitted, is RS256." - with its response types restricted to them,
     * and PKCE (RFC 7636; FAPI 2.0 §5.3.1.2) required.
     */
    @Test
    @Requirement({"OIDC-REG §2", "OIDFED §12.2.2"})
    void anExplicitRpGetsOidcDefaultsAndPkce() {
        Client client = FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP, true);

        assertEquals(List.of("code"), client.getRestrictedResponseTypes());
        assertTrue(client.isRestrictResponseTypes());
        assertEquals(Set.of("authorization_code"), client.getGrantTypes());
        assertEquals("RS256", client.getIdTokenSigningAlgorithm());
        assertTrue(client.isRequireProofKeyForCodeExchange());
        assertFalse(client.isBypassApprovalPage(), "a user is present: ask them");
        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, client.getClientAuthnType());
        assertFalse(FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP, false).isRequireProofKeyForCodeExchange(),
                "OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false - in production only with pkce-off accepted - turns it off");
    }

    @Test
    void anExplicitRpKeepsWhatItDeclared() {
        Client client = FederationClientBuilder.agent(RP, rp("response_types", List.of("code id_token"), "grant_types",
                List.of("authorization_code", "refresh_token"), "id_token_signed_response_alg", "PS256"), INLINE, EXPLICIT_RP, true);

        assertEquals(List.of("code id_token"), client.getRestrictedResponseTypes());
        assertEquals(Set.of("authorization_code", "refresh_token"), client.getGrantTypes());
        assertEquals("PS256", client.getIdTokenSigningAlgorithm());
    }

    /** Only an explicit RP: an agent, and an RP registered automatically at the token endpoint, get no defaults. */
    @Test
    void onlyAnExplicitRpGetsTheDefaults() {
        for (FederationClientBuilder.Provenance provenance : List.of(EXPLICIT_AGENT, PROVENANCE)) {
            Client client = FederationClientBuilder.agent(RP, Map.of("grant_types", List.of("client_credentials")), INLINE, provenance, true);
            assertEquals(List.of(), client.getRestrictedResponseTypes(), provenance.status() + " " + provenance.entityType());
            assertEquals(Set.of("client_credentials"), client.getGrantTypes());
            assertNull(client.getIdTokenSigningAlgorithm());
            assertFalse(client.isRequireProofKeyForCodeExchange());
        }
    }

    /** The four-argument form reads the setting, and only for an explicit RP. */
    @Test
    void theExplicitRpsPkceComesFromTheSetting() {
        try {
            FederationRuntimeConfig.install(FederationRuntimeConfig.from(
                    Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_REQUIRE_PKCE_ENV, "false")::get, name -> null));
            assertFalse(FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP).isRequireProofKeyForCodeExchange());
            FederationRuntimeConfig.install(FederationRuntimeConfig.from(name -> null, name -> null));
            assertTrue(FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP).isRequireProofKeyForCodeExchange(), "on by default");
        } finally {
            FederationRuntimeConfig.resetForTests();
        }
    }

    /** §12.2.3: "The OP SHOULD include metadata parameters that have a default value" - an RP's, as registered. */
    @Test
    @Requirement("OIDFED §12.2.3")
    void theExplicitResponseReportsAnRpsDefaults() {
        Map<String, Object> registered = new LinkedHashMap<>(rp());
        FederationClientBuilder.narrowed(registered, FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP, true));
        assertEquals(List.of("code"), registered.get("response_types"));
        assertEquals(List.of("authorization_code"), registered.get("grant_types"));
        assertEquals("RS256", registered.get("id_token_signed_response_alg"));

        Map<String, Object> declared = new LinkedHashMap<>(rp("id_token_signed_response_alg", "PS256", "grant_types",
                List.of("authorization_code", "refresh_token"), "response_types", List.of("code", "code id_token")));
        Client declaring = FederationClientBuilder.agent(RP, declared, INLINE, EXPLICIT_RP, true);
        declaring.getGrantTypes().remove("refresh_token");
        FederationClientBuilder.narrowed(declared, declaring);
        assertEquals("PS256", declared.get("id_token_signed_response_alg"));
        assertEquals(List.of("authorization_code"), declared.get("grant_types"), "narrowed, as before");
        assertEquals(List.of("code", "code id_token"), declared.get("response_types"));

        Map<String, Object> agent = new LinkedHashMap<>();
        FederationClientBuilder.narrowed(agent, FederationClientBuilder.agent(RP, Map.of(), INLINE, EXPLICIT_AGENT, true));
        assertEquals(Map.of(), agent, "an agent has no defaults to report");
        Map<String, Object> noAlg = new LinkedHashMap<>();
        Client withoutAlg = FederationClientBuilder.agent(RP, rp(), INLINE, EXPLICIT_RP, true);
        withoutAlg.setIdTokenSigningAlgorithm(null);
        FederationClientBuilder.narrowed(noAlg, withoutAlg);
        assertFalse(noAlg.containsKey("id_token_signed_response_alg"));
    }
}
