package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import java.util.HashMap;
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
}
