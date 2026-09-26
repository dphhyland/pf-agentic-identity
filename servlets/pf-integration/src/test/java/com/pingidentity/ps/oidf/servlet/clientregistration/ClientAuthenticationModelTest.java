package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;

/**
 * What PingFederate 13.1.3's client authentication model makes of the clients a federation registration builds.
 *
 * <p>13.1 lets a client carry a set of authentication types ({@code getClientAuthenticationTypes()}), and
 * {@code isUseClientAuthenticationModel()} says whether it uses that model, beside the single legacy type
 * ({@code getClientAuthnType()}). {@link FederationClientBuilder} sets only the legacy type. The token endpoint
 * chooses how a client may authenticate with {@code isAuthTypeEnabled}, which reads the set when there is one and
 * otherwise compares with the legacy type; the private_key_jwt validator constrains the signing algorithm with
 * {@code getPrivateKeyJwtTokenEndpointAuthSigningAlgorithm()}, which falls back to the legacy algorithm
 * ({@code BaseClientAuthnRequestHandler}, {@code ClientJwtValidator} and {@code Client}, read with javap from
 * pf-protocolengine 13.1.3.0, 2026-09-26). So these clients authenticate with private_key_jwt and nothing else, held
 * to the algorithm their metadata names.
 *
 * <p>A characterisation, not a requirement: it pins what the builder's clients report today, so a change on
 * either side shows up here. Revisit it once a booted 13.1.3 has shown how such a client is stored and
 * authenticated (register item U-0004).
 */
class ClientAuthenticationModelTest {

    private static final String RP = "https://rp.example.com";
    private static final RpKeyMaterial.Keys KEYS = new RpKeyMaterial.Keys(List.of(), "{\"keys\":[]}", null, "jwks");
    private static final FederationClientBuilder.Provenance PROVENANCE = new FederationClientBuilder.Provenance(
            "auto_registered", List.of("leaf", "statement"), 1234L, "https://ta.example", "openid_relying_party");

    @Test
    void anAttestingAgentIsPrivateKeyJwtOnTheSingleTypeModel() {
        Client agent = FederationClientBuilder.agent(RP + "/agent-1", Map.of("token_endpoint_auth_method", "attest_jwt_client_auth",
                "token_endpoint_auth_signing_alg", "ES256", "grant_types", List.of("client_credentials")), KEYS, PROVENANCE);

        assertPrivateKeyJwtOnly(agent, "ES256");
    }

    @Test
    void aRelyingPartyIsPrivateKeyJwtOnTheSingleTypeModel() throws Exception {
        Client relyingParty = FederationClientBuilder.relyingParty(RP, Map.of("redirect_uris", List.of(RP + "/cb"),
                "token_endpoint_auth_method", "private_key_jwt", "token_endpoint_auth_signing_alg", "PS256"),
                KEYS, PROVENANCE, AutoRegistrationSettings.DEFAULTS, RequestObject.Kind.REQUEST_OBJECT, "ES256");

        assertPrivateKeyJwtOnly(relyingParty, "PS256");
    }

    private static void assertPrivateKeyJwtOnly(Client client, String signingAlg) {
        assertFalse(client.isUseClientAuthenticationModel(), "the builder does not opt into 13.1's model");
        assertNull(client.getClientAuthenticationTypes(), "and sets no set of types");
        assertFalse(client.isMultiAuthEnabled());
        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, client.getSpecifiedClientAuthnType());
        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, client.getClientAuthnType());
        for (ClientAuthenticationType type : ClientAuthenticationType.values()) {
            assertEquals(type == ClientAuthenticationType.PRIVATE_KEY_JWT, client.isAuthTypeEnabled(type), type.name());
        }
        assertEquals(signingAlg, client.getPrivateKeyJwtTokenEndpointAuthSigningAlgorithm(),
                "the algorithm the private_key_jwt validator holds the client to");
    }
}
