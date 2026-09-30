package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.AttestationMetadataConfig;
import com.pingidentity.ps.oidf.federation.AttestationMetadataConfigs;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.servlet.oauth.AttestationMetadataFilter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.annotation.WebServlet;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/**
 * Each surface's metadata names its own challenge endpoint, at the path that endpoint is mapped to, and never the
 * other's: the attester's two documents name {@code GET /federation/attestation/challenge}, the authorization
 * server's OP metadata in the Entity Configuration names {@code POST /federation/attestation-challenge}. The paths
 * are read off the servlets' {@code @WebServlet} mappings, so a moved servlet fails here rather than in a client.
 */
@org.junit.jupiter.api.extension.ExtendWith(InMemoryStateAccepted.class)
class ChallengeEndpointAdvertisementTest {
    private static final String ISSUER = "https://pf.example.com";

    private static String mapped(Class<?> servlet) {
        return servlet.getAnnotation(WebServlet.class).urlPatterns()[0];
    }

    private static final String AS_PATH = mapped(ClientAttestationChallengeServlet.class);
    private static final String CAS_PATH = mapped(AttestationIssuanceChallengeServlet.class);

    @Test
    void theTwoEndpointsAreTwoPaths() {
        assertNotEquals(AS_PATH, CAS_PATH);
    }

    /** CAS §5.1: {@code challenge_endpoint} is the "URL of the challenge endpoint (Section 4.1)" - the CAS's own. */
    @Test
    @Requirement("CAS §5.1")
    void theClientAttestationServiceDocumentNamesTheAttestersEndpoint() throws Exception {
        ClientAttestationServiceMetadataServlet servlet = new ClientAttestationServiceMetadataServlet();
        servlet.init(mock(ServletConfig.class));
        Map<String, Object> metadata = servlet.metadata(ISSUER);

        assertEquals(ISSUER + CAS_PATH, metadata.get("challenge_endpoint"));
        assertFalse(names(metadata, AS_PATH), "the authorization server's endpoint is not named");
    }

    @Test
    void theAttesterConfigurationNamesTheAttestersEndpoint() {
        Map<String, Object> metadata = AttesterConfigurationServlet.metadata(ISSUER, false, false);

        assertEquals(ISSUER + CAS_PATH, metadata.get("challenge_endpoint"));
        assertFalse(names(metadata, AS_PATH), "the authorization server's endpoint is not named");
    }

    @Test
    void theEntityConfigurationNamesTheAuthorizationServersEndpointOnly() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("trustAnchorIssuers")).thenReturn(ISSUER);
        FederationService federation = new FederationService(FederationConfiguration.fromServletConfig(config), signingKeys());
        String jwt = federation.createEntityConfigurationJwt(ISSUER);
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) JsonUtil.parseJson(payload).get("metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> openidProvider = (Map<String, Object>) metadata.get("openid_provider");

        assertEquals(ISSUER + AS_PATH, openidProvider.get("challenge_endpoint"));
        assertFalse(names(metadata, CAS_PATH), "the attester's endpoint is named nowhere in the Entity Configuration");
    }

    // ---- one member set in the four documents (plan item S-4, F-0115, F-0118) ----------------------------------------

    /** PingFederate 13.1.3's discovery document, in its shape (the rig, 2026-10-01), for either path. */
    private static Map<String, Object> pingFederateDocument() {
        Map<String, Object> doc = new java.util.LinkedHashMap<>();
        doc.put("issuer", ISSUER);
        doc.put("token_endpoint", ISSUER + "/as/token.oauth2");
        doc.put("token_endpoint_auth_methods_supported", java.util.List.of("client_secret_basic", "private_key_jwt", "tls_client_auth", "none"));
        doc.put("dpop_signing_alg_values_supported", java.util.List.of("RS256", "ES256", "PS256"));
        return doc;
    }

    /** The attestation members {@code document} carries: ABCA-10's methods in its list, and each other member it names. */
    private static Map<String, Object> attestationMembers(Map<String, Object> document) {
        Map<String, Object> members = new java.util.TreeMap<>();
        for (String name : java.util.List.of("client_attestation_signing_alg_values_supported", "client_attestation_pop_signing_alg_values_supported",
                "challenge_endpoint")) {
            if (document.containsKey(name)) {
                members.put(name, document.get(name));
            }
        }
        Object methods = document.getOrDefault("token_endpoint_auth_methods_supported", java.util.List.of());
        members.put("methods", ((java.util.List<?>) methods).stream().filter(AttestationMetadataConfig.ATTESTATION_METHODS::contains).toList());
        return members;
    }

    /** The four documents this authorization server's metadata is served in, with {@code members} as the servlet read them. */
    private static java.util.List<Map<String, Object>> fourDocuments(AttestationMetadataConfig members) throws Exception {
        FederationService federation = FederationService.builder(AttestationMetadataConfigs.configuration(ISSUER, members), signingKeys())
                .providerMetadata((type, issuer) -> pingFederateDocument()).build();
        String jwt = federation.createEntityConfigurationJwt(ISSUER);
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) JsonUtil.parseJson(payload).get("metadata");
        java.util.List<Map<String, Object>> out = new java.util.ArrayList<>();
        out.add(cast(metadata.get("openid_provider")));
        out.add(cast(metadata.get("oauth_authorization_server")));
        for (String path : java.util.List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
            out.add(throughTheFilter(members, path));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Object block) {
        return (Map<String, Object>) block;
    }

    /** PingFederate's document at {@code path}, served through pf-integration's AttestationMetadataFilter. */
    private static Map<String, Object> throughTheFilter(AttestationMetadataConfig members, String path) throws Exception {
        jakarta.servlet.http.HttpServletRequest request = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn(path);
        when(request.getContextPath()).thenReturn("");
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
                sink.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {
            }
        });
        when(response.getStatus()).thenReturn(200);
        when(response.getContentType()).thenReturn("application/json");
        byte[] document = JsonUtil.toJson(pingFederateDocument()).getBytes(StandardCharsets.UTF_8);
        new AttestationMetadataFilter(() -> members).doFilter(request, response, (req, resp) -> {
            resp.getOutputStream().write(document);
        });
        return sink.size() == 0 ? pingFederateDocument() : JsonUtil.parseJson(sink.toString(StandardCharsets.UTF_8));
    }

    /**
     * ABCA-10 §6.1 (read 2026-10-01): "If the Authorization Server supports metadata as defined in [RFC8414] ..., it MUST
     * signal support for the challenge endpoint by including the metadata entry challenge_endpoint". Every document this
     * authorization server's metadata is served in carries the same members - openid_provider, oauth_authorization_server,
     * and PingFederate's own two through the filter - and the challenge endpoint in each is the authorization server's.
     */
    @Test
    @Requirement({"ABCA-10 §6.1", "ABCA-10 §8"})
    void theFourDocumentsCarryTheSameAttestationMembers() throws Exception {
        java.util.List<Map<String, Object>> four = fourDocuments(AttestationMetadataConfigs.defaults());
        Map<String, Object> first = attestationMembers(four.get(0));
        assertEquals(ISSUER + AS_PATH, first.get("challenge_endpoint"));
        assertEquals(AttestationMetadataConfig.ATTESTATION_METHODS, first.get("methods"));
        assertEquals(4, first.size(), "the methods, both algorithm lists and the challenge endpoint");
        for (Map<String, Object> document : four) {
            assertEquals(first, attestationMembers(document));
            assertFalse(names(document, CAS_PATH), "the attester's challenge endpoint is in none of them");
        }
        // ABCA-10 §7.6: client_attestation_pop_methods_supported without none asks every client for an attestation, so
        // only openid_provider, as before this change, carries it (F-0412)
        assertTrue(four.get(0).containsKey("client_attestation_pop_methods_supported"));
        for (Map<String, Object> document : four.subList(1, 4)) {
            assertFalse(document.containsKey("client_attestation_pop_methods_supported"));
        }
    }

    /** S9b's rule for a disabled component: ATTESTATION_AUTH switched off, none of the four advertises a member. */
    @Test
    void switchedOffNoneOfTheFourAdvertisesAMember() throws Exception {
        for (Map<String, Object> document : fourDocuments(AttestationMetadataConfigs.switchedOff())) {
            assertEquals(Map.of("methods", java.util.List.of()), attestationMembers(document));
        }
        AttestationMetadataConfigs.resetCurrent();
    }

    /**
     * F-0118: the attester's document keeps its own challenge_endpoint and names the authorization server - RFC 9728 §2's
     * authorization_servers, "a list of OAuth authorization server issuer identifiers, as defined in [RFC8414]" - and the
     * RFC 8414 §3 location of its metadata, whose challenge_endpoint is the one the token endpoint accepts.
     */
    @Test
    @Requirement({"RFC8414 §3", "RFC9728 §2"})
    void theAttesterDocumentLeadsAClientToTheAuthorizationServersChallenge() throws Exception {
        Map<String, Object> attester = AttesterConfigurationServlet.metadata(ISSUER, false, false, ISSUER);

        assertEquals(ISSUER + CAS_PATH, attester.get("challenge_endpoint"), "its own challenge endpoint, for the instance-key proof");
        assertEquals(java.util.List.of(ISSUER), attester.get("authorization_servers"));
        assertEquals(ISSUER + "/.well-known/oauth-authorization-server", attester.get("authorization_server_metadata"));
        Map<String, Object> asMetadata = throughTheFilter(AttestationMetadataConfigs.defaults(), "/.well-known/oauth-authorization-server");
        assertEquals(ISSUER, asMetadata.get("issuer"), "RFC 8414 §3.3: the issuer the client started from");
        assertEquals(ISSUER + AS_PATH, asMetadata.get("challenge_endpoint"), "and there, the challenge the token endpoint takes");

        Map<String, Object> unknown = AttesterConfigurationServlet.metadata(ISSUER, false, false);
        assertFalse(unknown.containsKey("authorization_servers"));
        assertFalse(unknown.containsKey("authorization_server_metadata"));
    }

    @Test
    void theWalkFindsAPathWhereverItIs() {
        assertEquals(true, names(Map.of("a", java.util.List.of(Map.of("b", ISSUER + CAS_PATH))), CAS_PATH));
        assertEquals(false, names(Map.of("a", java.util.List.of(1, ISSUER + AS_PATH)), CAS_PATH));
    }

    /**
     * Whether any string value in a parsed document, at any depth, names {@code path}. Walked rather than searched
     * as text, because the JSON writer may escape a solidus.
     */
    private static boolean names(Object value, String path) {
        if (value instanceof String text) {
            return text.contains(path);
        }
        if (value instanceof Map<?, ?> map) {
            return map.values().stream().anyMatch(v -> names(v, path));
        }
        if (value instanceof Iterable<?> list) {
            for (Object item : list) {
                if (names(item, path)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static SigningKeyProvider signingKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return "challenge-advertisement-test";
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
