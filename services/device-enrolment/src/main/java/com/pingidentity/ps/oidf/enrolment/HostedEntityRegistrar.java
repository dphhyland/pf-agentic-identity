/*
 * Onboarding an enrolled agent into the bank's OpenID Federation.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Registers an enrolled agent as a HOSTED entity under the bank's federation authority, so it becomes a
 * Leaf Entity with an Entity Identifier of its own - {@code <authority>/federation/agents/<agent_id>} -
 * that any member of the federation can resolve to the Trust Anchor.
 *
 * <p>Self-signed hosting: the agent's Entity Configuration is signed by the agent's OWN Federation Entity
 * Key (hardware-held on the Mac), and the authority only serves it and vouches for that key in its
 * Subordinate Statement. The authority cannot forge the agent's configuration.
 */
public interface HostedEntityRegistrar {

    /**
     * The agent's Entity Identifier, or null when federation onboarding is not configured.
     *
     * @param metadataPolicy what the authority's Subordinate Statement imposes on the agent's own metadata
     *     (OpenID Federation §6.1) - in self-signed hosting this is the authority's only lever on it
     */
    String register(String agentId, Map<String, Object> federationPublicJwk, Map<String, Object> metadata,
                    Map<String, Object> metadataPolicy, String ownerRef) throws EnrolmentException;

    /** The authority the agent's Entity Configuration names in {@code authority_hints}, or null. */
    String authorityEntityId();

    static HostedEntityRegistrar disabled() {
        return new HostedEntityRegistrar() {
            @Override
            public String register(String agentId, Map<String, Object> jwk, Map<String, Object> md,
                                   Map<String, Object> policy, String owner) {
                return null;
            }

            @Override
            public String authorityEntityId() {
                return null;
            }
        };
    }

    /**
     * The PingFederate hosted-entity API: {@code POST <authority>/federation/agents} with the authority's
     * admin bearer token (HostedEntityServlet, SELF_SIGNED mode).
     */
    final class PingFederate implements HostedEntityRegistrar {
        private static final Log LOGGER = LogFactory.getLog(PingFederate.class);
        private static final ObjectMapper JSON = new ObjectMapper();

        private final String authorityEntityId;
        private final URI baseUrl;
        private final String adminToken;
        private final HttpClient http;

        /**
         * @param authorityEntityId the authority's Entity Identifier (PingFederate's issuer)
         * @param baseUrl where to reach it from here - differs from the identifier when PF runs in a container
         * @param insecureTls dev only: trust PF's self-signed listener. Loudly logged.
         */
        public PingFederate(String authorityEntityId, String baseUrl, String adminToken, boolean insecureTls) {
            this.authorityEntityId = Objects.requireNonNull(authorityEntityId, "authorityEntityId");
            this.baseUrl = URI.create(Objects.requireNonNull(baseUrl, "baseUrl").replaceAll("/+$", ""));
            this.adminToken = Objects.requireNonNull(adminToken, "adminToken");
            HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5));
            if (insecureTls) {
                LOGGER.warn((Object) "PF_AUTHORITY_INSECURE_TLS=true: certificate checks OFF for the hosted-entity API (dev only)");
                builder.sslContext(trustAll());
                SSLParameters params = new SSLParameters();
                params.setEndpointIdentificationAlgorithm(null);
                builder.sslParameters(params);
            }
            this.http = builder.build();
        }

        @Override
        public String authorityEntityId() {
            return this.authorityEntityId;
        }

        @Override
        public String register(String agentId, Map<String, Object> federationPublicJwk, Map<String, Object> metadata,
                               Map<String, Object> metadataPolicy, String ownerRef) throws EnrolmentException {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("id", agentId);
            body.put("hostingMode", "SELF_SIGNED");
            body.put("federationJwks", Map.of("keys", List.of(federationPublicJwk)));
            body.put("metadata", metadata);
            if (metadataPolicy != null && !metadataPolicy.isEmpty()) {
                body.put("metadataPolicy", metadataPolicy);
            }
            body.put("listable", true);
            if (ownerRef != null) {
                body.put("ownerRef", ownerRef);
            }
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(this.baseUrl + "/federation/agents"))
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + this.adminToken)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                        .build();
                HttpResponse<String> response = this.http.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 201) {
                    throw EnrolmentException.serverError("the federation authority refused the agent (HTTP "
                            + response.statusCode() + "): " + response.body(), null);
                }
                JsonNode created = JSON.readTree(response.body());
                String entityId = created.path("entityId").asText(null);
                if (entityId == null) {
                    throw EnrolmentException.serverError("the federation authority returned no entityId", null);
                }
                LOGGER.info((Object) ("registered hosted federation entity " + entityId));
                return entityId;
            } catch (EnrolmentException e) {
                throw e;
            } catch (Exception e) {
                throw EnrolmentException.serverError("could not reach the federation authority: " + e.getMessage(), e);
            }
        }

        private static SSLContext trustAll() {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }}, new SecureRandom());
                return ctx;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
