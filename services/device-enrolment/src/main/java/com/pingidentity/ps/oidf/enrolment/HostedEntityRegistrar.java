/*
 * Onboarding an enrolled agent into the bank's OpenID Federation.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
     * The PingFederate hosted-entity API: {@code POST <authority>/federation/agents} (HostedEntityServlet, SELF_SIGNED
     * mode), an operator route that needs {@code oidf.admin.entities}: the headers come from {@link AuthorityCredentials}
     * - a DPoP-bound client-credentials token, or in development the static bearer.
     */
    final class PingFederate implements HostedEntityRegistrar {
        private static final Log LOGGER = LogFactory.getLog(PingFederate.class);
        private static final ObjectMapper JSON = new ObjectMapper();
        /** The environment variable that turns the trust-all on, and the name InsecureTls records it under. */
        static final String INSECURE_TLS = "PF_AUTHORITY_INSECURE_TLS";

        private final String authorityEntityId;
        private final URI baseUrl;
        private final AuthorityCredentials credentials;
        private final HttpClient http;

        /**
         * @param authorityEntityId the authority's Entity Identifier (PingFederate's issuer)
         * @param baseUrl where to reach it from here - differs from the identifier when PF runs in a container
         * @param insecureTls dev only: trust PF's self-signed listener ({@value #INSECURE_TLS}), through platform's
         *                    {@link InsecureTls}, which warns once and records the use; the host name is still checked
         */
        public PingFederate(String authorityEntityId, String baseUrl, String adminToken, boolean insecureTls) {
            this(authorityEntityId, baseUrl, insecureTls, http -> new AuthorityCredentials.StaticBearer(adminToken));
        }

        /**
         * @param credentials the credentials, given the HTTP client this registrar builds (the token endpoint is reached
         *                    through the same client and TLS trust as the API)
         */
        PingFederate(String authorityEntityId, String baseUrl, boolean insecureTls,
                     java.util.function.Function<HttpClient, AuthorityCredentials> credentials) {
            this.authorityEntityId = Objects.requireNonNull(authorityEntityId, "authorityEntityId");
            this.baseUrl = URI.create(Objects.requireNonNull(baseUrl, "baseUrl").replaceAll("/+$", ""));
            this.http = InsecureTls.trustAnyCertificate(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)), INSECURE_TLS,
                    insecureTls).build();
            this.credentials = Objects.requireNonNull(credentials.apply(this.http), "credentials");
        }

        /**
         * The registrar {@code settings} describe in {@code profile} ({@link AuthorityCredentials#from}): Main's one
         * way in.
         *
         * @throws IllegalStateException naming the settings to change
         */
        public static PingFederate of(String authorityEntityId, AuthorityCredentials.Settings settings, boolean insecureTls,
                                      DeploymentProfile profile) {
            PingFederate registrar = new PingFederate(authorityEntityId, settings.authorityUrl(), insecureTls,
                    http -> AuthorityCredentials.from(settings, profile, http, Clock.systemUTC()));
            LOGGER.info((Object) ("federation onboarding at " + authorityEntityId + " authenticates with "
                    + registrar.credentials.describe()));
            return registrar;
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
                URI collection = URI.create(this.baseUrl + "/federation/agents");
                HttpRequest.Builder request = HttpRequest.newBuilder(collection)
                        .timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
                this.credentials.headers("POST", collection).forEach(request::header);
                HttpResponse<String> response = this.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 401) {
                    this.credentials.rejected();
                }
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
    }
}
