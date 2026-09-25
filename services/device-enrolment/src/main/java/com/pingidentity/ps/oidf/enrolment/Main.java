/*
 * Wires the enrolment service from the environment and starts it.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.pingidentity.ps.oidf.appattest.AppAttestConfig;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.IomInstanceRegistry;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.sql.DataSource;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.postgresql.ds.PGSimpleDataSource;

/**
 * Entry point. Everything is configured by environment variable, as the other deployables in this repo
 * are.
 *
 * <pre>
 *   PORT                          listen port (default 8080)
 *   ENROLMENT_ISSUER              this service's entity id — the attestation iss, and the proof aud
 *   ENROLMENT_SIGNING_JWK         the attester's private JWK (dev). Production should use a vault-backed
 *                                 JwsSigner instead; the seam already exists
 *   IDM_DATABASE_URL              the Identity Object Model directory (Postgres) this service records
 *                                 instances in — the SAME directory the SCIM users live in, so an agent
 *                                 sits beside its owner. Accepts a JDBC URL or a postgresql:// DSN
 *                                 (Railway's reference-variable form). Absent → refuses to start
 *   APPLE_TEAM_ID / APPLE_BUNDLE_ID   the App ID an attestation must be bound to
 *   APPLE_ALLOW_DEVELOPMENT       "true" to accept development App Attest. Off by default, on purpose
 *   UV_MAX_AGE_SECONDS            the server-side time-box (default 300)
 *   REQUIRE_COMPLIANT_DEVICE      "false" to allow minting on an unassessed device (default true)
 *   OIDF_ATTESTATION_SUB          "client_id" flips the attestation sub to the registered client id
 *                                 (Phase 2.5; requires OIDF_AGENT_CLIENT_ID). Absent/other → legacy
 *                                 sub = instance id. agent_id carries the instance id either way
 *   OIDF_AGENT_CLIENT_ID          the OAuth client the device agents are instances of — required when
 *                                 OIDF_ATTESTATION_SUB=client_id, ignored otherwise
 * </pre>
 *
 * <p>Two defaults are deliberately strict, because the failure mode of getting them wrong is silent:
 * development App Attest is refused unless asked for, and a device whose compliance is unknown cannot
 * mint. Both fail closed.
 */
public final class Main {

    private static final Log LOGGER = LogFactory.getLog(Main.class);

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        String issuer = required("ENROLMENT_ISSUER");
        int port = Integer.parseInt(env("PORT", "8080"));
        long uvMaxAge = Long.parseLong(env("UV_MAX_AGE_SECONDS", "300"));
        boolean requireCompliant = Boolean.parseBoolean(env("REQUIRE_COMPLIANT_DEVICE", "true"));

        // App Attest is optional now: a deployment that only enrols connector agents with YubiKey or
        // self-asserted evidence needs no Apple configuration. Set both or neither.
        AppAttestVerifier appAttest = null;
        String teamId = System.getenv("APPLE_TEAM_ID");
        String bundleId = System.getenv("APPLE_BUNDLE_ID");
        if (teamId != null && !teamId.isBlank() && bundleId != null && !bundleId.isBlank()) {
            boolean allowDevelopment = Boolean.parseBoolean(env("APPLE_ALLOW_DEVELOPMENT", "false"));
            appAttest = new AppAttestVerifier(allowDevelopment
                    ? AppAttestConfig.allowingDevelopment(teamId, bundleId)
                    : AppAttestConfig.production(teamId, bundleId));
            if (allowDevelopment) {
                // Loud on purpose: this weakens the strongest assertion the service makes.
                LOGGER.warn((Object) "APPLE_ALLOW_DEVELOPMENT is set — development App Attest objects will "
                        + "be accepted. Every such enrolment is flagged in the registry, but this must not "
                        + "be set in production.");
            }
        } else if ((teamId == null) != (bundleId == null)) {
            throw new IllegalStateException("set both APPLE_TEAM_ID and APPLE_BUNDLE_ID, or neither");
        }

        InstanceRegistry registry;
        if ("memory".equalsIgnoreCase(env("REGISTRY", "iom"))) {
            LOGGER.warn((Object) "REGISTRY=memory: enrolments live in this process only and are lost on restart (dev only)");
            registry = new InMemoryInstanceRegistry();
        } else {
            registry = new IomInstanceRegistry(dataSource(requireIdmUrl()));
        }

        JwsSigner signer = new LocalJwkSigner(parseJwk(required("ENROLMENT_SIGNING_JWK")));
        String subjectClientId = subjectClientId();
        DeviceAttestationMinter minter = new DeviceAttestationMinter(issuer, subjectClientId);

        EnrolmentService service = new EnrolmentService(
                appAttest,
                pingOneVerifier(),
                registry, minter,
                new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(),
                signer, issuer, Duration.ofSeconds(uvMaxAge), requireCompliant,
                BindingNotifier.logOnly(), agentOptions(subjectClientId));

        EnrolmentHttpServer server = new EnrolmentHttpServer(service, signer, port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
        LOGGER.info((Object) ("issuer=" + issuer + " appAttest=" + (appAttest == null ? "off" : teamId + "." + bundleId)
                + " uvMaxAge=" + uvMaxAge + "s requireCompliantDevice=" + requireCompliant));
    }

    /**
     * The connector-agent path (Mac connector experiment). Everything is off unless configured:
     *
     * <pre>
     *   YUBICO_PIV_ROOTS            PEM bundle of pinned Yubico PIV roots: accept yubikey-piv evidence
     *   ALLOW_SELF_ASSERTED_KEYS    "true" to accept secure-enclave-self-asserted evidence (no key_storage claim)
     *   AGENT_AUTHORIZATION_DETAILS JSON array: the RFC 9396 ceiling every connector attestation carries
     *   PF_AUTHORITY_ENTITY_ID      the federation authority (PingFederate's issuer) hosting agent entities
     *   PF_AUTHORITY_URL            where to reach it from here (defaults to the entity id)
     *   PF_AUTHORITY_ADMIN_TOKEN    its hosted-entity admin bearer token (OIDF_AUTHORITY_ADMIN_TOKEN over there)
     *   PF_AUTHORITY_INSECURE_TLS   "true" to trust its self-signed listener (dev only)
     * </pre>
     */
    private static EnrolmentService.AgentOptions agentOptions(String clientId) throws Exception {
        PivAttestationVerifier piv = null;
        String roots = System.getenv("YUBICO_PIV_ROOTS");
        if (roots != null && !roots.isBlank()) {
            piv = PivAttestationVerifier.fromPemFile(java.nio.file.Path.of(roots));
        }
        boolean selfAsserted = Boolean.parseBoolean(env("ALLOW_SELF_ASSERTED_KEYS", "false"));
        if (selfAsserted) {
            LOGGER.warn((Object) "ALLOW_SELF_ASSERTED_KEYS=true: keys whose storage nobody can verify will be attested"
                    + " (without a key_storage claim)");
        }
        java.util.List<Map<String, Object>> authz = null;
        String authzJson = System.getenv("AGENT_AUTHORIZATION_DETAILS");
        if (authzJson != null && !authzJson.isBlank()) {
            authz = new com.fasterxml.jackson.databind.ObjectMapper().readValue(authzJson,
                    new com.fasterxml.jackson.core.type.TypeReference<java.util.List<Map<String, Object>>>() { });
        }
        HostedEntityRegistrar federation = HostedEntityRegistrar.disabled();
        String authority = System.getenv("PF_AUTHORITY_ENTITY_ID");
        if (authority != null && !authority.isBlank()) {
            federation = new HostedEntityRegistrar.PingFederate(authority, env("PF_AUTHORITY_URL", authority),
                    required("PF_AUTHORITY_ADMIN_TOKEN"), Boolean.parseBoolean(env("PF_AUTHORITY_INSECURE_TLS", "false")));
        }
        String software = clientId == null ? "claude-bank-connector" : clientId;
        Map<String, Object> oauthClient = new java.util.LinkedHashMap<>();
        oauthClient.put("client_name", "Claude bank connector");
        oauthClient.put("software_id", software);
        oauthClient.put("token_endpoint_auth_method", "attest_jwt_client_auth");
        // The authority's lever on a self-signed configuration: whatever the agent writes, these hold.
        Map<String, Object> policy = Map.of("oauth_client", Map.of(
                "software_id", Map.of("value", software),
                "token_endpoint_auth_method", Map.of("value", "attest_jwt_client_auth")));
        return new EnrolmentService.AgentOptions(federation, piv, selfAsserted, authz,
                Map.of("oauth_client", oauthClient), policy);
    }

    /**
     * The IdP verifier. Refuses rather than defaulting to permissive when unconfigured — an auth
     * service that silently accepts anything is worse than one that is plainly switched off.
     *
     * <p>{@code PINGONE_ACR_AAL2} lists the sign-on policy names that genuinely represent AAL2, comma
     * separated. PingOne puts the applied policy name in {@code acr} and this environment advertises no
     * {@code acr_values_supported}, so the mapping cannot be discovered and has to be stated. Anything
     * not listed is treated as AAL1 and will fail the binding requirement.
     */
    public static UserAuthenticationVerifier pingOneVerifier() {
        String issuer = System.getenv("PINGONE_ISSUER");
        String clientId = System.getenv("PINGONE_CLIENT_ID");
        if (issuer == null || issuer.isBlank() || clientId == null || clientId.isBlank()) {
            LOGGER.warn((Object) "PINGONE_ISSUER / PINGONE_CLIENT_ID are unset — user authentication "
                    + "will be refused, so enrolment cannot complete on this deployment.");
            return evidence -> {
                throw EnrolmentException.userAuthenticationFailed(
                        "no IdP is configured on this deployment");
            };
        }
        Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr = new LinkedHashMap<>();
        for (String policy : env("PINGONE_ACR_AAL2", "").split(",")) {
            String name = policy.trim();
            if (!name.isEmpty()) {
                assuranceByAcr.put(name, UserAuthentication.AssuranceLevel.AAL2);
            }
        }
        if (assuranceByAcr.isEmpty()) {
            LOGGER.warn((Object) "PINGONE_ACR_AAL2 is empty — every authentication will be treated as "
                    + "AAL1 and refused for binding. Set it to the passkey sign-on policy name.");
        }
        LOGGER.info((Object) ("PingOne verifier: issuer=" + issuer
                + " aal2Policies=" + assuranceByAcr.keySet()));
        return PingOneIdTokenVerifier.forEnvironment(issuer, clientId, assuranceByAcr);
    }

    /**
     * The Phase 2.5 {@code sub} flip: returns the registered client id to mint as the attestation
     * {@code sub} when {@code OIDF_ATTESTATION_SUB=client_id}, or {@code null} for the legacy
     * instance-id {@code sub}. Fails closed: the flag set without {@code OIDF_AGENT_CLIENT_ID} refuses
     * to start rather than silently minting legacy attestations an operator believes are flipped.
     */
    private static String subjectClientId() {
        String mode = env("OIDF_ATTESTATION_SUB", "");
        if (mode.isEmpty()) {
            return null;
        }
        if (!"client_id".equals(mode)) {
            throw new IllegalStateException(
                    "OIDF_ATTESTATION_SUB must be unset or 'client_id', got: " + mode);
        }
        String clientId = required("OIDF_AGENT_CLIENT_ID");
        LOGGER.info((Object) ("OIDF_ATTESTATION_SUB=client_id — attestation sub is the registered client "
                + clientId + "; the instance identity rides as agent_id"));
        return clientId;
    }

    /**
     * The directory URL, naming the rename if the old variable is the one that is set. The registry
     * moved from five private tables to the Identity Object Model, so a service still pointed at
     * {@code DATABASE_URL} would be reading a schema that no longer holds instances — a silent
     * "unknown instance" on every lookup rather than a startup failure.
     */
    private static String requireIdmUrl() {
        String url = System.getenv("IDM_DATABASE_URL");
        if (url != null && !url.isBlank()) {
            return url;
        }
        String legacy = System.getenv("DATABASE_URL");
        if (legacy != null && !legacy.isBlank()) {
            throw new IllegalStateException("IDM_DATABASE_URL is required (DATABASE_URL is set, but the "
                    + "registry now lives in the Identity Object Model directory — point IDM_DATABASE_URL "
                    + "at the directory that holds the SCIM users, and apply the model repo's "
                    + "006-add-agent-instance-registry migration to it)");
        }
        throw new IllegalStateException("IDM_DATABASE_URL is required");
    }

    /**
     * Accepts either a JDBC URL or a {@code postgresql://user:pass@host:port/db} DSN — the shape a
     * Railway reference variable ({@code ${{Postgres.DATABASE_URL}}}) expands to, which the PG driver
     * does not take directly.
     */
    private static DataSource dataSource(String url) {
        PGSimpleDataSource source = new PGSimpleDataSource();
        source.setUrl(toJdbcUrl(url));
        return source;
    }

    static String toJdbcUrl(String url) {
        String trimmed = url.trim();
        if (trimmed.startsWith("jdbc:")) {
            return trimmed;
        }
        if (!trimmed.startsWith("postgresql://") && !trimmed.startsWith("postgres://")) {
            throw new IllegalArgumentException("not a Postgres URL: " + trimmed);
        }
        try {
            URI uri = new URI(trimmed);
            StringBuilder jdbc = new StringBuilder("jdbc:postgresql://")
                    .append(uri.getHost())
                    .append(uri.getPort() < 0 ? "" : ":" + uri.getPort())
                    .append(uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath());
            String userInfo = uri.getUserInfo();
            String query = uri.getQuery();
            List<String> params = new ArrayList<>();
            if (userInfo != null && !userInfo.isBlank()) {
                int colon = userInfo.indexOf(':');
                String user = colon < 0 ? userInfo : userInfo.substring(0, colon);
                params.add("user=" + URLEncoder.encode(decode(user), StandardCharsets.UTF_8));
                if (colon >= 0) {
                    params.add("password="
                            + URLEncoder.encode(decode(userInfo.substring(colon + 1)), StandardCharsets.UTF_8));
                }
            }
            if (query != null && !query.isBlank()) {
                params.add(query);
            }
            if (!params.isEmpty()) {
                jdbc.append('?').append(String.join("&", params));
            }
            return jdbc.toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("malformed Postgres URL: " + trimmed, e);
        }
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, Object> parseJwk(String json) {
        try {
            return JsonUtil.parseJson(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("ENROLMENT_SIGNING_JWK is not a JSON JWK", e);
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set");
        }
        return value.trim();
    }
}
