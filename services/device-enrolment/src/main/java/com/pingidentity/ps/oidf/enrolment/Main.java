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
import com.pingidentity.ps.oidf.device.JdbcInstanceRegistry;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.sql.DataSource;
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
 *   DATABASE_URL                  Postgres JDBC URL. Absent → refuses to start
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
        String teamId = required("APPLE_TEAM_ID");
        String bundleId = required("APPLE_BUNDLE_ID");
        boolean allowDevelopment = Boolean.parseBoolean(env("APPLE_ALLOW_DEVELOPMENT", "false"));
        int port = Integer.parseInt(env("PORT", "8080"));
        long uvMaxAge = Long.parseLong(env("UV_MAX_AGE_SECONDS", "300"));
        boolean requireCompliant = Boolean.parseBoolean(env("REQUIRE_COMPLIANT_DEVICE", "true"));

        AppAttestConfig appAttestConfig = allowDevelopment
                ? AppAttestConfig.allowingDevelopment(teamId, bundleId)
                : AppAttestConfig.production(teamId, bundleId);
        if (allowDevelopment) {
            // Loud on purpose: this weakens the strongest assertion the service makes.
            LOGGER.warn((Object) "APPLE_ALLOW_DEVELOPMENT is set — development App Attest objects will "
                    + "be accepted. Every such enrolment is flagged in the registry, but this must not "
                    + "be set in production.");
        }

        DataSource dataSource = dataSource(required("DATABASE_URL"));
        InstanceRegistry registry = new JdbcInstanceRegistry(dataSource);

        JwsSigner signer = new LocalJwkSigner(parseJwk(required("ENROLMENT_SIGNING_JWK")));
        DeviceAttestationMinter minter = new DeviceAttestationMinter(issuer, subjectClientId());

        EnrolmentService service = new EnrolmentService(
                new AppAttestVerifier(appAttestConfig),
                pingOneVerifier(),
                registry, minter,
                new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(),
                signer, issuer, Duration.ofSeconds(uvMaxAge), requireCompliant);

        EnrolmentHttpServer server = new EnrolmentHttpServer(service, signer, port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
        LOGGER.info((Object) ("issuer=" + issuer + " appId=" + teamId + "." + bundleId
                + " uvMaxAge=" + uvMaxAge + "s requireCompliantDevice=" + requireCompliant));
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

    private static DataSource dataSource(String url) {
        PGSimpleDataSource source = new PGSimpleDataSource();
        source.setUrl(url);
        return source;
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
