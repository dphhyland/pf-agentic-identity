/*
 * Wires the enrolment service from its settings and starts it, once the production profile has let it.
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
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.io.PrintStream;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
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
 * are, and read through the {@code device-enrolment} settings catalogue
 * ({@code META-INF/oidf-settings/device-enrolment.json}; docs/configuration/device-enrolment.md) - strictly, from 0.6.0
 * (plan item ST-5): a switch is {@code true} or {@code false}, a number a whole number in its range, a choice one of
 * its choices, and anything else stops the service naming the setting. Under the development profile a value only the
 * old reader took ({@code yes}, {@code 1}, a padded number) is read as that reader read it, with a warning.
 *
 * <pre>
 *   PORT                          listen port (default 8080)
 *   ENROLMENT_ISSUER              this service's entity id — the attestation iss, and the proof aud
 *   ENROLMENT_SIGNING_JWK         the attester's private JWK (dev). Production should use a vault-backed
 *                                 JwsSigner instead; the seam already exists
 *   IDM_DATABASE_URL              the Identity Object Model directory (Postgres) this service records
 *                                 instances in — the SAME directory the SCIM users live in, so an agent
 *                                 sits beside its owner. Accepts a jdbc:postgresql: URL or a postgresql:// DSN
 *                                 (Railway's reference-variable form). Absent → refuses to start
 *   APPLE_TEAM_ID / APPLE_BUNDLE_ID   the App ID an attestation must be bound to
 *   APPLE_ALLOW_DEVELOPMENT       true to accept development App Attest. Off by default; forbidden in production
 *   APPLE_MACOS_REQUIRE_KEY_POLICY false to accept a Mac whose App Attest key does not show Full Security
 *                                 and SIP (macOS 27 writes the condition into the certificate). On by default
 *   APPLE_REQUIRE_RENEWAL_ASSERTION false to renew a connector that enrolled with App Attest without a fresh
 *                                 assertion from the same app. On by default
 *   CONNECTOR_BUILDS              comma-separated base64url SHA-256 hashes of the connector builds to accept,
 *                                 committed through App Attest; empty accepts any build and records it
 *   UV_MAX_AGE_SECONDS            the server-side time-box (default 300)
 *   REQUIRE_COMPLIANT_DEVICE      false to allow minting on an unassessed device (default true); forbidden in
 *                                 production
 *   OIDF_ATTESTATION_SUB          "client_id" flips the attestation sub to the registered client id
 *                                 (Phase 2.5; requires OIDF_AGENT_CLIENT_ID). Unset → legacy
 *                                 sub = instance id. agent_id carries the instance id either way
 *   OIDF_AGENT_CLIENT_ID          the OAuth client the device agents are instances of — required when
 *                                 OIDF_ATTESTATION_SUB=client_id, ignored otherwise
 * </pre>
 *
 * <p>Two defaults are deliberately strict, because the failure mode of getting them wrong is silent:
 * development App Attest is refused unless asked for, and a device whose compliance is unknown cannot
 * mint. Both fail closed, and under the production profile neither can be turned off (plan item PR-3).
 *
 * <p>Before anything is wired, {@link #audit} holds this process's settings to the production profile (plan item
 * PR-5): a forbidden switch set ({@code REQUIRE_COMPLIANT_DEVICE=false}, {@code APPLE_ALLOW_DEVELOPMENT=true},
 * {@code PF_AUTHORITY_INSECURE_TLS=true}, {@code PF_AUTHORITY_ADMIN_TOKEN}), a governed one that does not parse, or
 * {@code REGISTRY=memory} without the {@code in-memory-state} risk accepted. This is one component with no
 * PingFederate to keep serving, so under production any violation stops the process - exit status 1, every violation
 * on stderr - and under development each is a warning. The device path itself is not production-usable until Phase 6
 * (the programme plan's M-2).
 */
public final class Main {

    private static final Log LOGGER = LogFactory.getLog(Main.class);

    /** The settings catalogue this service reads. */
    static final String CATALOGUE = "device-enrolment";
    /** The exit status when the service refuses to start: a setting or the production profile. */
    static final int REFUSED = 1;

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        int status = run(System::getenv, System::getProperty, System.err);
        if (status != 0) {
            System.exit(status);
        }
    }

    /**
     * Audits the settings, wires the service and starts it: 0 once it is serving, {@link #REFUSED} when the production
     * profile or a setting refuses it, with the reason on {@code err}.
     */
    static int run(Function<String, String> env, Function<String, String> systemProperties, PrintStream err) throws Exception {
        EnrolmentHttpServer server = prepare(env, systemProperties, err);
        if (server == null) {
            return REFUSED;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
        return 0;
    }

    /**
     * The decision {@link #run} acts on: the audit, then the wiring. The server, built and not started, or null when
     * the production profile or a setting refuses it, with the reason on {@code err}.
     */
    static EnrolmentHttpServer prepare(Function<String, String> env, Function<String, String> systemProperties,
            PrintStream err) throws Exception {
        Settings settings = Settings.of(catalogue(), Sources.of(env, systemProperties, null));
        if (!audit(settings.catalogue(), env, systemProperties, err)) {
            return null;
        }
        try {
            return wire(settings, DeploymentProfile.of(env));
        } catch (IllegalStateException | IllegalArgumentException e) {
            // SettingRefused and ProfileRefused are IllegalStateExceptions: a setting refused, or the profile.
            err.println("device-enrolment did not start: " + e.getMessage());
            return null;
        }
    }

    /** This service's catalogue, from its own loader. */
    static Catalogue catalogue() {
        return Catalogue.load(Main.class.getClassLoader(), CATALOGUE);
    }

    /**
     * The start-up audit (plan item PR-5) over this service's own catalogue: under the production profile, false with
     * every violation on {@code err} when there is one; under development, each violation is a warning and it is true.
     */
    static boolean audit(Catalogue catalogue, Function<String, String> env, Function<String, String> systemProperties,
            PrintStream err) {
        DeploymentProfile profile = DeploymentProfile.of(env);
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env, systemProperties, null), List.of(catalogue), profile,
                AcceptedRisks.of(env, LocalDate.now(ZoneOffset.UTC)));
        result.warnings().forEach(warning -> LOGGER.warn((Object) warning));
        if (result.refuses()) {
            err.println("device-enrolment refused to start by the production profile (" + DeploymentProfile.describe(env)
                    + "), for " + result.violations().size() + " setting(s):");
            for (ProfileAudit.Violation v : result.violations()) {
                err.println("  " + v.message());
            }
            return false;
        }
        for (ProfileAudit.Violation v : result.violations()) {
            LOGGER.warn((Object) ("Development profile: device-enrolment would be refused under production - " + v.message()));
        }
        return true;
    }

    /** Everything the service needs, from its settings; the server is built, not started. */
    static EnrolmentHttpServer wire(Settings settings, DeploymentProfile profile) throws Exception {
        String issuer = required(settings.string("ENROLMENT_ISSUER"), "ENROLMENT_ISSUER");
        int port = settings.integer("PORT");
        Duration uvMaxAge = settings.duration("UV_MAX_AGE_SECONDS");
        boolean requireCompliant = settings.bool("REQUIRE_COMPLIANT_DEVICE");

        // App Attest is optional now: a deployment that only enrols connector agents with YubiKey or
        // self-asserted evidence needs no Apple configuration. Set both or neither.
        AppAttestVerifier appAttest = null;
        String teamId = settings.string("APPLE_TEAM_ID");
        String bundleId = settings.string("APPLE_BUNDLE_ID");
        boolean allowDevelopment = settings.bool("APPLE_ALLOW_DEVELOPMENT");
        if (teamId != null && bundleId != null) {
            appAttest = new AppAttestVerifier(allowDevelopment
                    ? AppAttestConfig.allowingDevelopment(teamId, bundleId)
                    : AppAttestConfig.production(teamId, bundleId));
            if (allowDevelopment) {
                // Loud on purpose: this weakens the strongest assertion the service makes. The audit has already
                // refused it under production.
                LOGGER.warn((Object) "APPLE_ALLOW_DEVELOPMENT is true — development App Attest objects will "
                        + "be accepted. Every such enrolment is flagged in the registry; production refuses to start with it.");
            }
        } else if ((teamId == null) != (bundleId == null)) {
            throw new IllegalStateException("set both APPLE_TEAM_ID and APPLE_BUNDLE_ID, or neither");
        }

        InstanceRegistry registry;
        if ("memory".equals(settings.choice("REGISTRY"))) {
            LOGGER.warn((Object) "REGISTRY=memory: enrolments live in this process only and are lost on restart (dev only)");
            registry = new InMemoryInstanceRegistry();
        } else {
            registry = new IomInstanceRegistry(dataSource(requireIdmUrl(settings)));
        }

        JwsSigner signer = new LocalJwkSigner(parseJwk(required(settings.secret("ENROLMENT_SIGNING_JWK"), "ENROLMENT_SIGNING_JWK")));
        String subjectClientId = subjectClientId(settings);
        DeviceAttestationMinter minter = new DeviceAttestationMinter(issuer, subjectClientId);

        EnrolmentService service = new EnrolmentService(
                appAttest,
                pingOneVerifier(settings),
                registry, minter,
                new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(),
                signer, issuer, uvMaxAge, requireCompliant,
                BindingNotifier.logOnly(), agentOptions(settings, subjectClientId, profile));

        EnrolmentHttpServer server = new EnrolmentHttpServer(service, signer, port);
        LOGGER.info((Object) ("issuer=" + issuer + " appAttest=" + (appAttest == null ? "off" : teamId + "." + bundleId)
                + " uvMaxAge=" + uvMaxAge.toSeconds() + "s requireCompliantDevice=" + requireCompliant));
        return server;
    }

    /**
     * The connector-agent path (Mac connector experiment). Everything is off unless configured:
     *
     * <pre>
     *   YUBICO_PIV_ROOTS            PEM bundle of pinned Yubico PIV roots: accept yubikey-piv evidence
     *   ALLOW_SELF_ASSERTED_KEYS    true to accept secure-enclave-self-asserted evidence (no key_storage claim)
     *   AGENT_AUTHORIZATION_DETAILS JSON array: the RFC 9396 ceiling every connector attestation carries
     *   PF_AUTHORITY_ENTITY_ID      the federation authority (PingFederate's issuer) hosting agent entities
     *   PF_AUTHORITY_URL            where to reach it from here (defaults to the entity id)
     *   PF_AUTHORITY_CLIENT_ID      device-enrolment's PingFederate client: a DPoP-bound client-credentials token with
     *                               oidf.admin.entities for the hosted-entity API, by PF_AUTHORITY_CLIENT_JWK
     *                               (private_key_jwt) or PF_AUTHORITY_CLIENT_SECRET (client_secret_basic), at
     *                               PF_AUTHORITY_TOKEN_ENDPOINT (default &lt;PF_AUTHORITY_URL&gt;/as/token.oauth2)
     *   PF_AUTHORITY_ADMIN_TOKEN    development only: the authority's static bearer (OIDF_AUTHORITY_ADMIN_TOKEN over
     *                               there); production refuses to start with it set
     *   PF_AUTHORITY_INSECURE_TLS   true to trust its self-signed listener (dev only; production refuses to start)
     *   AGENT_DISPLAY_NAME, AGENT_DESCRIPTION, AGENT_KEYWORDS (JSON array)
     *                               what the authority vouches for about every agent, in its own words
     *   AGENT_MISSION_TYPES         JSON array: the RAR types an agent may claim as its mission
     *   AGENT_MISSION_PURPOSES      JSON array: the DPV purposes an agent may pursue
     * </pre>
     */
    private static EnrolmentService.AgentOptions agentOptions(Settings settings, String clientId, DeploymentProfile profile)
            throws Exception {
        PivAttestationVerifier piv = null;
        java.nio.file.Path roots = settings.path("YUBICO_PIV_ROOTS");
        if (roots != null) {
            piv = PivAttestationVerifier.fromPemFile(roots);
        }
        boolean selfAsserted = settings.bool("ALLOW_SELF_ASSERTED_KEYS");
        if (selfAsserted) {
            LOGGER.warn((Object) "ALLOW_SELF_ASSERTED_KEYS=true: keys whose storage nobody can verify will be attested"
                    + " (without a key_storage claim)");
        }
        java.util.List<Map<String, Object>> authz = null;
        String authzJson = settings.string("AGENT_AUTHORIZATION_DETAILS");
        if (authzJson != null) {
            authz = new com.fasterxml.jackson.databind.ObjectMapper().readValue(authzJson,
                    new com.fasterxml.jackson.core.type.TypeReference<java.util.List<Map<String, Object>>>() { });
        }
        HostedEntityRegistrar federation = HostedEntityRegistrar.disabled();
        String authority = settings.string("PF_AUTHORITY_ENTITY_ID");
        if (authority != null) {
            URI authorityUrl = settings.url("PF_AUTHORITY_URL");
            URI tokenEndpoint = settings.url("PF_AUTHORITY_TOKEN_ENDPOINT");
            federation = HostedEntityRegistrar.PingFederate.of(authority, new AuthorityCredentials.Settings(
                    authorityUrl == null ? authority : authorityUrl.toString(), revealed(settings.secret("PF_AUTHORITY_ADMIN_TOKEN")),
                    settings.string("PF_AUTHORITY_CLIENT_ID"), revealed(settings.secret("PF_AUTHORITY_CLIENT_SECRET")),
                    revealed(settings.secret("PF_AUTHORITY_CLIENT_JWK")), tokenEndpoint == null ? null : tokenEndpoint.toString()),
                    settings.bool("PF_AUTHORITY_INSECURE_TLS"), profile);
        }
        String software = clientId == null ? "claude-bank-connector" : clientId;
        AgentMission mission = agentMission(software, settings::string);
        boolean macKeyPolicy = settings.bool("APPLE_MACOS_REQUIRE_KEY_POLICY");
        if (!macKeyPolicy) {
            LOGGER.warn((Object) "APPLE_MACOS_REQUIRE_KEY_POLICY=false: a Mac's App Attest key need not show Full Security"
                    + " and SIP, so its code signing cannot be relied on");
        }
        java.util.Set<String> listed = settings.words("CONNECTOR_BUILDS");
        java.util.Set<String> builds = listed == null ? new java.util.LinkedHashSet<>() : new java.util.LinkedHashSet<>(listed);
        boolean renewalAssertion = settings.bool("APPLE_REQUIRE_RENEWAL_ASSERTION");
        return new EnrolmentService.AgentOptions(federation, piv, selfAsserted, authz, mission.metadata(), mission.policy(),
                macKeyPolicy, builds, renewalAssertion);
    }

    /** What the authority says about every agent it hosts: vouched metadata, and the policy capping the rest. */
    record AgentMission(Map<String, Object> metadata, Map<String, Object> policy) {
    }

    /**
     * The agent's mission as the federation will see it. The metadata goes into the authority's Subordinate
     * Statement about each agent and replaces whatever the agent wrote for those members; the policy caps
     * what the agent may claim for itself. Both RAR types and purposes are {@code essential}: an agent that
     * declares no mission does not resolve at all.
     */
    static AgentMission agentMission(String software, java.util.function.UnaryOperator<String> env) throws java.io.IOException {
        com.fasterxml.jackson.databind.ObjectMapper json = new com.fasterxml.jackson.databind.ObjectMapper();
        com.fasterxml.jackson.core.type.TypeReference<java.util.List<String>> strings = new com.fasterxml.jackson.core.type.TypeReference<>() { };
        Map<String, Object> oauthClient = new java.util.LinkedHashMap<>();
        oauthClient.put("client_name", "Claude bank connector");
        oauthClient.put("software_id", software);
        oauthClient.put("token_endpoint_auth_method", "attest_jwt_client_auth");
        putIfSet(oauthClient, "display_name", env.apply("AGENT_DISPLAY_NAME"));
        putIfSet(oauthClient, "description", env.apply("AGENT_DESCRIPTION"));
        String keywords = env.apply("AGENT_KEYWORDS");
        if (keywords != null && !keywords.isBlank()) {
            oauthClient.put("keywords", json.readValue(keywords, strings));
        }
        // The authority's lever on a self-signed configuration: whatever the agent writes, these hold.
        Map<String, Object> clientPolicy = new java.util.LinkedHashMap<>();
        clientPolicy.put("software_id", Map.of("value", software));
        clientPolicy.put("token_endpoint_auth_method", Map.of("value", "attest_jwt_client_auth"));
        String types = env.apply("AGENT_MISSION_TYPES");
        if (types != null && !types.isBlank()) {
            clientPolicy.put("authorization_details_types", Map.of("subset_of", json.readValue(types, strings), "essential", true));
        }
        String purposes = env.apply("AGENT_MISSION_PURPOSES");
        if (purposes != null && !purposes.isBlank()) {
            clientPolicy.put("purposes", Map.of("subset_of", json.readValue(purposes, strings), "essential", true));
        }
        return new AgentMission(Map.of("oauth_client", oauthClient), Map.of("oauth_client", clientPolicy));
    }

    private static void putIfSet(Map<String, Object> target, String name, String value) {
        if (value != null && !value.isBlank()) {
            target.put(name, value);
        }
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
    static UserAuthenticationVerifier pingOneVerifier(Settings settings) {
        String issuer = settings.string("PINGONE_ISSUER");
        String clientId = settings.string("PINGONE_CLIENT_ID");
        if (issuer == null || clientId == null) {
            LOGGER.warn((Object) "PINGONE_ISSUER / PINGONE_CLIENT_ID are unset — user authentication "
                    + "will be refused, so enrolment cannot complete on this deployment.");
            return evidence -> {
                throw EnrolmentException.userAuthenticationFailed(
                        "no IdP is configured on this deployment");
            };
        }
        Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr = new LinkedHashMap<>();
        java.util.Set<String> aal2 = settings.words("PINGONE_ACR_AAL2");
        for (String name : aal2 == null ? java.util.Set.<String>of() : aal2) {
            assuranceByAcr.put(name, UserAuthentication.AssuranceLevel.AAL2);
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
    private static String subjectClientId(Settings settings) {
        if (settings.choice("OIDF_ATTESTATION_SUB") == null) {
            return null;
        }
        String clientId = required(settings.string("OIDF_AGENT_CLIENT_ID"), "OIDF_AGENT_CLIENT_ID");
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
    private static String requireIdmUrl(Settings settings) {
        Secret url = settings.secret("IDM_DATABASE_URL");
        if (url != null) {
            return url.reveal();
        }
        if (settings.secret("DATABASE_URL") != null) {
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

    /** The one JDBC scheme the registry takes. */
    static final String POSTGRESQL_JDBC = "jdbc:postgresql:";

    static String toJdbcUrl(String url) {
        String trimmed = url.trim();
        if (trimmed.startsWith("jdbc:")) {
            if (!trimmed.regionMatches(true, 0, POSTGRESQL_JDBC, 0, POSTGRESQL_JDBC.length())) {
                // The scheme only: the rest of a JDBC URL can carry a password.
                int second = trimmed.indexOf(':', "jdbc:".length());
                throw new IllegalArgumentException("IDM_DATABASE_URL names a " + (second < 0 ? "non-JDBC" : trimmed.substring(0,
                        second + 1)) + " database: the instance registry is PostgreSQL only (its tables are the Identity"
                        + " Object Model's, and this service ships only PostgreSQL's driver); use a " + POSTGRESQL_JDBC
                        + " URL or a postgresql:// DSN");
            }
            return trimmed;
        }
        if (!trimmed.startsWith("postgresql://") && !trimmed.startsWith("postgres://")) {
            // The scheme only, never the value: a DSN carries its password in the user information.
            throw new IllegalArgumentException("IDM_DATABASE_URL is not a PostgreSQL URL (its scheme is " + scheme(trimmed)
                    + "): use a " + POSTGRESQL_JDBC + " URL or a postgresql:// DSN");
        }
        try {
            URI uri = new URI(trimmed);
            StringBuilder jdbc = new StringBuilder("jdbc:postgresql://")
                    .append(uri.getHost())
                    .append(uri.getPort() < 0 ? "" : ":" + uri.getPort())
                    // A hierarchical URI with an authority always has a path, empty when none is written.
                    .append(uri.getPath().isEmpty() ? "/" : uri.getPath());
            String userInfo = uri.getUserInfo();
            String query = uri.getQuery();
            List<String> params = new ArrayList<>();
            if (userInfo != null && !userInfo.isBlank()) {
                int colon = userInfo.indexOf(':');
                String user = colon < 0 ? userInfo : userInfo.substring(0, colon);
                params.add("user=" + URLEncoder.encode(decode(user, "user"), StandardCharsets.UTF_8));
                if (colon >= 0) {
                    params.add("password="
                            + URLEncoder.encode(decode(userInfo.substring(colon + 1), "password"), StandardCharsets.UTF_8));
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
            // The reason and its index, not the input or the cause: both repeat the URL, password and all.
            throw new IllegalArgumentException("IDM_DATABASE_URL is a malformed PostgreSQL DSN: " + e.getReason()
                    + " at index " + e.getIndex());
        }
    }

    /**
     * A URL's scheme when it names one with an authority ({@code scheme://}), never more of the value; "missing"
     * otherwise, since the text before a colon may be a user name.
     */
    static String scheme(String url) {
        int colon = url.indexOf("://");
        return colon > 0 && url.substring(0, colon).matches("[A-Za-z][A-Za-z0-9+.-]*") ? url.substring(0, colon + 1) : "missing";
    }

    /** Percent-decodes part of a DSN's user information; a bad escape is refused without echoing the part. */
    private static String decode(String value, String part) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("IDM_DATABASE_URL's " + part + " has a malformed percent escape");
        }
    }

    private static Map<String, Object> parseJwk(String json) {
        try {
            return JsonUtil.parseJson(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("ENROLMENT_SIGNING_JWK is not a JSON JWK", e);
        }
    }

    /** {@code value}, or a refusal naming {@code name} when it is unset. */
    private static String required(String value, String name) {
        if (value == null) {
            throw new SettingRefused(name, name + " must be set");
        }
        return value;
    }

    private static String required(Secret value, String name) {
        if (value == null) {
            throw new SettingRefused(name, name + " must be set");
        }
        return value.reveal();
    }

    private static String revealed(Secret value) {
        return value == null ? null : value.reveal();
    }
}
