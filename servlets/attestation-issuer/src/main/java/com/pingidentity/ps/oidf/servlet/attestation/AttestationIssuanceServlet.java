/*
 * Attestation issuance endpoint: a SPIFFE workload exchanges its JWT-SVID for a Client Attestation.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.issuer.AssertedContext;
import com.pingidentity.ps.oidf.issuer.AssertedContextResolver;
import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.AttestationMinter;
import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.EvidenceBindingStore;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.issuer.EvidencePolicy;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.issuer.AttesterSigningKey;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.issuer.EntraDirectoryAssertedContextResolver;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationWalletProviderKeyResolver;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.issuer.InstanceIdentity;
import com.pingidentity.ps.oidf.issuer.ChainClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.issuer.WalletInstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.issuer.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.net.TrustedProxies;
import com.pingidentity.ps.oidf.platform.pf.auth.InMemoryWindowCounter;
import com.pingidentity.ps.oidf.platform.pf.auth.RedisWindowCounter;
import com.pingidentity.ps.oidf.platform.pf.auth.WindowCounter;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.rar.model.Omission;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.issuer.RemoteJwksCache;
import com.pingidentity.ps.oidf.issuer.SpiffeBinding;
import com.pingidentity.ps.oidf.issuer.SpiffeInstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.SpireSelectorIntrospector;
import com.pingidentity.ps.oidf.issuer.WorkloadIntrospector;
import com.pingidentity.ps.oidf.agent.AgentRegistry;
import com.pingidentity.ps.oidf.agent.AgentRegistryException;
import com.pingidentity.ps.oidf.agent.AgentRegistrySupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;

/**
 * Issues a Client Attestation to a workload that proves its identity with a SPIFFE JWT-SVID. A workload
 * that wants to act as an instance of a registered client {@code POST}s here with its {@code client_id},
 * its instance public JWK, its SVID, and a proof of possession of the instance key. The servlet resolves
 * the client's issuance config (attester key, SPIFFE trust bundle, one-to-many instance bindings),
 * validates the SVID against the bundle, checks the SPIFFE ID is bound to the client, verifies the
 * instance-key proof (with challenge/replay protection), enforces the RFC 9396 entitlement ceiling, and
 * mints a short-lived attestation signed with the client's per-client attester key
 * ({@link AttesterSigningKey}: OpenBao transit or inline JWK).
 *
 * <p>This is the <em>issuance</em> side only. The minted attestation is later presented by the workload
 * (with a fresh proof of possession) at the AS token endpoint via the existing client-authentication
 * path, which this servlet does not touch.
 *
 * <p>Response: {@code 200 {"attestation":"<jwt>","expires_in":N}} ({@code Cache-Control: no-store}); on
 * failure a JSON body {@code {"error":..,"error_description":..}} with a CAS §4.6 code and 4xx/5xx status, and an
 * {@value #CORRELATION_HEADER} header naming the log line that has the detail.
 *
 * <p>Before anything is read (plan item H-ATT-2, F-0060): the caller's client address - platform's
 * {@link TrustedProxies} - is counted, and past {@value #RATE_SETTING} requests in its minute it is answered 429
 * {@code temporarily_unavailable} with {@code Retry-After}; then the body is read, at most {@value #MAX_BODY_SETTING}
 * bytes of it, and a larger one is answered 413 {@code invalid_request} with no more read. Every failure, an
 * unexpected one included, is answered with a §4.6 error; a 5xx or {@code invalid_client} carries a fixed description
 * and the correlation id, never the exception's text, since that can name an internal URL, a vault or PingFederate's
 * own configuration. Methods other than POST are answered 405 {@code invalid_request}.
 */
// loadOnStartup: ATTESTATION_ISSUER's part registers at deploy, not on the first request (finding F-0193); its init
// never throws.
@WebServlet(urlPatterns = {"/federation/attestation"}, loadOnStartup = 1)
public class AttestationIssuanceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(AttestationIssuanceServlet.class);

    private volatile IssuanceClientResolver clientResolver;
    private volatile AttesterSigningKey attesterSigningKey;
    private volatile InstanceAttestationValidators instanceValidators;
    private volatile RemoteJwksCache jwksCache = new RemoteJwksCache();
    private volatile InstanceKeyProofValidator proofValidator = new InstanceKeyProofValidator();
    private volatile WorkloadIntrospector workloadIntrospector;
    private volatile AgentRegistry agentRegistry;
    private volatile Map<String, AssertedContextResolver> assertedContextResolvers;
    private boolean challengeRequired;
    private volatile List<String> customClaimsRequired = List.of();
    private volatile EvidencePolicy evidencePolicy;
    private volatile EvidenceBindingStore evidenceBindings;
    private volatile AttestationChallengeService challengeService;
    private volatile AttestationReplayCache replayCache;
    private volatile RarModels rarModels;
    /** This servlet's part of ATTESTATION_ISSUER, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;

    /**
     * The audit event for evidence presented by a second instance key or client: the rightful holder's evidence
     * has been used elsewhere, or the rightful holder is the one being refused because a thief presented first.
     * Either way the deployment is told, with both keys' thumbprints: {@code presented_jkt} for the key refused
     * now, {@code bound_jkt} and {@code bound_client} for the key and client that hold the binding.
     */
    public static final String EVIDENCE_CONFLICT_EVENT = "attestation.evidence.conflict";

    /** The largest body read, in bytes. */
    static final String MAX_BODY_SETTING = "OIDF_ATTESTER_MAX_BODY_BYTES";
    /** Issuance requests per client address per minute. */
    static final String RATE_SETTING = "OIDF_ATTESTER_ISSUANCE_REQUESTS_PER_MINUTE";
    /** How often the client index is rebuilt ({@link ClientBindingIndex}). */
    static final String CLIENT_INDEX_REFRESH_SETTING = "OIDF_ATTESTER_CLIENT_INDEX_REFRESH_SECONDS";
    /** The catalogue defaults, for a servlet a test made without {@code init}. */
    static final int DEFAULT_MAX_BODY_BYTES = 32 * 1024;
    static final int DEFAULT_REQUESTS_PER_MINUTE = 60;
    /** Where the per-address counts are kept in Redis. */
    static final String RATE_NAMESPACE = "oidf:cas:limit:issue";
    /** The response header that carries a failure's correlation id; the log line with the detail carries it too. */
    static final String CORRELATION_HEADER = "X-Correlation-Id";

    private static final Duration MINUTE = Duration.ofMinutes(1);

    private volatile int maxBodyBytes = DEFAULT_MAX_BODY_BYTES;
    private volatile int requestsPerMinute = DEFAULT_REQUESTS_PER_MINUTE;
    /** The per-address counter: injected, else Redis's or this node's, made on the first request. */
    private transient volatile WindowCounter rateCounter;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ComponentParts.Part part = Startup.begin(Startup.ATTESTATION_ISSUER, "AttestationIssuanceServlet");
        this.part = part;
        part.start(() -> this.init(config, part));
    }

    /**
     * The start function: what {@code init} did before S-9, run by {@link ComponentParts.Part#start} at deploy and again
     * by each supervisor retry after a dependency failure. What it throws is the part's state, never the container's.
     */
    private void init(ServletConfig config, ComponentParts.Part part) throws ServletException {
        // The attester's challenges, spent proof jtis and evidence bindings: shared through Redis, or this node's memory,
        // which the production profile allows only with the in-memory-state risk (Phase 3 plan, decisions 9 and 15).
        AttestationSupport.requireSharedState(StoreNamespace.CAS);
        // The conflict event belongs in PingFederate's audit log; the sink is installed once per classloader, by
        // whichever servlet or filter initialises first.
        PfAuditEventSink.install();
        // Every setting this servlet reads, strictly, through the attestation-issuer catalogue (plan item ST-5): a value
        // its entry refuses is FAILED_CONFIG, naming the setting, before anything is configured. The four read again
        // when the first request builds its validators and resolvers are read here too, so a wrong one fails now.
        Settings settings = Settings.of(SETTINGS).with(InitParams.sources(config));
        boolean challengeRequired = settings.bool("challengeRequired");
        List<String> customClaimsRequired = claims(settings, "OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED");
        String baoUrl = settings.string("openBaoUrl");
        Secret baoToken = settings.secret("openBaoToken");
        settings.string("OIDF_ATTESTER_OP_ISSUER");
        settings.jsonObject("OIDF_WALLET_PROVIDER_JWKS");
        settings.jsonObject("OIDF_ENTRA_AGENT_DIRECTORY");
        settings.url("OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        // The request path's limits (H-ATT-2) and the client index's schedule, and the trusted-proxy rule the
        // per-address count depends on (H-ATT-3): a value that cannot be read is FAILED_CONFIG, naming it.
        int maxBodyBytes = settings.integer(MAX_BODY_SETTING);
        int requestsPerMinute = settings.integer(RATE_SETTING);
        settings.duration(CLIENT_INDEX_REFRESH_SETTING);
        TrustedProxies.check();
        // OpenBao: this servlet's two init-params together, else OIDF_OPENBAO_URL and OIDF_OPENBAO_TOKEN and their
        // superseded names, read now for the same reason.
        AttesterSigningKey signingKey = baoUrl != null && baoToken != null ? new AttesterSigningKey(baoUrl, baoToken.reveal())
                : AttesterSigningKey.fromEnvironment();
        // The evidence policy's two settings (the evidence-policy catalogue), read the same way.
        EvidencePolicy evidencePolicy = EvidencePolicy.fromEnvironment();
        // The containment model every ceiling here is held to, once per classloader (the token-endpoint filter
        // shares it in pf-runtime.war). A models document that cannot be read would have this attester mint
        // against something other than what the deployment wrote, so the part is FAILED_CONFIG and the gate answers
        // 503 on its path, and only its path (plan item S-9).
        if (this.rarModels == null) {
            try {
                this.rarModels = AttestationRarModels.get();
            } catch (RarModelException e) {
                throw new ServletException("attestation issuance: the RAR containment models could not be loaded: "
                        + e.getMessage() + ". Fix " + RarModels.ENV_MODELS_FILE + " or " + RarModels.ENV_MODELS + ".", e);
            }
        }
        this.challengeRequired = challengeRequired;
        this.customClaimsRequired = customClaimsRequired;
        this.maxBodyBytes = maxBodyBytes;
        this.requestsPerMinute = requestsPerMinute;
        if (this.attesterSigningKey == null) {
            this.attesterSigningKey = signingKey;
        }
        if (this.evidencePolicy == null) {
            this.evidencePolicy = evidencePolicy;
        }
    }

    /** The settings catalogue this servlet and the attester's two metadata servlets read. */
    static final String SETTINGS = "attestation-issuer";

    /** This process's attestation-issuer settings, for a read made when a request first needs it. */
    static Settings processSettings() {
        return Settings.of(Catalogues.ISSUER, Sources.process());
    }

    /** The attestation-issuer catalogue, loaded once from this class's loader, for the reads a request makes. */
    static final class Catalogues {
        static final Catalogue ISSUER = Catalogue.load(AttestationIssuanceServlet.class.getClassLoader(), SETTINGS);

        private Catalogues() {
        }
    }

    /** {@code challengeRequired} from {@code config}'s init-params, strictly, for the attester's configuration servlet. */
    static boolean challengeRequired(ServletConfig config) {
        return Settings.of(SETTINGS).with(InitParams.sources(config)).bool("challengeRequired");
    }

    /** {@code OIDF_ATTESTER_CORS_ORIGINS} as written, strictly, for the attester's configuration servlet; null when unset. */
    static Set<String> corsOrigins(ServletConfig config) {
        return Settings.of(SETTINGS).with(InitParams.sources(config)).words(AttesterConfigurationServlet.CORS_SETTING);
    }

    /** A {@code words} setting as the claim list it is, in the order written; empty when unset. */
    static List<String> claims(Settings settings, String name) {
        Set<String> words = settings.words(name);
        return words == null ? List.of() : List.copyOf(words);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (ComponentGate.oauthEndpoint(this.part, resp)) {
            return;
        }
        if (!"POST".equals(req.getMethod())) {
            resp.setHeader("Allow", "POST");
            fail(resp, new IssuanceException("invalid_request", 405, "this endpoint takes POST, not " + req.getMethod()),
                    null);
            return;
        }
        this.doPost(req, resp);
    }

    /**
     * The request path: the per-address limit, the capped body, the issuance; and every failure, an unexpected one
     * included, answered as an error by {@link #fail}. An {@link Error} - a {@code LinkageError} from PingFederate's
     * classes, say - is answered {@code server_error} too, rather than by the container's own error page; one the JVM
     * raises about itself ({@link VirtualMachineError}) is then thrown on, since the process may not be fit to go on.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");
        try {
            this.admit(req, resp);
            IssuanceRequest request = parseRequest(this.readBody(req));
            Map<String, Object> body = issue(request);
            write(resp, 200, body);
        } catch (IssuanceException e) {
            fail(resp, e, null);
        } catch (RuntimeException | Error e) {
            fail(resp, IssuanceException.serverError("unexpected " + e), e);
            if (e instanceof VirtualMachineError vme) {
                throw vme;
            }
        }
    }

    /**
     * Counts one request against the caller's client address, and refuses it past {@value #RATE_SETTING} in the
     * address's minute: 429 {@code temporarily_unavailable} with {@code Retry-After}. A counter that cannot be written
     * refuses the request 503, as the challenge and replay stores do, rather than letting it through uncounted.
     */
    void admit(HttpServletRequest req, HttpServletResponse resp) throws IssuanceException {
        String address = TrustedProxies.current().clientAddress(req.getRemoteAddr(), name -> headerValues(req, name));
        String key = address == null || address.isBlank() ? "-" : address;
        WindowCount count;
        try {
            count = this.rateCounter().hit(key, MINUTE);
        } catch (IOException | RuntimeException e) {
            throw IssuanceException.temporarilyUnavailable("the issuance rate-limit counter could not be written: " + e);
        }
        if (count.count() > this.requestsPerMinute) {
            long retryAfter = Math.max(1L, (count.remaining().toMillis() + 999L) / 1000L);
            resp.setHeader("Retry-After", String.valueOf(retryAfter));
            throw new IssuanceException("temporarily_unavailable", 429, "this address has made more than "
                    + this.requestsPerMinute + " issuance requests this minute; retry in " + retryAfter + " s");
        }
    }

    /** The per-address counter: injected, else in Redis when a URL is set, else this node's (decision 9: no risk). */
    WindowCounter rateCounter() {
        WindowCounter local = this.rateCounter;
        return local != null ? local : this.makeRateCounter();
    }

    /** Makes the counter, unless a request that held the lock first already did. */
    synchronized WindowCounter makeRateCounter() {
        if (this.rateCounter == null) {
            this.rateCounter = defaultRateCounter();
        }
        return this.rateCounter;
    }

    /** Redis's counter when {@code OIDF_REDIS_URL} names one, else this node's; a Redis client made here is closed at shutdown. */
    static WindowCounter defaultRateCounter() {
        if (!RedisConfig.isConfigured()) {
            return new InMemoryWindowCounter(Clock.systemUTC());
        }
        RedisClient redis = new RedisClient(RedisConfig.current());
        Lifecycle.current().register("attester issuance rate limit Redis client", redis);
        return new RedisWindowCounter(redis, RATE_NAMESPACE);
    }

    void setRateCounter(WindowCounter counter) {
        this.rateCounter = counter;
    }

    void setMaxBodyBytes(int maxBodyBytes) {
        this.maxBodyBytes = maxBodyBytes;
    }

    void setRequestsPerMinute(int requestsPerMinute) {
        this.requestsPerMinute = requestsPerMinute;
    }

    /**
     * The body, at most {@value #MAX_BODY_SETTING} bytes of it: one declared larger is refused before any of it is read,
     * and one found larger once the cap is reached - chunked, or with a length that understated it - with nothing more
     * read. PingFederate's {@code pf.runtime.http.maxRequestBodySize} bounds form parameters, not a stream read.
     */
    byte[] readBody(HttpServletRequest req) throws IssuanceException {
        int cap = this.maxBodyBytes;
        if (req.getContentLengthLong() > cap) {
            throw tooLarge(cap);
        }
        byte[] body;
        try {
            body = req.getInputStream().readNBytes(cap + 1);
        } catch (IOException e) {
            throw IssuanceException.invalidRequest("the request body could not be read");
        }
        if (body.length > cap) {
            throw tooLarge(cap);
        }
        return body;
    }

    private static IssuanceException tooLarge(int cap) {
        return new IssuanceException("invalid_request", 413, "the request body is larger than " + cap
                + " bytes, the most this endpoint reads");
    }

    /**
     * Answers {@code e} as a CAS §4.6 error with a fresh correlation id in {@value #CORRELATION_HEADER}. A 5xx or an
     * {@code invalid_client} - the attester's own state or configuration, which can name an internal URL, a vault or a
     * client's settings - gets a fixed description naming the id, and the detail goes to the log at WARN under the same
     * id, with {@code cause}'s stack when there is one; any other 4xx describes the request, and says so.
     */
    static void fail(HttpServletResponse resp, IssuanceException e, Throwable cause) throws IOException {
        String id = UUID.randomUUID().toString();
        resp.setHeader(CORRELATION_HEADER, id);
        String description = e.getMessage();
        if (e.status() >= 500 || "invalid_client".equals(e.error())) {
            description = genericDescription(e.error(), id);
            LOGGER.warn((Object) ("Attestation issuance failed [" + id + "]: " + e.error() + " - " + e.getMessage()), cause);
        } else {
            LOGGER.debug((Object) ("Attestation issuance refused [" + id + "]: " + e.error() + " - " + e.getMessage()));
        }
        write(resp, e.status(), error(e.error(), description));
    }

    /** The fixed description of a failure whose detail stays in the log. */
    static String genericDescription(String error, String id) {
        switch (error) {
            case "temporarily_unavailable":
                return "the attester cannot check this request now; retry later (correlation id " + id + ")";
            case "invalid_client":
                return "the attester cannot issue for this client; its operator can find why under correlation id " + id;
            default:
                return "the attester could not complete this request; its operator can find why under correlation id " + id;
        }
    }

    /** Every value of a request header, for {@link TrustedProxies}; {@code null} when the container gives none. */
    static List<String> headerValues(HttpServletRequest req, String name) {
        Enumeration<String> values = req.getHeaders(name);
        return values == null ? null : Collections.list(values);
    }

    /**
     * Runs the issuance flow for a parsed request. Package-visible so tests can drive it directly with an
     * injected {@link IssuanceClientResolver} and {@link AttesterSigningKey}.
     */
    Map<String, Object> issue(IssuanceRequest request) throws IssuanceException {
        if (request.instanceKey == null || request.instanceKey.isEmpty()) {
            throw IssuanceException.invalidRequest("missing instance_key");
        }
        if (isBlank(request.svid)) {
            throw IssuanceException.invalidRequest("missing svid");
        }
        if (isBlank(request.proof)) {
            throw IssuanceException.invalidRequest("missing proof");
        }

        // 1-3. The workload names no client — it presents only its evidence. The attester reverse-maps
        //       the evidence's identity onto the client it is bound to: validate the evidence under each
        //       attestation client's trust config, and the one whose bundle verifies it AND whose bindings
        //       contain the resulting SPIFFE ID is the match. Which client an identity belongs to is the
        //       attester's knowledge alone.
        Match match = resolveByEvidence(request.svid, request.format);
        AttestationIssuanceConfig config = match.config;
        InstanceIdentity instance = match.instance;
        SpiffeBinding binding = match.binding;
        String clientId = match.clientId;

        // 4. Prove the caller holds the instance key it asks to bind, with freshness + replay protection.
        InstanceKeyProofValidator.Result proof =
                this.proofValidator.validate(request.proof, request.instanceKey, config.issuer());
        if (proof.challenge() != null && !proof.challenge().isBlank()) {
            switch (challengeService().consumeChallenge(proof.challenge())) {
                case CONSUMED:
                    break;
                case STORE_UNAVAILABLE:
                    throw IssuanceException.temporarilyUnavailable("the attestation challenge store is unavailable");
                default:
                    throw IssuanceException.invalidInstanceProof("challenge is unknown, expired, or already used");
            }
        } else if (this.challengeRequired) {
            throw IssuanceException.invalidInstanceProof("a server-issued challenge is required");
        }
        // The jti is remembered until the proof's own window ends (exp + skew, plan item S4c), not for a fixed time
        // from now; a proof whose window closed while the steps above ran is stale, and the store is not asked.
        if (proof.retainUntilEpochSeconds() < this.proofValidator.clock().millis() / 1000L) {
            throw IssuanceException.invalidInstanceProof(InstanceKeyProofValidator.WINDOW_REFUSED);
        }
        switch (replayCache().recordUntil(clientId, proof.jti(), proof.retainUntilEpochSeconds())) {
            case FIRST_USE:
                break;
            case STORE_UNAVAILABLE:
                throw IssuanceException.temporarilyUnavailable("the attestation replay store is unavailable");
            case STALE:
                throw IssuanceException.invalidInstanceProof(InstanceKeyProofValidator.WINDOW_REFUSED);
            default:
                throw IssuanceException.invalidInstanceProof("proof jti has already been used (replay)");
        }

        // 4a. Deployment-required custom claims must be present in the proof (advertised as
        // custom_claims_required in the /.well-known/client-attestation-service metadata). They are
        // evidence for policy only — never copied into the minted attestation.
        for (String claim : this.customClaimsRequired) {
            Object value = proof.claims().get(claim);
            if (value == null || (value instanceof String && ((String) value).isBlank())) {
                throw IssuanceException.invalidInstanceProof("proof is missing required claim: " + claim);
            }
        }

        // 4b. If the instance attestation itself binds a key (a WIA cnf), the key being bound must be that
        //     very key — so the attestation being consumed is about this instance_key, not some other. A
        //     SPIFFE SVID binds no key, so this is a no-op there.
        if (instance.boundKey() != null) {
            try {
                Jwks.assertSameKey(instance.boundKey(), Jwks.fromMap(request.instanceKey));
            } catch (Exception e) {
                throw IssuanceException.invalidInstanceProof(
                        "instance_key does not match the key bound by the instance attestation");
            }
        }

        // 5. Introspect the workload beyond the bare SVID — SPIRE registration selectors, etc. — and
        //    merge those attributes over the binding's declared metadata. These ride into the attestation
        //    and are available to the issuance policy for downscoping.
        Map<String, Object> workloadAttributes = new LinkedHashMap<>(binding.metadata());
        Map<String, Object> introspected = workloadIntrospector().introspect(instance);
        if (introspected != null) {
            workloadAttributes.putAll(introspected);
        }

        // 5a. Optional second-stage resolution of a caller-ASSERTED (unverified) discriminator against the
        //     already-evidenced instance — e.g. an Entra Agent ID oid Copilot Studio cannot cryptographically
        //     prove (its agents share one Microsoft-owned blueprint; only the hosting workload has real
        //     evidence). Off unless the client opts in via P_ASSERTED_CONTEXT_RESOLVER AND the caller actually
        //     supplies one — every existing evidence-only client is completely unaffected. The produced
        //     ceiling only ever NARROWS the evidenced ceiling (intersected below, step 6), never extends it.
        List<Map<String, Object>> assertedCeiling = null;
        if (config.assertedContextResolverId() != null && request.assertedContext != null) {
            AssertedContextResolver resolver = assertedContextResolvers().get(config.assertedContextResolverId());
            if (resolver == null) {
                throw IssuanceException.invalidClient("unknown "
                        + AttestationIssuanceConfig.P_ASSERTED_CONTEXT_RESOLVER + ": "
                        + config.assertedContextResolverId());
            }
            AssertedContext asserted = resolver.resolve(instance, request.assertedContext, config);
            if (!asserted.claims().isEmpty()) {
                workloadAttributes.put("asserted", asserted.claims());
            }
            assertedCeiling = asserted.ceiling();
        }

        // 6. The authority the attestation carries (CAS §7): the binding's ceiling, narrowed by the asserted
        //    context's when there is one, and the request granted against it.
        RarModels models = rarModels();
        List<Map<String, Object>> ceiling = config.effectiveCeiling(binding);
        if (assertedCeiling != null) {
            ceiling = intersectCeilings(models, ceiling, assertedCeiling);
        }
        List<Map<String, Object>> granted = grant(models, request.requestedDetails, ceiling);

        // 6a. Resolve this instance's stable agent_id, if an AgentRegistry is available (Phase 2.1). Keyed
        //     on the resolved instance subject, not the raw evidence, so it stays stable across restarts
        //     and across re-attestation with a fresh instance key. No registry at all is back-compatible
        //     (no claim, issuance proceeds); a registry that IS available but fails is not — see
        //     resolveAgentId's own javadoc.
        Optional<String> agentId = resolveAgentId(config.issuer(), clientId, instance);

        // 6b. The evidence is acceptable beyond being valid - not longer-lived than this attester allows, one
        //     audience if required - and, every refusal above being past, it binds to this key and client. The
        //     first presenter wins; the same presenter may return; anyone else is refused and audited. Last,
        //     so a refused request never takes the binding: a presenter holding a WIA but not the key it
        //     names passes the key proof with a key of its own and fails at 4b, and must not hold the rightful
        //     key out by having bound first.
        long now = Instant.now().getEpochSecond();
        evidencePolicy().check(instance, now);
        bindEvidence(instance, request.instanceKey, clientId);

        // 7. Mint + sign with the attester key. The attester assigns the client_id (the attestation sub);
        //    the workload learns it only from the attestation it receives back.
        JwsSigner signer = attesterSigningKey().signerFor(config.signingKeyRef(), config.signingJwk());
        // The client's TTL, and never past the evidence: the attestation vouches for the instance no longer
        // than its platform does.
        long ttl = EvidencePolicy.effectiveTtlSeconds(config.ttlSeconds(), instance, now);
        String attestation = AttestationMinter.mint(config.issuer(), clientId, request.instanceKey,
                instance, workloadAttributes, granted, ttl, signer, agentId.orElse(null));

        LOGGER.info((Object) ("Issued client attestation: client_id=" + clientId
                + " format=" + instance.format() + " subject=" + instance.subject()
                + " evidence_sha256=" + instance.evidenceDigest() + " instance_jkt=" + thumbprintOf(request.instanceKey)
                + " ttl=" + ttl + "s"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("attestation", attestation);
        body.put("expires_in", ttl);
        return body;
    }

    /**
     * Binds the evidence to the instance key and client once the key proof and every other check have passed,
     * so a request refused by any of those checks never takes the binding. A conflict - the same evidence
     * already bound to another key or client - is refused with 401 {@code instance_attestation_bound} and
     * recorded as {@link #EVIDENCE_CONFLICT_EVENT} in the audit log, naming the evidence's digest and type, the
     * client, the key presented now and the key and client that hold the binding. Evidence with nothing to
     * digest (a format without a single token) is not bound. Residual risk, stated plainly: a thief who
     * presents the evidence first wins the binding and the rightful holder is the one refused. That is
     * detectable here, not preventable, until evidence is itself bound to the instance key.
     */
    private void bindEvidence(InstanceIdentity instance, Map<String, Object> instanceKey, String clientId)
            throws IssuanceException {
        if (instance.evidenceDigest() == null) {
            return;
        }
        String jkt = thumbprintOf(instanceKey);
        EvidenceBindingStore.Result bound = evidenceBindings().bind(instance.evidenceDigest(), jkt, clientId,
                instance.expEpochSeconds());
        switch (bound.binding()) {
            case BOUND:
                return;
            case STORE_UNAVAILABLE:
                throw IssuanceException.temporarilyUnavailable("the evidence binding store is unavailable");
            default:
                FederationEvents.event(EVIDENCE_CONFLICT_EVENT).failure("evidence_bound_elsewhere").subject(clientId)
                        .role("ATTESTER").audit()
                        .field("evidence_sha256", instance.evidenceDigest())
                        .field("evidence_type", instance.evidenceType())
                        .field("instance_subject", instance.subject())
                        .field("presented_jkt", jkt)
                        .field("bound_jkt", bound.holderJkt())
                        .field("bound_client", bound.holderClientId())
                        .description("the evidence is bound to " + bound.holderJkt() + " for " + bound.holderClientId()
                                + "; presented again by " + jkt + " for " + clientId)
                        .emit();
                throw IssuanceException.instanceAttestationBound(
                        "this evidence is already bound to a different instance key or client; present fresh evidence");
        }
    }

    /** The RFC 7638 thumbprint of a key that has just verified a signature, so it cannot lack one. */
    static String thumbprintOf(Map<String, Object> jwk) {
        try {
            return Jwks.thumbprint(jwk);
        } catch (Exception e) {
            throw new IllegalStateException("instance_key verified a proof but has no thumbprint", e);
        }
    }

    // ---- seams for tests / runtime defaults -------------------------------------------------------

    void setClientResolver(IssuanceClientResolver resolver) {
        this.clientResolver = resolver;
    }

    void setEvidencePolicy(EvidencePolicy policy) {
        this.evidencePolicy = policy;
    }

    void setEvidenceBindingStore(EvidenceBindingStore store) {
        this.evidenceBindings = store;
    }

    void setChallengeService(AttestationChallengeService service) {
        this.challengeService = service;
    }

    void setReplayCache(AttestationReplayCache cache) {
        this.replayCache = cache;
    }

    /** A test's proof validator, for a clock the test controls. */
    void setProofValidator(InstanceKeyProofValidator validator) {
        this.proofValidator = validator;
    }

    void setRarModels(RarModels models) {
        this.rarModels = models;
    }

    /**
     * The containment models: injected, loaded at {@code init}, or - for a caller that never ran {@code init} - this
     * classloader's, so a mint never proceeds without them.
     */
    RarModels rarModels() throws IssuanceException {
        RarModels local = this.rarModels;
        if (local != null) {
            return local;
        }
        try {
            return AttestationRarModels.get();
        } catch (RarModelException e) {
            throw IssuanceException.serverError("the RAR containment models could not be loaded: " + e.getMessage());
        }
    }

    /** The evidence policy: injected, else read from the environment on first use, so a bad value fails the first request and names itself. */
    synchronized EvidencePolicy evidencePolicy() throws IssuanceException {
        if (this.evidencePolicy == null) {
            try {
                this.evidencePolicy = EvidencePolicy.fromEnvironment();
            } catch (IllegalArgumentException e) {
                throw IssuanceException.serverError("the attester's evidence policy is misconfigured: " + e.getMessage());
            }
        }
        return this.evidencePolicy;
    }

    /** The evidence bindings: injected, else the shared store's {@code oidf:cas:evidence:*}. */
    EvidenceBindingStore evidenceBindings() {
        EvidenceBindingStore local = this.evidenceBindings;
        return local != null ? local : AttestationSupport.evidenceBindingStore();
    }

    /**
     * The challenges this endpoint consumes: injected, else the shared store's {@code oidf:cas:challenge:*}, which
     * {@link AttestationIssuanceChallengeServlet} issues into. The authorization server's challenges live in
     * {@code oidf:as:challenge:*} and are unknown here, so a proof carrying one is refused (CAS §4.1).
     */
    AttestationChallengeService challengeService() {
        AttestationChallengeService local = this.challengeService;
        return local != null ? local : AttestationSupport.challengeService(StoreNamespace.CAS);
    }

    /** The spent proof jtis: injected, else the shared store's {@code oidf:cas:jti:*}. */
    AttestationReplayCache replayCache() {
        AttestationReplayCache local = this.replayCache;
        return local != null ? local : AttestationSupport.replayCache(StoreNamespace.CAS);
    }

    void setAttesterSigningKey(AttesterSigningKey key) {
        this.attesterSigningKey = key;
    }

    void setChallengeRequired(boolean required) {
        this.challengeRequired = required;
    }

    void setCustomClaimsRequired(List<String> claims) {
        this.customClaimsRequired = List.copyOf(claims);
    }

    void setInstanceValidators(InstanceAttestationValidators validators) {
        this.instanceValidators = validators;
    }

    void setJwksCache(RemoteJwksCache cache) {
        this.jwksCache = cache;
    }

    /** Test/deployment seam: overrides the shared {@link AgentRegistrySupport} default (see below). */
    void setAgentRegistry(AgentRegistry registry) {
        this.agentRegistry = registry;
    }

    /**
     * Resolves this instance's stable {@code agent_id}. Prefers an explicitly injected registry (tests);
     * otherwise falls back to {@link AgentRegistrySupport}, the process-wide holder that keeps agent
     * identity consistent across classloaders — the same reason {@link AttestationSupport} exists for the
     * challenge/replay stores.
     *
     * <p>Two distinct outcomes, both deliberate: no registry available at all (neither injected nor
     * configured on the shared holder) is back-compatible — {@link Optional#empty()}, issuance proceeds
     * with no {@code agent_id} claim, exactly as before this method existed. A registry that IS available
     * but whose {@code resolveOrMint} itself fails is not back-compatible — once agent identity is opted
     * into, a broken registry must fail the request rather than silently issue an attestation with no
     * agent identity.
     *
     * @throws IssuanceException {@code server_error} if a registry is available but fails
     */
    private Optional<String> resolveAgentId(String iss, String clientId, InstanceIdentity instance)
            throws IssuanceException {
        AgentRegistry registry = this.agentRegistry;
        if (registry == null) {
            if (!AgentRegistrySupport.isConfigured()) {
                return Optional.empty();
            }
            registry = AgentRegistrySupport.registry();
        }
        try {
            return Optional.of(registry.resolveOrMint(iss, clientId, instance.format(), instance.subject()).agentId());
        } catch (AgentRegistryException e) {
            throw IssuanceException.serverError("could not resolve agent_id: " + e.getMessage());
        }
    }

    /** The active instance-attestation registry, lazily built from the environment. */
    InstanceAttestationValidators instanceValidators() {
        InstanceAttestationValidators local = this.instanceValidators;
        if (local == null) {
            synchronized (this) {
                if (this.instanceValidators == null) {
                    this.instanceValidators = defaultInstanceValidators();
                }
                local = this.instanceValidators;
            }
        }
        return local;
    }

    /**
     * The runtime default registry: every built-in evidence type, with the placeholder wallet validator
     * replaced by a wired one when wallet-provider trust is configured — federation-backed
     * ({@code OIDF_TRUST_CONTROLLER_HOST} + {@code OIDF_ATTESTER_OP_ISSUER}) in preference to a static
     * provider→JWKS map ({@code OIDF_WALLET_PROVIDER_JWKS}). Overridable so the lazy-init path is testable.
     */
    protected InstanceAttestationValidators defaultInstanceValidators() {
        InstanceAttestationValidators registry = InstanceAttestationValidators.defaults();
        InstanceAttestationValidator wallet = walletValidatorFromEnv();
        if (wallet != null) {
            registry = registry.with(wallet);
        }
        return registry;
    }

    /**
     * Builds the wallet (WIA) validator, preferring federation-backed wallet-provider trust over the static
     * map, or null when neither is configured (the placeholder stays, and any WIA is refused).
     */
    static InstanceAttestationValidator walletValidatorFromEnv() {
        InstanceAttestationValidator federation = federationWalletValidatorFromEnv();
        return federation != null ? federation : staticWalletValidatorFromEnv();
    }

    /**
     * Builds a wallet validator whose provider keys are resolved through the OpenID Federation trust chain
     * ({@link FederationWalletProviderKeyResolver}), mirroring the AS-side attester wiring. Enabled when a trust
     * controller is configured ({@code OIDF_FEDERATION_TRUST_CONTROLLER_HOST}, or the superseded
     * {@code OIDF_TRUST_CONTROLLER_HOST}) and the hosted attester's own entity id ({@code OIDF_ATTESTER_OP_ISSUER},
     * the relying party in the WIA trust chain) is set; returns null otherwise.
     *
     * <p>The anchors are the deployment's pinned set ({@link FederationRuntimeConfig#trustAnchors()}) - the same
     * ones every other federation check here uses - so the wallet path can no longer name an anchor of its own. A
     * trust controller without pinned keys throws here, naming the variable: a trust anchor's keys are configured
     * out of band (OpenID Federation 1.0 §4), not read from its .well-known over HTTPS. The registry is built on the
     * first issuance request, so that request fails closed, rather than yielding a validator that trusts whoever
     * answers at the host, or silently falling back to the static provider map.
     */
    static InstanceAttestationValidator federationWalletValidatorFromEnv() {
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        String opIssuer = processSettings().string("OIDF_ATTESTER_OP_ISSUER");
        if (!runtime.isTrustControllerConfigured() || opIssuer == null) {
            return null;
        }
        TrustChainValidator chainValidator = AttesterResolvers.federationValidator(runtime, null);
        AttesterKeyResolver resolver = new FederationWalletProviderKeyResolver(chainValidator, opIssuer);
        LOGGER.info((Object) ("Wallet instance attestation: federation-backed provider trust via "
                + runtime.trustControllerHost()));
        return new WalletInstanceAttestationValidator(resolver);
    }

    /**
     * Builds a wallet validator from {@code OIDF_WALLET_PROVIDER_JWKS} — a JSON object mapping each accepted
     * wallet-provider entity id to its JWKS — trusting those keys statically (dev / no-federation). Returns
     * null when unset or unparseable.
     */
    static InstanceAttestationValidator staticWalletValidatorFromEnv() {
        Map<String, Object> jwks = processSettings().jsonObject("OIDF_WALLET_PROVIDER_JWKS");
        if (jwks == null) {
            return null;
        }
        Map<String, List<JsonWebKey>> byProvider = new LinkedHashMap<>();
        jwks.forEach((provider, value) -> {
            if (value instanceof Map) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> jwksObj = (Map<String, Object>) value;
                    byProvider.put(provider, new JsonWebKeySet(JsonUtil.toJson(jwksObj)).getJsonWebKeys());
                } catch (Exception ignored) {
                    // skip a malformed provider entry
                }
            }
        });
        if (byProvider.isEmpty()) {
            return null;
        }
        LOGGER.info((Object) ("Wallet instance attestation: statically trusted providers " + byProvider.keySet()));
        return new WalletInstanceAttestationValidator(new StaticAttesterKeyResolver(byProvider));
    }

    void setAssertedContextResolvers(Map<String, AssertedContextResolver> resolvers) {
        this.assertedContextResolvers = resolvers;
    }

    /** The active {@link AssertedContextResolver} registry (by id), lazily built from the environment. */
    Map<String, AssertedContextResolver> assertedContextResolvers() {
        Map<String, AssertedContextResolver> local = this.assertedContextResolvers;
        if (local == null) {
            synchronized (this) {
                if (this.assertedContextResolvers == null) {
                    this.assertedContextResolvers = defaultAssertedContextResolvers();
                }
                local = this.assertedContextResolvers;
            }
        }
        return local;
    }

    /**
     * The runtime default: an Entra Agent ID directory resolver if {@code OIDF_ENTRA_AGENT_DIRECTORY} is
     * configured, else an empty registry (no client can opt into a resolver that isn't registered — such a
     * client's {@code attestation_asserted_context_resolver} then fails closed with {@code invalid_client},
     * never silently ignored). Overridable so the lazy-init path is testable.
     */
    protected Map<String, AssertedContextResolver> defaultAssertedContextResolvers() {
        Map<String, AssertedContextResolver> out = new LinkedHashMap<>();
        EntraDirectoryAssertedContextResolver entra = entraDirectoryResolverFromEnv();
        if (entra != null) {
            LOGGER.info((Object) ("Asserted-context resolver registered: " + entra.id()));
            out.put(entra.id(), entra);
        }
        return out;
    }

    /**
     * Builds the Entra Agent ID directory resolver from {@code OIDF_ENTRA_AGENT_DIRECTORY} (a JSON object
     * mapping asserted oid → directory entry). Returns null when unset or unparseable — a deployment with
     * no directory configured simply has no client able to opt into {@link EntraDirectoryAssertedContextResolver#ID}.
     */
    static EntraDirectoryAssertedContextResolver entraDirectoryResolverFromEnv() {
        Map<String, Object> directory = processSettings().jsonObject("OIDF_ENTRA_AGENT_DIRECTORY");
        return directory == null ? null : EntraDirectoryAssertedContextResolver.fromJson(JsonUtil.toJson(directory));
    }

    /**
     * The authority the attestation carries (CAS §7): {@code effective = requested ∩ ceiling(instance)}.
     *
     * <ul>
     *   <li>Rule 2: "An empty or absent {@code authorization_details} request means the instance asks for its
     *       <b>full ceiling</b>; the CAS issues the ceiling of the matched binding."</li>
     *   <li>Otherwise {@code authorize(requested, ceiling, INHERIT)}: each requested detail fitted to the first
     *       ceiling entry of its type that contains it, with every field that entry constrains and the request
     *       leaves out filled from it, so the attestation never carries a detail wider than its ceiling. The
     *       library checks its own grant against the ceiling before returning it (rule 1: "The issued
     *       {@code authorization_details} MUST be a subset of the applicable ceiling").</li>
     *   <li>Rule 3, with the {@code "reject"} this attester advertises as its {@code narrowing_behavior}: "A
     *       request exceeding the ceiling is handled per the advertised narrowing_behavior: "reject" →
     *       access_denied".</li>
     * </ul>
     *
     * @throws IssuanceException {@code access_denied} for a request outside the ceiling; {@code invalid_request}
     *                           for one the model refuses (malformed, too large, an undeclared field, an
     *                           unmodelled type, or one of this repository's markers, which an issuance request
     *                           has no business carrying)
     */
    static List<Map<String, Object>> grant(RarModels models, List<Map<String, Object>> requested,
                                           List<Map<String, Object>> ceiling) throws IssuanceException {
        try {
            return requested.isEmpty()
                    ? models.fullCeiling(ceiling)
                    : models.authorize(requested, ceiling, Omission.INHERIT);
        } catch (RarModelException e) {
            throw mapEntitlementError(e);
        }
    }

    /**
     * An asserted-context ceiling folded into the evidenced one: the model's meet ({@code intersect}), the
     * largest details within both, pairwise by type - so the asserted context narrows the evidenced ceiling and
     * never extends it. This used to keep a base entry only when the asserted ceiling contained it whole, which
     * dropped an entry the asserted ceiling only partly allowed (EMEA and APAC against EMEA) rather than narrowing
     * it, and compared five array fields. Plan item X-B10 (Phase 5) rebuilds the asserted context on this meet.
     *
     * @throws IssuanceException {@code server_error} when the two cannot be combined - a ceiling the model
     *                           refuses, or a meet past the size limit - since both come from this attester's own
     *                           configuration, not from the request
     */
    static List<Map<String, Object>> intersectCeilings(RarModels models, List<Map<String, Object>> base,
                                                       List<Map<String, Object>> narrowing) throws IssuanceException {
        try {
            return models.intersect(base, narrowing);
        } catch (RarModelException e) {
            throw IssuanceException.serverError(
                    "the asserted context's ceiling cannot be combined with the binding's: " + e.getMessage());
        }
    }

    RemoteJwksCache jwksCache() {
        return this.jwksCache;
    }

    void setWorkloadIntrospector(WorkloadIntrospector introspector) {
        this.workloadIntrospector = introspector;
    }

    /**
     * The workload introspector — a SPIRE selector lookup if {@code oidf.attester.spire.entries.url}
     * (env {@code OIDF_ATTESTER_SPIRE_ENTRIES_URL}) is set, else a no-op. Lazily initialized so tests can
     * inject one and the runtime path needs no live SPIRE by default.
     */
    WorkloadIntrospector workloadIntrospector() {
        WorkloadIntrospector local = this.workloadIntrospector;
        if (local == null) {
            synchronized (this) {
                if (this.workloadIntrospector == null) {
                    this.workloadIntrospector = defaultWorkloadIntrospector();
                }
                local = this.workloadIntrospector;
            }
        }
        return local;
    }

    protected WorkloadIntrospector defaultWorkloadIntrospector() {
        URI url = processSettings().url("OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        if (url != null) {
            LOGGER.info((Object) ("Workload introspection via SPIRE entries endpoint: " + url));
            return new SpireSelectorIntrospector(url.toString());
        }
        return WorkloadIntrospector.none();
    }

    /** The attester's private mapping: evidence identity → the client it is bound to. */
    private static final class Match {
        final String clientId;
        final AttestationIssuanceConfig config;
        final InstanceIdentity instance;
        final SpiffeBinding binding;

        Match(String clientId, AttestationIssuanceConfig config, InstanceIdentity instance, SpiffeBinding binding) {
            this.clientId = clientId;
            this.config = config;
            this.instance = instance;
            this.binding = binding;
        }
    }

    /**
     * Reverse-maps a workload's evidence onto the client it is bound to. Tries each attestation client's
     * trust config: the client whose bundle cryptographically verifies the evidence AND whose bindings
     * contain the resolved SPIFFE ID is the match. A SPIFFE ID bound to two clients is a configuration
     * error and is rejected rather than resolved arbitrarily.
     */
    private Match resolveByEvidence(String evidence, String declaredFormat) throws IssuanceException {
        Attempt first = this.matchEvidence(evidence, declaredFormat);
        if (first.match != null) {
            return first.match;
        }
        // Evidence no indexed client accepts: the index may predate the client, so it is read again - at most once in
        // ClientBindingIndex.MISS_REFRESH_INTERVAL, whoever asks - and the evidence matched once more.
        if (!refreshAfterMiss(clientResolver())) {
            throw first.miss;
        }
        Attempt second = this.matchEvidence(evidence, declaredFormat);
        if (second.match != null) {
            return second.match;
        }
        throw second.miss;
    }

    /** Asks {@code resolver}, or each plugin of a chain, to read its clients again after a miss; whether any did. */
    static boolean refreshAfterMiss(IssuanceClientResolver resolver) {
        if (resolver instanceof ChainClientResolver) {
            boolean any = false;
            for (IssuanceClientResolver plugin : ((ChainClientResolver) resolver).plugins()) {
                any |= plugin.refreshAfterMiss();
            }
            return any;
        }
        return resolver.refreshAfterMiss();
    }

    /** One look for the client the evidence is bound to: a match, or the miss to answer when none is found. */
    private static final class Attempt {
        final Match match;
        final IssuanceException miss;

        Attempt(Match match, IssuanceException miss) {
            this.match = match;
            this.miss = miss;
        }
    }

    private Attempt matchEvidence(String evidence, String declaredFormat) throws IssuanceException {
        List<AttesterClient> clients = clientResolver().attestationClients();
        if (clients.isEmpty()) {
            return new Attempt(null, IssuanceException.invalidClient("no attestation clients are configured"));
        }
        InstanceAttestationValidators registry = instanceValidators();
        Match match = null;
        boolean anyValidated = false;
        String validatedFormat = null;
        IssuanceException deferredServerError = null;
        for (AttesterClient candidate : clients) {
            AttestationIssuanceConfig config = candidate.config();
            InstanceAttestationValidator validator = registry.find(config.evidenceType()).orElse(null);
            if (validator == null) {
                // The client names an evidence type this attester does not implement — a config fault on
                // that client alone, not a reason to reject evidence another client may accept.
                LOGGER.warn((Object) ("client " + candidate.clientId() + " declares unsupported evidence type: "
                        + config.evidenceType()));
                continue;
            }
            // An explicitly declared format narrows the search; a sniffed one never does, so a
            // mis-sniffed token can still find its client.
            if (declaredFormat != null && !declaredFormat.equals(validator.format())) {
                continue;
            }
            List<JsonWebKey> bundleKeys;
            InstanceIdentity instance;
            try {
                bundleKeys = config.bundleUrl() != null ? jwksCache().get(config.bundleUrl()) : config.bundleKeys();
                instance = validator.validate(evidence, bundleKeys, config);
            } catch (IssuanceException e) {
                // A 5xx (e.g. the trust bundle could not be fetched) is an attester-side fault, not
                // "bad evidence" — remember it and surface it only if nothing else matches.
                if (e.status() >= 500) {
                    deferredServerError = e;
                }
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug((Object) ("evidence rejected by client " + candidate.clientId()
                            + " [" + config.evidenceType() + "]: " + e.error() + " " + e.getMessage()));
                }
                // Otherwise this client's trust config simply does not accept the evidence — try the next.
                continue;
            }
            anyValidated = true;
            validatedFormat = instance.format();
            SpiffeBinding binding = config.bindingFor(instance.subject()).orElse(null);
            if (binding == null) {
                continue;
            }
            if (match != null) {
                throw IssuanceException.invalidClient(
                        "instance identity is bound to more than one client: " + instance.subject());
            }
            match = new Match(candidate.clientId(), config, instance, binding);
        }
        if (match != null) {
            return new Attempt(match, null);
        }
        if (anyValidated) {
            // A SPIFFE identity keeps the long-standing, documented error code; other formats get the
            // format-neutral one.
            String message = "evidence identity is not registered with any client";
            return new Attempt(null, SpiffeInstanceAttestationValidator.FORMAT.equals(validatedFormat)
                    ? IssuanceException.spiffeIdNotAuthorized(message)
                    : IssuanceException.instanceNotAuthorized(message));
        }
        if (deferredServerError != null) {
            // An attester-side fault (a trust bundle that could not be fetched), not a client the index lacks.
            throw deferredServerError;
        }
        return new Attempt(null, IssuanceException.invalidSvid("no attester client accepts this evidence"
                + (declaredFormat != null ? " for format '" + declaredFormat + "'" : "")
                + " (looks like format '" + InstanceAttestationValidators.sniff(evidence) + "')"));
    }

    IssuanceClientResolver clientResolver() {
        IssuanceClientResolver local = this.clientResolver;
        if (local == null) {
            synchronized (this) {
                if (this.clientResolver == null) {
                    this.clientResolver = defaultClientResolver();
                }
                local = this.clientResolver;
            }
        }
        return local;
    }

    /**
     * The runtime default resolver, {@link AttesterResolvers#fromEnvironment()}: an OpenID Federation entity
     * when one is named, a Client ID Metadata Document from {@code oidf.attester.cimd.url} only under
     * {@code OIDF_DEPLOYMENT_PROFILE=development} (plan item M-1), and PingFederate's management store.
     * Overridable so tests bypass them.
     */
    protected IssuanceClientResolver defaultClientResolver() {
        return AttesterResolvers.fromEnvironment();
    }

    private AttesterSigningKey attesterSigningKey() {
        AttesterSigningKey local = this.attesterSigningKey;
        if (local == null) {
            synchronized (this) {
                if (this.attesterSigningKey == null) {
                    this.attesterSigningKey = AttesterSigningKey.fromEnvironment();
                }
                local = this.attesterSigningKey;
            }
        }
        return local;
    }

    /**
     * A refusal of the request's details, as the CAS §4.6 error: {@code access_denied} (403) for one outside the
     * ceiling, {@code invalid_request} (400) for one the model cannot compare. The model's message names the
     * detail and the field, never the value.
     */
    static IssuanceException mapEntitlementError(RarModelException e) {
        if (e.reason() == RarModelException.Reason.EXCEEDS_CEILING) {
            return IssuanceException.accessDenied(e.getMessage());
        }
        return IssuanceException.invalidRequest("authorization_details: " + e.getMessage());
    }

    // ---- request parsing --------------------------------------------------------------------------

    private static IssuanceRequest parseRequest(byte[] raw) throws IssuanceException {
        Map<String, Object> json;
        try {
            json = JsonUtil.parseJson(new String(raw, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw IssuanceException.invalidRequest("request body is not valid JSON");
        }
        // Phase 2.3: agent_id is minted by the attester's own AgentRegistry after evidence validation —
        // it is never something a caller supplies. Reject a request that tries, rather than silently
        // ignoring the field: a caller sending it is either an integration bug worth surfacing now, or an
        // attempt to influence a claim that must only ever come from the attester's own minting.
        if (json.containsKey("agent_id")) {
            throw IssuanceException.invalidRequest("agent_id is minted by the attester; it is not an accepted request field");
        }

        IssuanceRequest request = new IssuanceRequest();
        request.clientId = asString(json.get("client_id"));
        request.instanceKey = asObject(json.get("instance_key"));
        // 'svid' is the original field name; 'instance_attestation' is the format-neutral alias a
        // non-SPIFFE client (a wallet presenting a WIA) reads more naturally.
        request.svid = firstNonBlank(asString(json.get("instance_attestation")), asString(json.get("svid")));
        request.format = asString(json.get("instance_attestation_format"));
        request.proof = asString(json.get("proof"));
        request.requestedDetails = asObjectList(json.get("authorization_details"));
        request.assertedContext = assertedContextValue(json.get("asserted_context"));
        return request;
    }

    /**
     * Extracts the {@code value} from an optional {@code asserted_context} request field
     * ({@code {"type": "...", "value": "<discriminator>"}}) — a caller-supplied, UNVERIFIED discriminator
     * (e.g. an Entra Agent ID {@code oid}) for a client-opted-in {@link AssertedContextResolver}. Absent or
     * malformed is null, not an error: a client with no resolver configured never looks at this field.
     */
    private static String assertedContextValue(Object raw) {
        if (!(raw instanceof Map)) {
            return null;
        }
        Object value = ((Map<?, ?>) raw).get("value");
        return value == null ? null : String.valueOf(value);
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asObjectList(Object value) throws IssuanceException {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List)) {
            throw IssuanceException.invalidRequest("authorization_details must be a JSON array");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof Map)) {
                throw IssuanceException.invalidRequest("each authorization_details entry must be a JSON object");
            }
            Map<String, Object> entry = (Map<String, Object>) item;
            // Phase 2.3: the same firewall as the top-level agent_id field, applied to a caller's
            // requested authorization_details — a caller must not be able to smuggle an agent_id through
            // an entitlement entry either.
            if (entry.containsKey("agent_id")) {
                throw IssuanceException.invalidRequest(
                        "agent_id is minted by the attester; it is not an accepted authorization_details field");
            }
            out.add(entry);
        }
        return out;
    }

    private static Map<String, Object> error(String code, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        if (description != null) {
            body.put("error_description", description);
        }
        return body;
    }

    private static void write(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String firstNonBlank(String a, String b) {
        return !isBlank(a) ? a : b;
    }

    /** Parsed issuance request. */
    static final class IssuanceRequest {
        String clientId;
        Map<String, Object> instanceKey;
        String svid;
        /** Optional explicit {@code instance_attestation_format} ("spiffe" | "wallet" | …); null to infer. */
        String format;
        String proof;
        List<Map<String, Object>> requestedDetails = List.of();
        /** Optional caller-supplied, UNVERIFIED discriminator for an opted-in {@link AssertedContextResolver}. */
        String assertedContext;
    }
}
