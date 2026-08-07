/*
 * Attestation issuance endpoint: a SPIFFE workload exchanges its JWT-SVID for a Client Attestation.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttesterClient;
import com.pingidentity.ps.oidf.common.AttestationMinter;
import com.pingidentity.ps.oidf.common.AttestationSupport;
import com.pingidentity.ps.oidf.common.AttesterSigningKey;
import com.pingidentity.ps.oidf.common.AttesterKeyResolver;
import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationException;
import com.pingidentity.ps.oidf.common.FederationWalletProviderKeyResolver;
import com.pingidentity.ps.oidf.common.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.common.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.common.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.common.InstanceIdentity;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.JdkHttpGetClient;
import com.pingidentity.ps.oidf.common.Jwks;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.common.TrustChainValidator;
import com.pingidentity.ps.oidf.common.WalletInstanceAttestationValidator;
import com.pingidentity.ps.oidf.common.IssuanceException;
import com.pingidentity.ps.oidf.common.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.PfMgmtClientStore;
import com.pingidentity.ps.oidf.common.RarEntitlement;
import com.pingidentity.ps.oidf.common.RemoteJwksCache;
import com.pingidentity.ps.oidf.common.SpiffeBinding;
import com.pingidentity.ps.oidf.common.SpiffeInstanceAttestationValidator;
import com.pingidentity.ps.oidf.common.SpireSelectorIntrospector;
import com.pingidentity.ps.oidf.common.WorkloadIntrospector;
import com.pingidentity.ps.oidf.agent.AgentRegistry;
import com.pingidentity.ps.oidf.agent.AgentRegistryException;
import com.pingidentity.ps.oidf.agent.AgentRegistrySupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
 * failure a JSON body {@code {"error":..,"error_description":..}} with a stable code and 4xx/5xx status.
 */
@WebServlet(urlPatterns = {"/federation/attestation"})
public class AttestationIssuanceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(AttestationIssuanceServlet.class);
    private static final long PROOF_REPLAY_TTL_SECONDS = ClientAttestationConfig.DEFAULT_POP_MAX_AGE_SECONDS;

    private volatile IssuanceClientResolver clientResolver;
    private volatile AttesterSigningKey attesterSigningKey;
    private volatile InstanceAttestationValidators instanceValidators;
    private volatile RemoteJwksCache jwksCache = new RemoteJwksCache();
    private volatile InstanceKeyProofValidator proofValidator = new InstanceKeyProofValidator();
    private volatile WorkloadIntrospector workloadIntrospector;
    private volatile AgentRegistry agentRegistry;
    private boolean challengeRequired;
    private volatile List<String> customClaimsRequired = List.of();

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.challengeRequired = Boolean.parseBoolean(config.getInitParameter("challengeRequired"));
        this.customClaimsRequired = customClaimsFrom(config.getInitParameter("customClaimsRequired"),
                "oidf.attestation.custom.claims.required", "OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED");
        String baoUrl = config.getInitParameter("openBaoUrl");
        String baoToken = config.getInitParameter("openBaoToken");
        if (baoUrl != null && baoToken != null) {
            this.attesterSigningKey = new AttesterSigningKey(baoUrl, baoToken);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");
        try {
            IssuanceRequest request = parseRequest(req);
            Map<String, Object> body = issue(request);
            write(resp, 200, body);
        } catch (IssuanceException e) {
            if (e.status() >= 500) {
                LOGGER.warn((Object) ("Attestation issuance failed: " + e.error() + " - " + e.getMessage()), e);
            }
            write(resp, e.status(), error(e.error(), e.getMessage()));
        }
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
            if (!AttestationSupport.challengeService().consume(proof.challenge())) {
                throw IssuanceException.invalidInstanceProof("challenge is unknown, expired, or already used");
            }
        } else if (this.challengeRequired) {
            throw IssuanceException.invalidInstanceProof("a server-issued challenge is required");
        }
        if (!AttestationSupport.replayCache().firstSeen(clientId, proof.jti(), PROOF_REPLAY_TTL_SECONDS)) {
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

        // 6. Resolve the granted entitlement against the effective ceiling, then apply any
        //    selector-conditioned downscoping the policy requires.
        List<Map<String, Object>> ceiling = config.effectiveCeiling(binding);
        List<Map<String, Object>> granted;
        if (!request.requestedDetails.isEmpty()) {
            try {
                granted = RarEntitlement.authorize(request.requestedDetails, ceiling);
            } catch (ClientAttestationException e) {
                throw mapEntitlementError(e);
            }
        } else {
            granted = ceiling;
        }

        // 6a. Resolve this instance's stable agent_id, if an AgentRegistry is available (Phase 2.1). Keyed
        //     on the resolved instance subject, not the raw evidence, so it stays stable across restarts
        //     and across re-attestation with a fresh instance key. No registry at all is back-compatible
        //     (no claim, issuance proceeds); a registry that IS available but fails is not — see
        //     resolveAgentId's own javadoc.
        Optional<String> agentId = resolveAgentId(config.issuer(), clientId, instance);

        // 7. Mint + sign with the attester key. The attester assigns the client_id (the attestation sub);
        //    the workload learns it only from the attestation it receives back.
        JwsSigner signer = attesterSigningKey().signerFor(config.signingKeyRef(), config.signingJwk());
        String attestation = AttestationMinter.mint(config.issuer(), clientId, request.instanceKey,
                instance, workloadAttributes, granted, config.ttlSeconds(), signer, agentId.orElse(null));

        LOGGER.info((Object) ("Issued client attestation: client_id=" + clientId
                + " format=" + instance.format() + " subject=" + instance.subject()
                + " ttl=" + config.ttlSeconds() + "s"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("attestation", attestation);
        body.put("expires_in", config.ttlSeconds());
        return body;
    }

    // ---- seams for tests / runtime defaults -------------------------------------------------------

    void setClientResolver(IssuanceClientResolver resolver) {
        this.clientResolver = resolver;
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
     * ({@link FederationWalletProviderKeyResolver}), mirroring the AS-side attester wiring. Enabled when the
     * trust controller host ({@code OIDF_TRUST_CONTROLLER_HOST}) and the hosted attester's own entity id
     * ({@code OIDF_ATTESTER_OP_ISSUER}, the relying party in the WIA trust chain) are set; returns null
     * otherwise. {@code OIDF_TRUST_CONTROLLER_IGNORE_SSL} relaxes TLS for a dev trust controller.
     */
    static InstanceAttestationValidator federationWalletValidatorFromEnv() {
        String trustControllerHost = env("oidf.trust.controller.host", "OIDF_TRUST_CONTROLLER_HOST");
        String opIssuer = env("oidf.attester.op.issuer", "OIDF_ATTESTER_OP_ISSUER");
        if (trustControllerHost == null || opIssuer == null) {
            return null;
        }
        boolean ignoreSsl = Boolean.parseBoolean(
                String.valueOf(env("oidf.trust.controller.ignore.ssl", "OIDF_TRUST_CONTROLLER_IGNORE_SSL")));
        TrustChainValidator chainValidator = new TrustChainValidator(
                new HttpTrustControllerGateway(new JdkHttpGetClient(ignoreSsl), trustControllerHost),
                trustControllerHost);
        AttesterKeyResolver resolver = new FederationWalletProviderKeyResolver(chainValidator, opIssuer);
        LOGGER.info((Object) ("Wallet instance attestation: federation-backed provider trust via "
                + trustControllerHost));
        return new WalletInstanceAttestationValidator(resolver);
    }

    /**
     * Builds a wallet validator from {@code OIDF_WALLET_PROVIDER_JWKS} — a JSON object mapping each accepted
     * wallet-provider entity id to its JWKS — trusting those keys statically (dev / no-federation). Returns
     * null when unset or unparseable.
     */
    static InstanceAttestationValidator staticWalletValidatorFromEnv() {
        String jwks = env("oidf.wallet.provider.jwks", "OIDF_WALLET_PROVIDER_JWKS");
        if (jwks == null) {
            return null;
        }
        Map<String, List<JsonWebKey>> byProvider = new LinkedHashMap<>();
        try {
            JsonUtil.parseJson(jwks).forEach((provider, value) -> {
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
        } catch (Exception e) {
            return null;
        }
        if (byProvider.isEmpty()) {
            return null;
        }
        LOGGER.info((Object) ("Wallet instance attestation: statically trusted providers " + byProvider.keySet()));
        return new WalletInstanceAttestationValidator(new StaticAttesterKeyResolver(byProvider));
    }

    /** A system property, falling back to an environment variable; null when neither is set. */
    static String env(String property, String envVar) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }

    /**
     * A comma-separated claim-name list from a servlet init-param, else the environment (sys-prop /
     * env var); empty when neither is set. Shared with the discovery metadata servlet so the
     * advertised {@code custom_claims_required} and the enforced set come from one configuration.
     */
    static List<String> customClaimsFrom(String initParam, String sysProp, String envVar) {
        String csv = (initParam != null && !initParam.isBlank()) ? initParam : env(sysProp, envVar);
        if (csv == null) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String token : csv.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return List.copyOf(out);
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
        String url = System.getProperty("oidf.attester.spire.entries.url");
        if (url == null || url.isBlank()) {
            url = System.getenv("OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        }
        if (url != null && !url.isBlank()) {
            LOGGER.info((Object) ("Workload introspection via SPIRE entries endpoint: " + url));
            return new SpireSelectorIntrospector(url.trim());
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
        List<AttesterClient> clients = clientResolver().attestationClients();
        if (clients.isEmpty()) {
            throw IssuanceException.invalidClient("no attestation clients are configured");
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
            return match;
        }
        if (anyValidated) {
            // A SPIFFE identity keeps the long-standing, documented error code; other formats get the
            // format-neutral one.
            String message = "evidence identity is not registered with any client";
            throw SpiffeInstanceAttestationValidator.FORMAT.equals(validatedFormat)
                    ? IssuanceException.spiffeIdNotAuthorized(message)
                    : IssuanceException.instanceNotAuthorized(message);
        }
        if (deferredServerError != null) {
            throw deferredServerError;
        }
        throw IssuanceException.invalidSvid("no attester client accepts this evidence"
                + (declaredFormat != null ? " for format '" + declaredFormat + "'" : "")
                + " (looks like format '" + InstanceAttestationValidators.sniff(evidence) + "')");
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
     * The runtime default resolver. If the system property {@code oidf.attester.cimd.url} is set, the
     * attester's SPIFFE-ID → client mapping is read from that Client ID Metadata Document; otherwise it
     * reads clients from PingFederate's management store. Overridable so tests bypass both.
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

    private static IssuanceException mapEntitlementError(ClientAttestationException e) {
        if (ClientAttestationException.ACCESS_DENIED.equals(e.error())) {
            return IssuanceException.accessDenied(e.getMessage());
        }
        return IssuanceException.invalidRequest(e.getMessage());
    }

    // ---- request parsing --------------------------------------------------------------------------

    private static IssuanceRequest parseRequest(HttpServletRequest req) throws IssuanceException {
        Map<String, Object> json;
        try {
            byte[] raw = req.getInputStream().readAllBytes();
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
        return request;
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
    }
}
