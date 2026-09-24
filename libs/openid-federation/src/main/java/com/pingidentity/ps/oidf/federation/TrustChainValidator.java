package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.jose.VerificationPolicy;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * Establishes trust in an Entity by OpenID Federation 1.0 §10: collects the statements linking it to one of
 * the configured Trust Anchors (starting from any it was handed), validates the resulting Trust Chain (§3.2,
 * §10.2), then resolves the subject's metadata - its immediate superior's {@code metadata} first, then every
 * Subordinate Statement's {@code constraints} (§6.2), then the chain's {@code metadata_policy} (§6.1.4).
 *
 * <h2>Where trust comes from</h2>
 * Each anchor's keys are configured out of band ({@link TrustAnchor}, §4). The statement an anchor issues
 * about the entity below it is verified with those keys and nothing fetched; every statement below is verified
 * with the keys the statement above it asserts (§10.2: "ES[j] ... validates with a public key in
 * ES[j+1]["jwks"]"). An Intermediate's own Entity Configuration, used on the way to find its superiors and
 * its fetch endpoint, must be signed by a key its superior asserts for it. Nothing an anchor serves over HTTPS
 * is ever a source of trust.
 *
 * <h2>Finding a chain</h2>
 * A depth-first search over {@code authority_hints} (§10.1), statements the caller presented used before any
 * fetch. At each Entity the configured anchors are tried first and at most
 * {@link ValidatorOptions#maxAuthorityHints()} hints are followed; an Entity already on the path is never
 * revisited ("If a loop is detected, the authority hint that led to it MUST NOT be used"). Every candidate
 * route that reaches an anchor is validated in full; a route that fails does not stop the search, so a
 * subject in two federations resolves through whichever of them validates (§10.3), and the first one that
 * validates is used - anchors-first ordering makes that the shortest. One budget of
 * {@link ValidatorOptions#maxFetches()} bounds the network work of the whole validation.
 *
 * <h2>What comes back</h2>
 * {@link TrustChainValidationResult#trustChain()} is the chain in §4 shape - the subject's Entity
 * Configuration, the Subordinate Statements up to the anchor's, and the anchor's Entity Configuration when it
 * was presented or requested - with {@code expiresAt} the least {@code exp} in it (§10.4). Every refusal is a
 * {@link TrustChainValidationException} saying which check failed on which statement.
 */
public final class TrustChainValidator {
    private static final Log LOGGER = LogFactory.getLog(TrustChainValidator.class);

    /** The fetch budget of a validator built without {@link ValidatorOptions}. */
    static final int DEFAULT_MAX_FETCHES_PER_VALIDATION = ValidatorOptions.DEFAULT_MAX_FETCHES;

    /** A presented or cached statement this close to its {@code exp} is fetched afresh first. */
    private static final long REFRESH_WINDOW_SECONDS = 300L;

    /** The most Subordinate Statements one route may hold (§18.1 - a caller-supplied chain names the depth). */
    static final int MAX_ROUTE_STATEMENTS = 16;

    /**
     * The most steps (a statement added to a route) one validation's search may take. Fetches are budgeted
     * separately; this bounds the work presented statements cause, which costs no fetch at all.
     */
    static final int MAX_SEARCH_STEPS = 128;

    private final TrustControllerGateway gateway;
    private final TrustAnchorSet anchors;
    private final Set<String> acceptedSigningAlgorithms;
    private final ValidatorOptions options;
    private final VerificationPolicy statementPolicy;

    public TrustChainValidator(TrustControllerGateway gateway, TrustAnchor trustAnchor) {
        this(gateway, trustAnchor, Set.of());
    }

    public TrustChainValidator(TrustControllerGateway gateway, TrustAnchor trustAnchor, Set<String> acceptedSigningAlgorithms) {
        this(gateway, TrustAnchorSet.of(Objects.requireNonNull(trustAnchor, "trustAnchor")), acceptedSigningAlgorithms,
                ValidatorOptions.defaults());
    }

    /**
     * @param anchors                   the Trust Anchors to validate against, in preference order; at least one
     * @param acceptedSigningAlgorithms the JWS algorithms a statement may use; empty accepts any asymmetric one
     * @param options                   limits and choices; {@code null} for {@link ValidatorOptions#defaults()}
     */
    public TrustChainValidator(TrustControllerGateway gateway, TrustAnchorSet anchors, Set<String> acceptedSigningAlgorithms,
                               ValidatorOptions options) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.anchors = Objects.requireNonNull(anchors, "anchors");
        if (anchors.isEmpty()) {
            throw new IllegalArgumentException("a trust chain validator needs at least one trust anchor");
        }
        this.acceptedSigningAlgorithms = acceptedSigningAlgorithms != null ? Set.copyOf(acceptedSigningAlgorithms) : Set.of();
        this.options = options != null ? options : ValidatorOptions.defaults();
        this.statementPolicy = VerificationPolicy.entityStatement()
                .withClock(this.options.clock())
                .withClockSkewSeconds(this.options.clockSkewSeconds());
        // §10.2 verifies an anchor's statements with its configured keys; the gateway reads the anchors'
        // Entity Configurations to find their fetch endpoints, so it has to know them. Done here so no
        // caller can forget it.
        gateway.bindTrustAnchors(anchors, this.acceptedSigningAlgorithms);
    }

    public TrustAnchorSet trustAnchors() {
        return this.anchors;
    }

    public ValidatorOptions options() {
        return this.options;
    }

    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer) throws Exception {
        return this.validate(trustChain, expectedRpIssuer, expectedOpIssuer, -1L, -1L, -1L);
    }

    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer,
                                               long maxLeafNodeTime, long maxTrustAnchorNodeTime) throws Exception {
        return this.validate(trustChain, expectedRpIssuer, expectedOpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, -1L);
    }

    /**
     * @param trustChain                   statements the caller was handed, in any order; may be empty
     * @param expectedRpIssuer             the Trust Chain subject
     * @param expectedOpIssuer             the OP establishing trust (see {@link ValidationRequest#opIssuer()})
     * @param maxLeafNodeTime              see {@link ValidationRequest#maxLeafAgeSeconds()}
     * @param maxTrustAnchorNodeTime       see {@link ValidationRequest#maxAnchorAgeSeconds()}
     * @param maxTrustChainEntryAgeSeconds see {@link ValidationRequest#maxPresentedEntryAgeSeconds()}
     */
    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer,
                                               long maxLeafNodeTime, long maxTrustAnchorNodeTime,
                                               long maxTrustChainEntryAgeSeconds) throws Exception {
        Claims.requireNonBlank(expectedRpIssuer, "expectedRpIssuer");
        Claims.requireNonBlank(expectedOpIssuer, "expectedOpIssuer");
        return this.validate(ValidationRequest.forSubject(expectedRpIssuer)
                .presentedChain(trustChain)
                .opIssuer(expectedOpIssuer)
                .maxLeafAgeSeconds(maxLeafNodeTime)
                .maxAnchorAgeSeconds(maxTrustAnchorNodeTime)
                .maxPresentedEntryAgeSeconds(maxTrustChainEntryAgeSeconds)
                .build());
    }

    /** Discovery from the subject's own Entity Configuration, as the resolve endpoint does (§8.3). */
    public TrustChainValidationResult resolve(String subject, List<String> requestedAnchors) {
        return this.validate(ValidationRequest.forSubject(subject).requestedAnchors(requestedAnchors).build());
    }

    /**
     * @throws TrustChainValidationException when no chain to a usable anchor validates, naming the check that
     *                                       failed on the first route that reached an anchor, or why none did
     */
    public TrustChainValidationResult validate(ValidationRequest request) {
        Objects.requireNonNull(request, "request");
        Claims.requireNonBlank(request.subject(), "subject");
        SubordinateStatementCache.PendingWrites pendingWrites = this.gateway.newPendingWrites();
        FetchBudget budget = new FetchBudget(this.options.maxFetches());
        TrustChainValidationResult result = new Run(request, budget, pendingWrites).execute();
        // Statements fetched on the way are cached only once the chain they belong to validated, so a
        // refused chain leaves nothing behind for the next caller.
        pendingWrites.commit();
        return result;
    }

    /**
     * The leaf of a presented chain: the self-signed statement with {@code authority_hints} whose subject
     * issues nothing else in the chain. Selection only - nothing is verified here.
     */
    public static JwtClaims selectLeafEntityStatement(List<String> trustChain) throws Exception {
        String sub;
        String iss;
        if (trustChain == null || trustChain.isEmpty()) {
            throw new IllegalArgumentException("trust_chain is required");
        }
        ArrayList<JwtClaims> parsed = new ArrayList<JwtClaims>(trustChain.size());
        HashSet<String> subordinateIssuers = new HashSet<String>();
        for (String jwt : trustChain) {
            JwtClaims claims = JwtCodec.parseUnverifiedClaims(jwt);
            iss = Claims.requireNonBlank(claims.getIssuer(), "iss");
            sub = Claims.requireNonBlank(claims.getSubject(), "sub");
            parsed.add(claims);
            if (iss.equals(sub)) continue;
            subordinateIssuers.add(iss);
        }
        JwtClaims found = null;
        for (JwtClaims claims : parsed) {
            List<String> hints;
            iss = claims.getIssuer();
            if (!iss.equals(sub = claims.getSubject()) || !claims.hasClaim("authority_hints") || (hints = claims.getStringListClaimValue("authority_hints")) == null || hints.isEmpty() || subordinateIssuers.contains(sub)) continue;
            if (found != null) {
                throw new IllegalArgumentException("Trust chain contains multiple candidate leaf JWTs (self-signed with authority_hints and not acting as a subordinate issuer)");
            }
            found = claims;
        }
        if (found == null) {
            throw new IllegalArgumentException("Leaf JWT not found in trust chain (expected self-signed JWT with authority_hints that does not issue subordinate statements in the chain)");
        }
        return found;
    }

    // ---- one validation --------------------------------------------------------------------------------

    /** The state of one validation: what was presented, what has been fetched, the budget, the failures. */
    private final class Run {
        private final ValidationRequest request;
        private final FetchBudget budget;
        private final SubordinateStatementCache.PendingWrites pending;
        private final List<Statement> presented = new ArrayList<>();
        private final List<TrustAnchor> candidates;
        private TrustChainValidationException firstRouteFailure;
        private boolean transportFailure;
        private int steps;
        private int attempts;

        Run(ValidationRequest request, FetchBudget budget, SubordinateStatementCache.PendingWrites pending) {
            this.request = request;
            this.budget = budget;
            this.pending = pending;
            try {
                this.candidates = TrustChainValidator.this.anchors.select(request.requestedAnchors());
            } catch (FederationException e) {
                throw new TrustChainValidationException(Kind.ANCHOR, null, request.subject(), e.description());
            }
        }

        TrustChainValidationResult execute() {
            this.indexPresented();
            String subject = this.request.subject();
            Statement subjectConfiguration = this.presentedConfiguration(subject, true);
            if (subjectConfiguration == null) {
                if (!EntityId.isValid(subject)) {
                    throw new TrustChainValidationException(Kind.SYNTAX, null, subject, "the subject is not an Entity Identifier"
                            + " (federation identifiers are https URLs), so it is not fetched");
                }
                subjectConfiguration = this.fetchConfiguration(subject);
                if (subjectConfiguration == null) {
                    throw new TrustChainValidationException(this.transportFailure ? Kind.TRANSPORT : Kind.SUBJECT, subject, subject,
                            "the subject's Entity Configuration was not presented and could not be fetched");
                }
            }
            subjectConfiguration = this.fresh(subjectConfiguration);
            Route route = new Route(subjectConfiguration);
            TrustAnchor subjectAnchor = this.candidate(subject);
            TrustChainValidationResult result = null;
            if (subjectAnchor != null) {
                // The subject is itself a configured anchor: the chain is its Entity Configuration alone.
                route.anchor = subjectAnchor;
                result = this.attempt(route);
            }
            if (result == null) {
                Set<String> visited = new HashSet<>();
                visited.add(EntityId.comparable(subject));
                result = this.extend(route, subjectConfiguration, subject, visited);
            }
            if (result != null) {
                return result;
            }
            if (this.firstRouteFailure != null) {
                throw this.firstRouteFailure;
            }
            throw new TrustChainValidationException(this.transportFailure ? Kind.TRANSPORT : Kind.ROUTE, null, subject,
                    "no authority_hint leads from " + subject + " to a configured trust anchor " + this.anchorIds());
        }

        private List<String> anchorIds() {
            List<String> ids = new ArrayList<>();
            for (TrustAnchor anchor : this.candidates) {
                ids.add(anchor.entityId());
            }
            return ids;
        }

        /**
         * Grows {@code route} upwards from {@code currentSubject}. Returns the result of the first route that
         * reaches an anchor and validates, or null.
         *
         * <p>§3.2 requires a Subordinate Statement's issuer to be one of its subject's {@code authority_hints}.
         * Whenever the subject's configuration is known - always for the Trust Chain subject - only statements
         * by its hints are used; a presented statement by anyone else is passed over, not refused, since the
         * caller may simply have sent more than was needed.
         */
        private TrustChainValidationResult extend(Route route, Statement currentConfiguration, String currentSubject,
                                                  Set<String> visited) {
            if (route.statements.size() > MAX_ROUTE_STATEMENTS) {
                return null;
            }
            Set<String> tried = new HashSet<>();
            // Statements the caller presented about this Entity first: they cost no fetch, and a chain in §4
            // shape carries no Intermediate Entity Configurations, only the statements about them.
            for (Statement statement : this.presentedAbout(currentSubject)) {
                String superior = statement.issuer;
                if (!tried.add(EntityId.comparable(superior))
                        || currentConfiguration != null && !currentConfiguration.hasAuthorityHint(superior)) {
                    continue;
                }
                TrustChainValidationResult result = this.step(route, this.fresh(statement), superior, visited);
                if (result != null) {
                    return result;
                }
            }
            if (currentConfiguration == null) {
                // Only an Intermediate's configuration can be missing here (the subject's never is), and step()
                // already looked for a presented one.
                currentConfiguration = this.fetchConfiguration(currentSubject);
                if (currentConfiguration == null) {
                    return null;
                }
                route.configurations.put(EntityId.comparable(currentSubject), currentConfiguration);
            }
            for (String superior : this.orderedHints(currentConfiguration.authorityHints())) {
                if (!tried.add(EntityId.comparable(superior))) {
                    continue;
                }
                Statement statement = this.fetchSubordinateStatement(superior, currentSubject);
                if (statement == null) {
                    continue;
                }
                TrustChainValidationResult result = this.step(route, statement, superior, visited);
                if (result != null) {
                    return result;
                }
            }
            return null;
        }

        /** Adds {@code statement} (issued by {@code superior}) to the route and either validates or climbs. */
        private TrustChainValidationResult step(Route route, Statement statement, String superior, Set<String> visited) {
            String key = EntityId.comparable(superior);
            if (visited.contains(key)) {
                // §10.1: "If a loop is detected, the authority hint that led to it MUST NOT be used."
                return null;
            }
            if (++this.steps > MAX_SEARCH_STEPS) {
                throw new TrustChainValidationException(Kind.BUDGET, superior, statement.subject, "trust chain resolution took"
                        + " more than " + MAX_SEARCH_STEPS + " steps; refusing to keep searching");
            }
            route.statements.add(statement);
            try {
                TrustAnchor anchor = this.candidate(superior);
                if (anchor != null) {
                    route.anchor = anchor;
                    TrustChainValidationResult result = this.attempt(route);
                    route.anchor = null;
                    return result;
                }
                Statement configuration = this.presentedConfiguration(superior, false);
                if (configuration != null) {
                    configuration = this.fresh(configuration);
                    route.configurations.put(key, configuration);
                }
                visited.add(key);
                try {
                    return this.extend(route, configuration, superior, visited);
                } finally {
                    visited.remove(key);
                    route.configurations.remove(key);
                }
            } finally {
                route.statements.remove(route.statements.size() - 1);
            }
        }

        /**
         * Validates a route that reached an anchor. A failure is remembered and the search goes on - until
         * {@link ValidatorOptions#maxRouteAttempts()} routes have failed, when the search stops there and the
         * first failure is reported, before anything more is fetched.
         */
        private TrustChainValidationResult attempt(Route route) {
            this.attempts++;
            try {
                return new Resolution(this, route).resolve();
            } catch (TrustChainValidationException e) {
                LOGGER.debug("Trust chain route for " + this.request.subject() + " via " + route.anchor.entityId()
                        + " refused: " + e.kind().code() + " - " + e.getMessage());
                if (e.kind() == Kind.BUDGET) {
                    throw e;
                }
                if (this.firstRouteFailure == null) {
                    this.firstRouteFailure = e;
                }
                if (this.attempts >= TrustChainValidator.this.options.maxRouteAttempts()) {
                    throw this.firstRouteFailure;
                }
                return null;
            }
        }

        // ---- statements: presented, fetched, refreshed ----------------------------------------------

        private void indexPresented() {
            long maxAge = this.request.maxPresentedEntryAgeSeconds();
            long now = TrustChainValidator.this.options.clock().instant().getEpochSecond();
            for (String jwt : this.request.presentedChain()) {
                Statement statement = Statement.parse(jwt);
                if (maxAge > 0L && now - statement.iat > maxAge) {
                    LOGGER.debug("Dropping a presented statement issued " + (now - statement.iat) + "s ago, over the "
                            + maxAge + "s limit (sub=" + statement.subject + ")");
                    continue;
                }
                this.presented.add(statement);
            }
        }

        /**
         * The presented Entity Configuration of {@code entityId}, or null. Two of them are ambiguous: for the
         * subject that refuses the chain, for anything else it leaves the choice to discovery.
         */
        private Statement presentedConfiguration(String entityId, boolean required) {
            Statement match = null;
            for (Statement statement : this.presented) {
                if (statement.isConfiguration() && EntityId.same(statement.subject, entityId)) {
                    if (match != null) {
                        if (required) {
                            throw new TrustChainValidationException(Kind.SYNTAX, entityId, entityId,
                                    "the presented chain is ambiguous: it holds more than one Entity Configuration of " + entityId);
                        }
                        return null;
                    }
                    match = statement;
                }
            }
            return match;
        }

        private List<Statement> presentedAbout(String subject) {
            List<Statement> out = new ArrayList<>();
            for (Statement statement : this.presented) {
                if (!statement.isConfiguration() && EntityId.same(statement.subject, subject)) {
                    out.add(statement);
                }
            }
            return out;
        }

        private long maxAgeFor(String entityId) {
            return EntityId.same(entityId, this.request.subject()) ? this.request.maxLeafAgeSeconds()
                    : this.request.maxAnchorAgeSeconds();
        }

        private Statement fetchConfiguration(String entityId) {
            if (!EntityId.isValid(entityId)) {
                return null;
            }
            this.budget.spend("entity configuration of " + entityId);
            String jwt;
            try {
                jwt = TrustChainValidator.this.gateway.fetchEntityStatement(entityId, this.maxAgeFor(entityId), this.pending);
            } catch (Exception e) {
                this.noteFetchFailure("entity configuration of " + entityId, e);
                return null;
            }
            Statement statement = this.parseFetched(jwt, "entity configuration of " + entityId);
            if (statement == null || !statement.isConfiguration() || !EntityId.same(statement.subject, entityId)) {
                LOGGER.debug("The document fetched as the Entity Configuration of " + entityId + " is not one");
                return null;
            }
            return statement;
        }

        private Statement fetchSubordinateStatement(String issuer, String subject) {
            if (!EntityId.isValid(issuer)) {
                return null;
            }
            this.budget.spend("subordinate statement " + issuer + " -> " + subject);
            String jwt;
            try {
                jwt = TrustChainValidator.this.gateway.fetchSubordinateStatement(issuer, subject, this.maxAgeFor(subject), this.pending);
            } catch (Exception e) {
                this.noteFetchFailure("subordinate statement " + issuer + " -> " + subject, e);
                return null;
            }
            Statement statement = this.parseFetched(jwt, "subordinate statement " + issuer + " -> " + subject);
            // Issued by the authority and about the subject, it is a Subordinate Statement: the two differ.
            if (statement == null || !EntityId.same(statement.issuer, issuer) || !EntityId.same(statement.subject, subject)) {
                LOGGER.debug("The statement fetched from " + issuer + " about " + subject + " is not a Subordinate Statement about it");
                return null;
            }
            return statement;
        }

        private Statement parseFetched(String jwt, String what) {
            if (jwt == null || jwt.isBlank()) {
                LOGGER.debug("Empty response for " + what);
                return null;
            }
            try {
                return Statement.parse(jwt);
            } catch (TrustChainValidationException e) {
                LOGGER.debug("Unparseable response for " + what + ": " + e.getMessage());
                return null;
            }
        }

        private void noteFetchFailure(String what, Exception e) {
            if (e instanceof IOException || e.getCause() instanceof IOException) {
                this.transportFailure = true;
            }
            LOGGER.debug("Could not fetch " + what + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        /**
         * A presented statement close to expiry, or older than the caller allows, is fetched afresh; if that
         * fails the original is kept and validation decides.
         */
        private Statement fresh(Statement statement) {
            long now = TrustChainValidator.this.options.clock().instant().getEpochSecond();
            long maxAge = this.maxAgeFor(statement.subject);
            boolean expiring = statement.exp == 0L || statement.exp - now <= REFRESH_WINDOW_SECONDS;
            boolean tooOld = maxAge > 0L && now - statement.iat > maxAge;
            if (!expiring && !tooOld) {
                return statement;
            }
            if (!this.budget.trySpend()) {
                return statement;
            }
            String what = (statement.isConfiguration() ? "entity configuration of " : "subordinate statement "
                    + statement.issuer + " -> ") + statement.subject;
            try {
                String jwt = statement.isConfiguration()
                        ? TrustChainValidator.this.gateway.fetchEntityStatement(statement.subject, maxAge, this.pending)
                        : TrustChainValidator.this.gateway.fetchSubordinateStatement(statement.issuer, statement.subject, maxAge, this.pending);
                Statement refreshed = this.parseFetched(jwt, what);
                if (refreshed != null && EntityId.same(refreshed.issuer, statement.issuer)
                        && EntityId.same(refreshed.subject, statement.subject)) {
                    return refreshed;
                }
            } catch (Exception e) {
                this.noteFetchFailure(what, e);
            }
            LOGGER.debug("Could not refresh the " + what + "; validating the one presented");
            return statement;
        }

        private TrustAnchor candidate(String entityId) {
            for (TrustAnchor anchor : this.candidates) {
                if (EntityId.same(anchor.entityId(), entityId)) {
                    return anchor;
                }
            }
            return null;
        }

        /** The candidate anchors first, in preference order, then the other hints; at most the configured number. */
        private List<String> orderedHints(List<String> hints) {
            List<String> ordered = new ArrayList<>();
            for (TrustAnchor anchor : this.candidates) {
                for (String hint : hints) {
                    if (EntityId.same(hint, anchor.entityId()) && !ordered.contains(hint)) {
                        ordered.add(hint);
                    }
                }
            }
            for (String hint : hints) {
                if (!ordered.contains(hint)) {
                    ordered.add(hint);
                }
            }
            int cap = TrustChainValidator.this.options.maxAuthorityHints();
            return ordered.size() > cap ? ordered.subList(0, cap) : ordered;
        }
    }

    // ---- validating and resolving one route ----------------------------------------------------------

    /** One route from the subject to an anchor, validated (§3.2, §10.2) and resolved (§6). */
    private final class Resolution {
        private final Run run;
        private final Route route;
        private final TrustAnchor anchor;
        private final List<Statement> statements;
        private final JwtClaims[] verified;

        Resolution(Run run, Route route) {
            this.run = run;
            this.route = route;
            this.anchor = route.anchor;
            this.statements = List.copyOf(route.statements);
            this.verified = new JwtClaims[this.statements.size()];
        }

        TrustChainValidationResult resolve() {
            String subject = this.run.request.subject();
            int top = this.statements.size() - 1;
            for (int j = 0; j <= top; j++) {
                Statement statement = this.statements.get(j);
                EntityStatementChecks.check(statement.header, statement.claims, j == 0 ? this.run.request.opIssuer() : null);
            }
            // §10.2 / §4: the anchor's own statement - its Subordinate Statement about the entity below it, or,
            // when the subject is the anchor, its Entity Configuration - with the configured keys only.
            this.verified[top] = this.verifyWithAnchor(this.statements.get(top));
            for (int j = top - 1; j >= 0; j--) {
                Statement statement = this.statements.get(j);
                Map<String, Object> assertedKeys = this.statements.get(j + 1).jwks();
                this.verified[j] = this.verifyInline(statement, assertedKeys, statement.issuer);
                if (j >= 1) {
                    this.checkIntermediate(j, assertedKeys);
                }
            }
            Statement subjectConfiguration = this.statements.get(0);
            // §10.2: ES[0] also validates with a key in its own jwks.
            this.verifyInline(subjectConfiguration, subjectConfiguration.jwks(), subject);
            List<String> chain = new ArrayList<>();
            long expiresAt = Long.MAX_VALUE;
            for (int j = 0; j <= top; j++) {
                chain.add(this.statements.get(j).jwt);
                expiresAt = Math.min(expiresAt, this.statements.get(j).exp);
            }
            Statement anchorConfiguration = top >= 1 ? this.anchorConfiguration() : null;
            if (anchorConfiguration != null) {
                chain.add(anchorConfiguration.jwt);
                expiresAt = Math.min(expiresAt, anchorConfiguration.exp);
            }

            Set<String> removedByConstraint = new LinkedHashSet<>();
            Set<String> policed = new LinkedHashSet<>();
            Map<String, Object> metadata = this.resolveMetadata(removedByConstraint, policed);
            TrustChainValidationResult peer = this.peerChain();
            return new TrustChainValidationResult.Builder()
                    .trustAnchorIssuer(this.anchor.entityId())
                    .leafSubject(this.verified[0].getClaimValueAsString("sub"))
                    .resolvedMetadata(metadata)
                    .trustChain(chain)
                    .presentedTrustChain(this.run.request.presentedChain())
                    .leafEntityStatement(this.verified[0])
                    .policedEntityTypes(policed)
                    .entityTypesRemovedByConstraint(removedByConstraint)
                    .expEpochSeconds(expiresAt)
                    .fetchesUsed(this.run.budget.used())
                    .peerChain(peer)
                    .build();
        }

        /** An Intermediate's Entity Configuration, when the route has it, is signed by a key its superior asserts. */
        private void checkIntermediate(int j, Map<String, Object> assertedKeys) {
            Statement statementByIntermediate = this.statements.get(j);
            String intermediate = statementByIntermediate.issuer;
            Statement configuration = this.route.configurations.get(EntityId.comparable(intermediate));
            if (configuration == null) {
                return;
            }
            EntityStatementChecks.check(configuration.header, configuration.claims, null);
            this.verifyInline(configuration, assertedKeys, intermediate);
            // §3.2: the key the Intermediate signed its statement with is one of its own. (That its superior is
            // one of its authority_hints the search already made sure of: with its configuration in hand, only
            // hints are followed.)
            String kid = String.valueOf(statementByIntermediate.header.get("kid"));
            boolean own = false;
            for (JsonWebKey key : Jwks.parseFederationKeySet(configuration.jwks())) {
                own |= kid.equals(key.getKeyId());
            }
            if (!own) {
                throw new TrustChainValidationException(Kind.KID, intermediate, statementByIntermediate.subject,
                        "the statement's kid is not a key in its issuer's own Entity Configuration (§3.2)");
            }
        }

        /**
         * A statement the anchor issued, against its configured keys. Only ever called with one whose
         * {@code iss} names the anchor (the search ends a route only there), in whichever of the two spellings
         * {@link EntityId#same} allows, so that spelling is the issuer expected.
         */
        private JwtClaims verifyWithAnchor(Statement statement) {
            List<JsonWebKey> keys;
            try {
                keys = this.anchor.keys();
            } catch (IllegalArgumentException e) {
                throw new TrustChainValidationException(Kind.ANCHOR, statement.issuer, statement.subject,
                        "the trust anchor's own keys are not usable: " + e.getMessage(), e);
            }
            try {
                return JwtCodec.verifyAgainstKeys(statement.jwt, keys, statement.issuer,
                        TrustChainValidator.this.acceptedSigningAlgorithms, TrustChainValidator.this.statementPolicy);
            } catch (JwtVerificationException e) {
                throw refusal(e, statement, "does not verify against the configured trust anchor keys");
            }
        }

        private JwtClaims verifyInline(Statement statement, Map<String, Object> jwks, String expectedIssuer) {
            try {
                return JwtCodec.verifyAgainstInlineJwks(statement.jwt, jwks, expectedIssuer,
                        TrustChainValidator.this.acceptedSigningAlgorithms, TrustChainValidator.this.statementPolicy);
            } catch (JwtVerificationException e) {
                throw refusal(e, statement, "does not verify against the keys its superior asserts");
            }
        }

        /**
         * The anchor's Entity Configuration, ES[i] (§4): the presented one, else - when the caller asked for it
         * - fetched once. Either way it must verify against the configured keys (§10.2). One that cannot be
         * fetched is left out, which §4 allows; the chain's trust never depended on it.
         */
        private Statement anchorConfiguration() {
            Statement presentedOne = this.run.presentedConfiguration(this.anchor.entityId(), false);
            Statement configuration = presentedOne != null ? this.run.fresh(presentedOne) : null;
            if (configuration == null && this.run.request.includeAnchorConfiguration() && this.run.budget.trySpend()) {
                try {
                    String jwt = TrustChainValidator.this.gateway.anchorConfiguration(this.anchor,
                            TrustChainValidator.this.acceptedSigningAlgorithms, this.run.pending);
                    configuration = this.run.parseFetched(jwt, "entity configuration of " + this.anchor.entityId());
                } catch (Exception e) {
                    this.run.noteFetchFailure("entity configuration of " + this.anchor.entityId(), e);
                }
            }
            if (configuration == null) {
                return null;
            }
            if (!configuration.isConfiguration() || !EntityId.same(configuration.subject, this.anchor.entityId())) {
                return null;
            }
            EntityStatementChecks.check(configuration.header, configuration.claims, null);
            this.verifyWithAnchor(configuration);
            return configuration;
        }

        /**
         * §6.1.4.2 and §6.2: the subject's metadata with its immediate superior's {@code metadata} applied,
         * then the Entity Types every {@code allowed_entity_types} leaves, then the chain's policy.
         */
        private Map<String, Object> resolveMetadata(Set<String> removedByConstraint, Set<String> policed) {
            int top = this.statements.size() - 1;
            Map<String, Object> metadata = new LinkedHashMap<>(Claims.optionalMap(this.verified[0], "metadata"));
            if (top >= 1) {
                // §3.1.1: the superior's metadata "applies only to those Entity Types that are present in the
                // subject's Entity Configuration" and overrides identically named parameters.
                // EntityStatementChecks has made every metadata value an object.
                Map<String, Object> superior = Claims.optionalMap(this.verified[1], "metadata");
                for (String type : superior.keySet()) {
                    if (metadata.containsKey(type)) {
                        Map<String, Object> merged = new LinkedHashMap<>(Claims.optionalNestedMap(metadata, type));
                        merged.putAll(Claims.optionalNestedMap(superior, type));
                        metadata.put(type, merged);
                    }
                }
            }
            Set<String> allowed = null;
            for (int j = 1; j <= top; j++) {
                Statement statement = this.statements.get(j);
                Constraints constraints = Constraints.parse(this.verified[j].getClaimValue("constraints"));
                String failure = constraints.checkPathLength(j);
                if (failure == null) {
                    List<String> below = new ArrayList<>();
                    for (int k = 1; k <= j; k++) {
                        below.add(this.statements.get(k).subject);
                    }
                    failure = constraints.checkNames(below);
                }
                if (failure != null) {
                    throw new TrustChainValidationException(Kind.CONSTRAINT, statement.issuer, statement.subject,
                            "constraints: " + failure + " (§6.2)");
                }
                if (constraints.allowedEntityTypes() != null) {
                    if (allowed == null) {
                        allowed = new LinkedHashSet<>(constraints.allowedEntityTypes());
                    } else {
                        allowed.retainAll(constraints.allowedEntityTypes());
                    }
                }
            }
            metadata = Constraints.filterEntityTypes(metadata, allowed, removedByConstraint);
            return this.applyPolicy(metadata, policed);
        }

        /**
         * §6.1.4.1 and §6.1.4.2: every Entity Type's policy is merged down the chain, anchor first - a merge
         * error anywhere refuses the chain - and applied to the metadata of the types the subject has.
         */
        private Map<String, Object> applyPolicy(Map<String, Object> metadata, Set<String> policed) {
            int top = this.statements.size() - 1;
            Set<String> types = new LinkedHashSet<>();
            for (int j = 1; j <= top; j++) {
                types.addAll(Claims.optionalMap(this.verified[j], "metadata_policy").keySet());
            }
            Map<String, Object> resolved = new LinkedHashMap<>(metadata);
            String subject = this.statements.get(0).subject;
            for (String type : types) {
                MetadataPolicy composed = MetadataPolicy.empty();
                for (int j = top; j >= 1; j--) {
                    Map<String, Object> policy = Claims.optionalNestedMap(Claims.optionalMap(this.verified[j], "metadata_policy"), type);
                    try {
                        composed = composed.composeWith(MetadataPolicy.parse(policy, null));
                    } catch (MetadataPolicy.PolicyException e) {
                        // The statement whose policy could not be merged into those above it.
                        throw new TrustChainValidationException(Kind.POLICY, this.statements.get(j).issuer, subject,
                                "metadata policy for " + type + ": " + e.getMessage(), e);
                    }
                }
                if (composed.isEmpty() || !metadata.containsKey(type)) {
                    continue;
                }
                policed.add(type);
                try {
                    resolved.put(type, composed.apply(Claims.optionalNestedMap(metadata, type)));
                } catch (MetadataPolicy.PolicyException e) {
                    // The subject's metadata breaks the chain's policy; named after the statement about it.
                    throw new TrustChainValidationException(Kind.POLICY, this.statements.get(1).issuer, subject,
                            "metadata for " + type + " does not satisfy the chain's policy: " + e.getMessage(), e);
                }
            }
            return resolved;
        }

        /** §4.4: a {@code peer_trust_chain} about the OP, validated as a chain ending at the same anchor. */
        private TrustChainValidationResult peerChain() {
            List<String> peer = this.run.request.peerTrustChain();
            if (peer.isEmpty()) {
                return null;
            }
            String op = this.run.request.opIssuer();
            if (op == null || op.isBlank()) {
                throw new TrustChainValidationException(Kind.PEER_CHAIN, null, null, "a peer_trust_chain needs the OP it is about");
            }
            ValidationRequest peerRequest = ValidationRequest.forSubject(op)
                    .presentedChain(peer)
                    .requestedAnchors(TrustChainValidator.this.options.requirePeerChainSameAnchor()
                            ? List.of(this.anchor.entityId()) : this.run.request.requestedAnchors())
                    .build();
            try {
                return new Run(peerRequest, this.run.budget, this.run.pending).execute();
            } catch (TrustChainValidationException e) {
                if (e.kind() == Kind.BUDGET) {
                    // The budget is the whole validation's; spending it on the peer chain ends everything.
                    throw e;
                }
                throw new TrustChainValidationException(Kind.PEER_CHAIN, e.issuer(), op,
                        "the peer_trust_chain does not validate" + (TrustChainValidator.this.options.requirePeerChainSameAnchor()
                                ? " to the same trust anchor" : "") + ": " + e.getMessage(), e);
            }
        }
    }

    private static TrustChainValidationException refusal(JwtVerificationException e, Statement statement, String what) {
        // Claims, issuer and subject are checked before a key is tried (EntityStatementChecks, and the route
        // itself), so what is left for the verifier to refuse is time, algorithm, key, type or signature.
        Kind kind = switch (e.reason()) {
            case EXPIRED -> Kind.EXP;
            case NOT_YET_VALID -> Kind.IAT;
            case ALGORITHM -> Kind.ALG;
            case KEY -> Kind.KID;
            case TYP -> Kind.TYP;
            default -> Kind.SIGNATURE;
        };
        String description = kind == Kind.SIGNATURE || kind == Kind.KID ? what + ": " + e.getMessage() : e.getMessage();
        return new TrustChainValidationException(kind, statement.issuer, statement.subject, description, e);
    }

    // ---- data -------------------------------------------------------------------------------------

    /** A candidate route: the subject's Entity Configuration, then Subordinate Statements up to an anchor's. */
    private static final class Route {
        private final List<Statement> statements = new ArrayList<>();
        /** Intermediates' Entity Configurations the search used, by {@link EntityId#comparable} identifier. */
        private final Map<String, Statement> configurations = new HashMap<>();
        private TrustAnchor anchor;

        Route(Statement subjectConfiguration) {
            this.statements.add(subjectConfiguration);
        }
    }

    /** A parsed, unverified Entity Statement. */
    private static final class Statement {
        private final String jwt;
        private final Map<String, Object> header;
        private final JwtClaims claims;
        private final String issuer;
        private final String subject;
        private final long iat;
        private final long exp;

        private Statement(String jwt, Map<String, Object> header, JwtClaims claims, String issuer, String subject, long iat, long exp) {
            this.jwt = jwt;
            this.header = header;
            this.claims = claims;
            this.issuer = issuer;
            this.subject = subject;
            this.iat = iat;
            this.exp = exp;
        }

        static Statement parse(String jwt) {
            try {
                Map<String, Object> header = JwtCodec.getJwtHeaders(jwt);
                JwtClaims claims = JwtCodec.parseUnverifiedClaims(jwt);
                String iss = Claims.requireNonBlank(claims.getIssuer(), "iss");
                String sub = Claims.requireNonBlank(claims.getSubject(), "sub");
                long iat = claims.getIssuedAt() == null ? 0L : claims.getIssuedAt().getValue();
                long exp = claims.getExpirationTime() == null ? 0L : claims.getExpirationTime().getValue();
                return new Statement(jwt, header, claims, iss, sub, iat, exp);
            } catch (MalformedClaimException | IllegalArgumentException e) {
                throw new TrustChainValidationException(Kind.SYNTAX, null, null,
                        "a statement in the trust chain is not a well-formed Entity Statement");
            } catch (Exception e) {
                throw new TrustChainValidationException(Kind.SYNTAX, null, null,
                        "a statement in the trust chain is not a well-formed JWT");
            }
        }

        boolean isConfiguration() {
            return EntityId.same(this.issuer, this.subject);
        }

        List<String> authorityHints() {
            Object hints = this.claims.getClaimValue("authority_hints");
            List<String> out = new ArrayList<>();
            if (hints instanceof List<?> list) {
                for (Object hint : list) {
                    if (hint instanceof String s) {
                        out.add(s);
                    }
                }
            }
            return out;
        }

        boolean hasAuthorityHint(String entityId) {
            for (String hint : this.authorityHints()) {
                if (EntityId.same(hint, entityId)) {
                    return true;
                }
            }
            return false;
        }

        Map<String, Object> jwks() {
            return Claims.optionalMap(this.claims, "jwks");
        }
    }

    /**
     * How many live fetches one validation may make. A chain is caller-supplied: its leaf names hints, each
     * hint can name more, and every hint is tried - a branching search over attacker-chosen URLs. Without a
     * ceiling one unauthenticated request could become dozens of outbound GETs, each holding a request thread
     * for up to the fetch timeout. Cached statements cost budget too: the point is to bound the work.
     */
    static final class FetchBudget {
        private final int max;
        private int used;

        FetchBudget(int max) {
            this.max = max;
        }

        void spend(String what) {
            if (++this.used > this.max) {
                throw new TrustChainValidationException(Kind.BUDGET, null, null, "trust chain resolution exceeded its fetch"
                        + " budget of " + this.max + " (last: " + what + "); refusing to keep resolving");
            }
        }

        /** Spends one fetch if any is left; refreshing a statement is never worth failing a validation over. */
        boolean trySpend() {
            if (this.used >= this.max) {
                return false;
            }
            this.used++;
            return true;
        }

        int used() {
            return this.used;
        }
    }
}
