package com.pingidentity.ps.oidf.federation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.JwtCodec;

/**
 * Validates an OpenID Federation trust chain against a configured known trust anchor. Given a
 * (possibly partial) chain plus the expected RP and OP issuers, it locates the leaf, walks
 * {@code authority_hints} to the anchor (fetching and refreshing statements via the gateway as
 * needed), verifies each statement's signature against its issuer's JWKS, and returns the
 * validated leaf metadata as a {@link TrustChainValidationResult}.
 */
public final class TrustChainValidator {
    private static final Log LOGGER = LogFactory.getLog(TrustChainValidator.class);
    private final TrustControllerGateway gateway;
    private final String knownTrustAnchor;
    private final Set<String> acceptedSigningAlgorithms;

    public TrustChainValidator(TrustControllerGateway gateway, String knownTrustAnchor) {
        this(gateway, knownTrustAnchor, Set.of());
    }

    public TrustChainValidator(TrustControllerGateway gateway, String knownTrustAnchor, Set<String> acceptedSigningAlgorithms) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.knownTrustAnchor = Claims.requireNonBlank(knownTrustAnchor, "knownTrustAnchor");
        this.acceptedSigningAlgorithms = acceptedSigningAlgorithms != null ? Set.copyOf(acceptedSigningAlgorithms) : Set.of();
    }

    private long applicableMaxAge(String entitySubject, String expectedRpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime) {
        return Objects.equals(entitySubject, expectedRpIssuer) ? maxLeafNodeTime : maxTrustAnchorNodeTime;
    }

    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer) throws Exception {
        return this.validate(trustChain, expectedRpIssuer, expectedOpIssuer, -1L, -1L, -1L);
    }

    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime) throws Exception {
        return this.validate(trustChain, expectedRpIssuer, expectedOpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, -1L);
    }

    public TrustChainValidationResult validate(List<String> trustChain, String expectedRpIssuer, String expectedOpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime, long maxTrustChainEntryAgeSeconds) throws Exception {
        List<String> authorityHints;
        Claims.requireNonBlank(expectedRpIssuer, "expectedRpIssuer");
        Claims.requireNonBlank(expectedOpIssuer, "expectedOpIssuer");
        trustChain = filterStaleChainEntries(trustChain, maxTrustChainEntryAgeSeconds);
        SubordinateStatementCache.PendingWrites pendingWrites = this.gateway.newPendingWrites();
        FetchBudget budget = new FetchBudget(DEFAULT_MAX_FETCHES_PER_VALIDATION);
        LinkedHashMap<String, List<ChainEntry>> entriesBySubject = new LinkedHashMap<String, List<ChainEntry>>();
        for (String jwt : trustChain) {
            ChainEntry entry = new ChainEntry(jwt, JwtCodec.parseUnverifiedClaims(jwt));
            entriesBySubject.computeIfAbsent(entry.subject, ignored -> new ArrayList()).add(entry);
        }
        ChainEntry leafEntry = selectSelfSignedEntry(entriesBySubject.get(expectedRpIssuer), expectedRpIssuer, "Leaf JWT");
        if (leafEntry == null) {
            // Only now would we fetch a caller-named identifier. OpenID Federation entity identifiers
            // are https URLs (§1.2); refusing anything else here means a chain naming
            // "file:///..." or "http://169.254.169.254/..." is rejected before a socket is opened,
            // rather than relying solely on the outbound policy further down.
            requireFetchableEntityId(expectedRpIssuer);
            leafEntry = this.tryFetchSelfSignedEntry(expectedRpIssuer, maxLeafNodeTime, pendingWrites, budget);
            if (leafEntry == null) {
                throw new IllegalArgumentException("Leaf JWT not found in trust_chain and could not be fetched from " + expectedRpIssuer + "/.well-known/openid-federation (expected self-statement with sub=iss=" + expectedRpIssuer + ")");
            }
            entriesBySubject.computeIfAbsent(leafEntry.subject, ignored -> new ArrayList()).add(leafEntry);
        }
        if ((authorityHints = leafEntry.getAuthorityHints()) == null || authorityHints.isEmpty()) {
            throw new IllegalArgumentException("Leaf JWT does not contain authority_hints claim");
        }
        List<ChainEntry> orderedChainEntries = null;
        String trustAnchorIssuer = null;
        // Try the configured anchor's own hint first. Only a route that reaches knownTrustAnchor can
        // ever succeed, so any other hint is at best wasted work and at worst an attacker-chosen URL
        // this validator would fetch on the way to failing. Ordering costs nothing and means the
        // common case never touches the others.
        for (String hint : anchorFirst(authorityHints)) {
            List<ChainEntry> route = this.tryRoute(entriesBySubject, leafEntry, hint, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, pendingWrites, budget);
            if (route == null) continue;
            orderedChainEntries = route;
            trustAnchorIssuer = this.knownTrustAnchor;
            break;
        }
        if (orderedChainEntries == null) {
            throw new IllegalArgumentException("No authority_hint from the leaf leads to the configured known trust anchor: " + this.knownTrustAnchor);
        }
        JwtClaims verifiedLeaf = null;
        // The verified claims of every entry above the leaf (index >= 1), leaf-to-anchor order —
        // these are the statements that may carry a metadata_policy CONSTRAINING the leaf (an
        // entry's own metadata_policy constrains what is below it in the chain, never itself, so
        // index 0 — the leaf's own Entity Configuration — is never a source of policy here).
        JwtClaims[] verifiedByIndex = new JwtClaims[orderedChainEntries.size()];
        ArrayList<String> orderedChain = new ArrayList<String>(orderedChainEntries.size());
        int i = 0;
        while (i < orderedChainEntries.size()) {
            ChainEntry entry = orderedChainEntries.get(i);
            if (entry.jwt != null) {
                long entryMaxAge = this.applicableMaxAge(entry.subject, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime);
                boolean expiring = entry.isExpiringWithin(300L);
                boolean tooOld = entry.isOlderThan(entryMaxAge);
                if (expiring || tooOld) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(String.format("entryMaxAge(%s), expiring(%s), tooOld(%s)", entryMaxAge, expiring, tooOld));
                    }
                    ChainEntry refreshed = this.refreshEntry(entry, entryMaxAge, pendingWrites);
                    if (refreshed != null) {
                        orderedChainEntries.set(i, refreshed);
                        entry = refreshed;
                    }
                }
            }
            if (entry.jwt != null) {
                orderedChain.add(entry.jwt);
            }
            if (entry.jwt != null) {
                int lastIndex = orderedChainEntries.size() - 1;
                Map<String, Object> jwks = i < lastIndex ? orderedChainEntries.get(i + 1).jwks : null;
                JwtClaims verified;
                if (jwks != null) {
                    verified = JwtCodec.verifyAgainstInlineJwks(entry.jwt, jwks, entry.issuer, this.acceptedSigningAlgorithms);
                } else if (Objects.equals(entry.subject, entry.issuer) && entry.jwks != null) {
                    // Self-signed Entity Configuration with no superior statement after it in the
                    // route: per OpenID Federation §3.2 an Entity Configuration is verified with
                    // the Federation Entity Keys it itself carries. Chain-position trust in this
                    // subject was already established during the walk (the trust anchor's
                    // subordinate statement for it resolved successfully) — re-fetching the same
                    // statement from the entity's .well-known just to re-verify it added a live
                    // cross-cloud HTTP call to every token request, and was the residual
                    // stall/timeout source after pushed chains eliminated the walk-time fetch.
                    verified = JwtCodec.verifyAgainstInlineJwks(entry.jwt, entry.jwks, entry.issuer, this.acceptedSigningAlgorithms);
                } else {
                    verified = this.fetchVerifiedClaims(entry.jwt, pendingWrites);
                }
                verifiedByIndex[i] = verified;
                if (verifiedLeaf == null) {
                    verifiedLeaf = verified;
                }
            }
            ++i;
        }
        // The full metadata claim, one block per entity type the leaf holds (e.g. an agent is
        // typically both openid_relying_party and oauth_client at once) — not narrowed to a single
        // assumed type, so a caller that needs a type other than openid_relying_party (e.g.
        // ClientEntityAuthorizer, which reads oauth_client) actually receives it.
        Map<String, Object> resolvedMetadata = applyMetadataPolicy(
                Claims.optionalMap(verifiedLeaf, "metadata"), verifiedByIndex);
        pendingWrites.commit();
        return new TrustChainValidationResult(trustAnchorIssuer, verifiedLeaf.getSubject(), resolvedMetadata, trustChain, verifiedLeaf);
    }

    /**
     * Applies every ancestor statement's {@code metadata_policy} to the leaf's metadata, so a policy
     * set at (or above) the trust anchor actually constrains what a relying party receives — until
     * this, the leaf's self-published metadata was used as-is, with nothing from any superior applied
     * at all.
     *
     * <p>An OpenID Federation 1.0 {@code metadata_policy} constrains what is <em>below</em> the entry
     * that carries it, never the entry itself: {@code verifiedByIndex[0]} — the leaf's own Entity
     * Configuration — is therefore never a source of policy, only a target. Composition runs from the
     * entry closest to the trust anchor down to the entry immediately superior to the leaf (highest
     * index to index 1), matching {@link MetadataPolicy#composeWith}'s superior-then-subordinate
     * contract, and is per entity type — a policy for {@code oauth_client} says nothing about
     * {@code oauth_resource}.
     *
     * <p>{@code metadata_policy_crit} is assumed to be nested per entity type exactly like
     * {@code metadata_policy} itself. That assumption, and the choices {@link MetadataPolicy} makes
     * where OpenID Federation 1.0 Final's own per-operator merge table (§6.1.4) could not be read in
     * either published rendering, are the same "no more permissive than any plausible reading" posture
     * documented on {@link MetadataPolicy}'s class javadoc.
     *
     * @throws MetadataPolicy.PolicyException on any policy conflict, or metadata that does not satisfy
     *                                         the composed policy — always fails closed, never falls
     *                                         through with an unenforced policy
     */
    private static Map<String, Object> applyMetadataPolicy(Map<String, Object> leafMetadata, JwtClaims[] verifiedByIndex)
            throws MetadataPolicy.PolicyException {
        Set<String> entityTypes = new LinkedHashSet<String>(leafMetadata.keySet());
        for (int idx = 1; idx < verifiedByIndex.length; idx++) {
            if (verifiedByIndex[idx] != null) {
                entityTypes.addAll(Claims.optionalMap(verifiedByIndex[idx], "metadata_policy").keySet());
            }
        }
        if (entityTypes.isEmpty()) {
            return leafMetadata;
        }

        LinkedHashMap<String, Object> resolved = new LinkedHashMap<String, Object>(leafMetadata);
        for (String entityType : entityTypes) {
            MetadataPolicy composed = MetadataPolicy.empty();
            for (int idx = verifiedByIndex.length - 1; idx >= 1; idx--) {
                if (verifiedByIndex[idx] != null) {
                    composed = composed.composeWith(policyForType(verifiedByIndex[idx], entityType));
                }
            }
            if (composed.isEmpty()) {
                continue;
            }
            Map<String, Object> current = Claims.optionalNestedMap(leafMetadata, entityType);
            Map<String, Object> applied = composed.apply(current);
            if (!applied.isEmpty()) {
                resolved.put(entityType, applied);
            }
        }
        return resolved;
    }

    /** The {@code metadata_policy} (and any {@code metadata_policy_crit}) one statement declares for one entity type. */
    private static MetadataPolicy policyForType(JwtClaims statement, String entityType) throws MetadataPolicy.PolicyException {
        Map<String, Object> policy = Claims.optionalNestedMap(Claims.optionalMap(statement, "metadata_policy"), entityType);
        if (policy.isEmpty()) {
            return MetadataPolicy.empty();
        }
        Object rawCritical = Claims.optionalMap(statement, "metadata_policy_crit").get(entityType);
        List<String> critical = rawCritical instanceof List ? asStringList((List<?>) rawCritical) : List.of();
        return MetadataPolicy.parse(policy, critical);
    }

    private static List<String> asStringList(List<?> values) {
        ArrayList<String> out = new ArrayList<String>(values.size());
        for (Object value : values) {
            out.add(String.valueOf(value));
        }
        return out;
    }

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

    private List<ChainEntry> tryRoute(Map<String, List<ChainEntry>> entriesBySubject, ChainEntry leafEntry, String firstHopIssuer, String expectedRpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime, SubordinateStatementCache.PendingWrites pendingWrites, FetchBudget budget) {
        ArrayList<ChainEntry> route = new ArrayList<ChainEntry>();
        route.add(leafEntry);
        HashSet<String> visitedSubjects = new HashSet<String>();
        visitedSubjects.add(leafEntry.subject);
        return this.extendRoute(entriesBySubject, route, leafEntry, firstHopIssuer, visitedSubjects, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, pendingWrites, budget);
    }

    private List<ChainEntry> extendRoute(Map<String, List<ChainEntry>> entriesBySubject, List<ChainEntry> route, ChainEntry current, String hintIssuer, Set<String> visitedSubjects, String expectedRpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime, SubordinateStatementCache.PendingWrites pendingWrites, FetchBudget budget) {
        ChainEntry nextHop = findEntry(entriesBySubject.get(current.subject), hintIssuer);
        if (nextHop == null) {
            nextHop = this.tryFetchSubordinateEntry(hintIssuer, current.subject, this.applicableMaxAge(current.subject, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime), pendingWrites, budget);
            if (nextHop == null) {
                return null;
            }
            entriesBySubject.computeIfAbsent(nextHop.subject, ignored -> new ArrayList()).add(nextHop);
        }
        route.add(nextHop);
        return this.walkRoute(entriesBySubject, route, nextHop, visitedSubjects, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, pendingWrites, budget);
    }

    private List<ChainEntry> walkRoute(Map<String, List<ChainEntry>> entriesBySubject, List<ChainEntry> route, ChainEntry current, Set<String> visitedSubjects, String expectedRpIssuer, long maxLeafNodeTime, long maxTrustAnchorNodeTime, SubordinateStatementCache.PendingWrites pendingWrites, FetchBudget budget) {
        while (!Objects.equals(current.issuer, this.knownTrustAnchor)) {
            ChainEntry next;
            if (Objects.equals(current.subject, current.issuer)) {
                List<String> intermediateHints = current.getAuthorityHints();
                if (intermediateHints == null || intermediateHints.isEmpty()) {
                    return null;
                }
                // Every hint, not just the first: an intermediate with more than one authority used to
                // resolve only via hint[0] and otherwise report "no route to anchor", even when a
                // later hint reached the configured anchor. The leaf level (see validate) always
                // iterated; this level did not. Anchor-first for the same reason as there.
                for (String hint : anchorFirst(intermediateHints)) {
                    ArrayList<ChainEntry> branchRoute = new ArrayList<ChainEntry>(route);
                    HashSet<String> branchVisited = new HashSet<String>(visitedSubjects);
                    List<ChainEntry> completed = this.extendRoute(entriesBySubject, branchRoute, current, hint, branchVisited, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime, pendingWrites, budget);
                    if (completed != null) {
                        return Objects.equals(hint, this.knownTrustAnchor) ? route : completed;
                    }
                }
                return null;
            }
            String nextSubject = current.issuer;
            if (!visitedSubjects.add(nextSubject)) {
                return null;
            }
            List<ChainEntry> candidates = entriesBySubject.get(nextSubject);
            ChainEntry chainEntry = next = candidates == null || candidates.isEmpty() ? null : pickNext(candidates);
            if (next == null) {
                next = this.tryFetchSelfSignedEntry(nextSubject, this.applicableMaxAge(nextSubject, expectedRpIssuer, maxLeafNodeTime, maxTrustAnchorNodeTime), pendingWrites, budget);
                if (next == null) {
                    return null;
                }
                entriesBySubject.computeIfAbsent(next.subject, ignored -> new ArrayList()).add(next);
            }
            route.add(next);
            current = next;
        }
        return route;
    }

    private ChainEntry refreshEntry(ChainEntry stale, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) {
        // Refreshing an expiring entry is a small, bounded errand of its own - one or two fetches, not
        // a walk - so it gets its own budget rather than drawing on the validation's.
        FetchBudget budget = new FetchBudget(2);
        ChainEntry refreshed = Objects.equals(stale.subject, stale.issuer) ? this.tryFetchSelfSignedEntry(stale.subject, maxAgeFromIatSeconds, pendingWrites, budget) : this.tryFetchSubordinateEntry(stale.issuer, stale.subject, maxAgeFromIatSeconds, pendingWrites, budget);
        if (refreshed == null) {
            LOGGER.debug("Could not refresh expiring entity statement for sub=" + stale.subject + ", iss=" + stale.issuer + "; verification will proceed against the stale entry");
        }
        return refreshed;
    }

    private ChainEntry tryFetchSubordinateEntry(String authorityIssuer, String subject, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites, FetchBudget budget) {
        ChainEntry entry;
        block5: {
            String jwt;
            block4: {
                try {
                    budget.spend("subordinate statement " + authorityIssuer + " -> " + subject);
                    jwt = this.gateway.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds, pendingWrites);
                    if (jwt != null && !jwt.isBlank()) break block4;
                    LOGGER.debug("fetchSubordinateStatement returned empty body for sub=" + subject + ", iss=" + authorityIssuer);
                    return null;
                }
                catch (Exception e) {
                    LOGGER.debug("Failed to fetch subordinate statement for sub=" + subject + ", iss=" + authorityIssuer + ": " + e.getMessage());
                    return null;
                }
            }
            try {
                entry = new ChainEntry(jwt, JwtCodec.parseUnverifiedClaims(jwt));
            }
            catch (Exception parseFailure) {
                LOGGER.debug("Failed to parse fetched entity statement: " + parseFailure.getMessage());
                return null;
            }
            if (Objects.equals(entry.subject, subject) && Objects.equals(entry.issuer, authorityIssuer)) break block5;
            LOGGER.debug("Fetched subordinate statement did not match expectations: requested sub=" + subject + ", iss=" + authorityIssuer + " but got sub=" + entry.subject + ", iss=" + entry.issuer);
            return null;
        }
        return entry;
    }

    private ChainEntry tryFetchSelfSignedEntry(String subject, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites, FetchBudget budget) {
        ChainEntry entry;
        block5: {
            String jwt;
            block4: {
                try {
                    budget.spend("entity configuration of " + subject);
                    jwt = this.gateway.fetchEntityStatement(subject, maxAgeFromIatSeconds, pendingWrites);
                    if (jwt != null && !jwt.isBlank()) break block4;
                    LOGGER.debug("fetchEntityStatement returned empty body for subject=" + subject);
                    return null;
                }
                catch (Exception e) {
                    LOGGER.debug("Failed to fetch entity configuration for " + subject + ": " + e.getMessage());
                    return null;
                }
            }
            try {
                entry = new ChainEntry(jwt, JwtCodec.parseUnverifiedClaims(jwt));
            }
            catch (Exception parseFailure) {
                LOGGER.debug("Failed to parse fetched entity statement: " + parseFailure.getMessage());
                return null;
            }
            if (Objects.equals(entry.subject, subject) && Objects.equals(entry.issuer, subject)) break block5;
            LOGGER.debug("Fetched entity configuration was not self-signed for subject=" + subject + ": sub=" + entry.subject + ", iss=" + entry.issuer);
            return null;
        }
        return entry;
    }

    private static ChainEntry findEntry(List<ChainEntry> entries, String issuer) {
        if (entries == null) {
            return null;
        }
        for (ChainEntry entry : entries) {
            if (!Objects.equals(entry.issuer, issuer)) continue;
            return entry;
        }
        return null;
    }

    private static ChainEntry pickNext(List<ChainEntry> candidates) {
        ChainEntry selfSigned = null;
        for (ChainEntry entry : candidates) {
            if (Objects.equals(entry.subject, entry.issuer)) {
                selfSigned = entry;
                continue;
            }
            return entry;
        }
        return selfSigned;
    }

    private static List<String> filterStaleChainEntries(List<String> trustChain, long maxTrustChainEntryAgeSeconds) {
        if (trustChain == null || trustChain.isEmpty()) {
            LOGGER.debug("trustChain == null || trustChain.isEmpty()");
            return trustChain;
        }
        if (maxTrustChainEntryAgeSeconds <= 0L) {
            LOGGER.debug("maxTrustChainEntryAgeSeconds <= 0L");
            return trustChain;
        }
        long now = Instant.now().getEpochSecond();
        ArrayList<String> filtered = new ArrayList<String>(trustChain.size());
        for (String jwt : trustChain) {
            Long iat;
            if (jwt == null || jwt.isBlank()) continue;
            try {
                JwtClaims claims = JwtCodec.parseUnverifiedClaims(jwt);
                iat = claims.hasClaim("iat") ? Long.valueOf(claims.getIssuedAt().getValue()) : null;
            }
            catch (Exception e) {
                LOGGER.debug("Unable to parse iat from trust_chain entry; keeping it for downstream verification: " + e.getMessage());
                filtered.add(jwt);
                continue;
            }
            if (iat == null) {
                filtered.add(jwt);
                continue;
            }
            long age = now - iat;
            if (age > maxTrustChainEntryAgeSeconds) {
                if (!LOGGER.isDebugEnabled()) continue;
                LOGGER.debug("Dropping stale trust_chain entry (iat=" + iat + ", ageSeconds=" + age + ", maxTrustChainEntryAgeSeconds=" + maxTrustChainEntryAgeSeconds + ")");
                continue;
            }
            filtered.add(jwt);
        }
        return filtered;
    }

    private JwtClaims fetchVerifiedClaims(String jwt, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        JwtClaims unverifiedClaims = JwtCodec.parseUnverifiedClaims(jwt);
        String issuer = Claims.requireNonBlank(unverifiedClaims.getIssuer(), "iss");
        JwtClaims fetchIssuerMetadata = this.gateway.fetchEntityConfigurationOf(issuer, pendingWrites);
        Map<String, Object> jwks = Claims.requiredMap(fetchIssuerMetadata, "jwks");
        return JwtCodec.verifyAgainstInlineJwks(jwt, jwks, issuer, this.acceptedSigningAlgorithms);
    }

    /**
     * An entity identifier this validator is willing to dereference. OpenID Federation identifiers are
     * https URLs; anything else in a caller-supplied chain is a request-forgery attempt, not a
     * federation entity. (The outbound policy screens addresses too - this is the cheap early check
     * that also keeps the error message about federation rather than about networking.)
     */
    private static void requireFetchableEntityId(String entityId) {
        String lower = entityId == null ? "" : entityId.toLowerCase(java.util.Locale.ROOT);
        if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
            throw new IllegalArgumentException("Not a fetchable entity identifier (federation identifiers are https URLs): " + entityId);
        }
    }

    /** The configured anchor's hint first; the rest keep their order. */
    private List<String> anchorFirst(List<String> hints) {
        if (hints == null || hints.size() < 2 || this.knownTrustAnchor == null) {
            return hints;
        }
        if (!hints.contains(this.knownTrustAnchor)) {
            return hints;
        }
        ArrayList<String> ordered = new ArrayList<String>(hints.size());
        ordered.add(this.knownTrustAnchor);
        for (String hint : hints) {
            if (!Objects.equals(hint, this.knownTrustAnchor)) {
                ordered.add(hint);
            }
        }
        return ordered;
    }

    /**
     * How many live fetches one validation may make. A chain is caller-supplied: its leaf names hints,
     * each hint can name more, and since every intermediate hint is now tried (rather than only the
     * first) the walk is a branching search over attacker-chosen URLs. Without a ceiling one
     * unauthenticated request can become dozens of outbound GETs, each holding a synchronous PF
     * request thread for up to the fetch timeout. Cached entries cost budget too - the point is to
     * bound the work, not just the network.
     */
    static final int DEFAULT_MAX_FETCHES_PER_VALIDATION = 24;

    /** Mutable per-validation counter. Never shared between validations. */
    private static final class FetchBudget {
        private final int max;
        private int used;

        FetchBudget(int max) {
            this.max = max;
        }

        void spend(String what) {
            if (++this.used > this.max) {
                throw new IllegalArgumentException("trust chain resolution exceeded its fetch budget of "
                        + this.max + " (last: " + what + "); refusing to keep resolving");
            }
        }
    }

    private static ChainEntry selectSelfSignedEntry(List<ChainEntry> entries, String subject, String description) {
        if (entries == null || entries.isEmpty()) {
            return null;
        }
        ChainEntry match = null;
        for (ChainEntry entry : entries) {
            if (!Objects.equals(entry.subject, entry.issuer)) continue;
            if (match != null) {
                throw new IllegalArgumentException(description + " is ambiguous for sub=" + subject);
            }
            match = entry;
        }
        return match;
    }

    private static final class ChainEntry {
        private final String jwt;
        private final String subject;
        private final String issuer;
        private final List<String> authorityHints;
        private final Map<String, Object> jwks;
        private final long expEpochSeconds;
        private final long iatEpochSeconds;

        private ChainEntry(String jwt, JwtClaims claims) throws MalformedClaimException {
            this.jwt = jwt;
            this.subject = Claims.requireNonBlank(claims.getSubject(), "sub");
            this.issuer = Claims.requireNonBlank(claims.getIssuer(), "iss");
            this.authorityHints = claims.hasClaim("authority_hints") ? claims.getStringListClaimValue("authority_hints") : null;
            Map<String, Object> parsedJwks = Claims.optionalMap(claims, "jwks");
            this.jwks = parsedJwks.isEmpty() ? null : parsedJwks;
            this.expEpochSeconds = claims.hasClaim("exp") ? claims.getExpirationTime().getValue() : 0L;
            this.iatEpochSeconds = claims.hasClaim("iat") ? claims.getIssuedAt().getValue() : 0L;
        }

        public List<String> getAuthorityHints() {
            return this.authorityHints;
        }

        private boolean isExpiringWithin(long bufferSeconds) {
            if (this.jwt == null) {
                return false;
            }
            if (this.expEpochSeconds == 0L) {
                return true;
            }
            long now = Instant.now().getEpochSecond();
            return this.expEpochSeconds - now <= bufferSeconds;
        }

        private boolean isOlderThan(long maxAgeFromIatSeconds) {
            if (this.jwt == null) {
                return false;
            }
            if (maxAgeFromIatSeconds <= 0L) {
                return false;
            }
            if (this.iatEpochSeconds == 0L) {
                return false;
            }
            long now = Instant.now().getEpochSecond();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format("now(%s) iatEpochSeconds(%s) maxAgeFromIatSeconds(%s)", now, this.iatEpochSeconds, maxAgeFromIatSeconds));
            }
            return now - this.iatEpochSeconds > maxAgeFromIatSeconds;
        }
    }
}

