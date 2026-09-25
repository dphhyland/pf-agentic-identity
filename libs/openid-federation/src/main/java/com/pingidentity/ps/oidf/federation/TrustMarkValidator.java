/*
 * Validates the Trust Marks an Entity carries.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;

/**
 * OpenID Federation 1.0 §7.3: which of the Trust Marks an Entity's configuration carries are valid, against the
 * Trust Anchor its chain reached.
 *
 * <p>For each mark: it is a signed JWT typed {@code trust-mark+jwt} with an acceptable {@code alg} and a {@code kid};
 * it is about the Entity that carries it; the anchor recognises its issuer for its type ({@code trust_mark_issuers},
 * §7 and §3.1.2 - a type the anchor does not list is not recognised); the issuer is trusted, by a chain to the same
 * anchor (§7.3: "The trust in the Trust Mark Issuer comes before the trust in the trust mark"), or is the Entity
 * itself (§7: "a federation MAY allow an Entity to self-sign"); its signature verifies with the key its {@code kid}
 * names among the issuer's Federation Entity Keys; it was issued in the past and, if it has an {@code exp}, has not
 * expired - one without {@code exp} "does not expire" (§7.1); and when the anchor names an owner for its type
 * ({@code trust_mark_owners}) it carries a delegation from that owner that validates (§7.2.2). Optionally the
 * issuer's status endpoint is asked too (§8.4), and anything but {@code active} is a rejection.
 *
 * <p>A mark that fails any of this is rejected, with the reason. A rejected mark never refuses the chain it came
 * with: §7.3 "is NOT about validating whether a Trust Mark of a particular kind can exist".
 *
 * <p>Each issuer costs a chain resolution, so one validation examines at most {@value #MAX_MARKS_EXAMINED} marks and
 * resolves at most {@value #MAX_ISSUERS_RESOLVED} issuers (§18.1); the rest are rejected unexamined. An issuer is
 * resolved once per validation however many of its marks the entity carries.
 */
public final class TrustMarkValidator {
    private static final Log LOGGER = LogFactory.getLog(TrustMarkValidator.class);
    public static final String TRUST_MARK_TYP = "trust-mark+jwt";
    public static final String DELEGATION_TYP = "trust-mark-delegation+jwt";
    public static final String STATUS_RESPONSE_TYP = "trust-mark-status-response+jwt";
    private static final long CLOCK_SKEW_SECONDS = 60L;
    /** Marks examined per validation; beyond this they are rejected unexamined (§18.1). */
    public static final int MAX_MARKS_EXAMINED = 16;
    /** Distinct issuers resolved per validation, whether or not they validate (§18.1). */
    public static final int MAX_ISSUERS_RESOLVED = 8;

    /** A Trust Mark that validated. {@code expiresAt} is -1 for a mark that does not expire. */
    public record Verified(String type, String issuer, String subject, long issuedAt, long expiresAt, String jwt) {
    }

    /** A Trust Mark that did not validate, and why. */
    public record Rejected(String type, String issuer, String reason) {
    }

    /** What an Entity's Trust Marks came to. */
    public record Result(List<Verified> verified, List<Rejected> rejected) {
        public Result {
            verified = List.copyOf(verified);
            rejected = List.copyOf(rejected);
        }

        /** Whether a mark of {@code type} validated. */
        public boolean has(String type) {
            return this.verified.stream().anyMatch(v -> v.type().equals(type));
        }

        /** The earliest {@code exp} among the verified marks, or -1 when none expires. */
        public long earliestExpiry() {
            return this.verified.stream().mapToLong(Verified::expiresAt).filter(e -> e >= 0).min().orElse(-1L);
        }

        /** The verified marks as a {@code trust_marks} claim (§3.1.2). */
        public List<Map<String, Object>> asClaim() {
            List<Map<String, Object>> claim = new ArrayList<>();
            for (Verified v : this.verified) {
                claim.add(Map.of("trust_mark_type", v.type(), "trust_mark", v.jwt()));
            }
            return claim;
        }
    }

    private final TrustChainValidator issuers;
    private final Set<String> acceptedAlgorithms;
    private final Clock clock;
    private final HttpPostClient statusClient;

    /**
     * @param issuers            resolves a Trust Mark Issuer's chain; it must trust the same anchors as the subject's
     * @param acceptedAlgorithms the signing algorithms accepted; empty for any asymmetric one
     */
    public TrustMarkValidator(TrustChainValidator issuers, Set<String> acceptedAlgorithms, Clock clock) {
        this(issuers, acceptedAlgorithms, clock, null);
    }

    /** As above, also asking each issuer's status endpoint (§8.4) through {@code statusClient}. */
    public TrustMarkValidator(TrustChainValidator issuers, Set<String> acceptedAlgorithms, Clock clock, HttpPostClient statusClient) {
        this.issuers = Objects.requireNonNull(issuers, "issuers");
        this.acceptedAlgorithms = acceptedAlgorithms == null ? Set.of() : Set.copyOf(acceptedAlgorithms);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.statusClient = statusClient;
    }

    /**
     * Validates the Trust Marks of {@code subject}'s chain against the anchor's Entity Configuration, which is where the
     * anchor says whose marks it recognises: the one the chain ends with ({@link
     * ValidationRequest.Builder#includeAnchorConfiguration}), else the anchor's own, resolved and verified against its
     * pinned keys - a fetch nothing in a request can steer. Without it every mark is rejected.
     */
    public Result validate(TrustChainValidationResult subject) {
        Object raw = subject.leafEntityStatement().getClaimValue("trust_marks");
        List<Verified> verified = new ArrayList<>();
        List<Rejected> rejected = new ArrayList<>();
        if (!(raw instanceof List<?> marks) || marks.isEmpty()) {
            return new Result(verified, rejected);
        }
        JwtClaims anchor = anchorConfiguration(subject);
        if (anchor == null) {
            anchor = this.resolveAnchorConfiguration(subject.trustAnchorIssuer());
        }
        Map<String, Object> issuerConfigurations = new HashMap<>();
        int examined = 0;
        for (Object item : marks) {
            // EntityStatementChecks has already held each entry to §3.1.2's shape.
            Map<?, ?> entry = (Map<?, ?>) item;
            String type = (String) entry.get("trust_mark_type");
            String jwt = (String) entry.get("trust_mark");
            String issuer = unverifiedIssuer(jwt);
            if (++examined > MAX_MARKS_EXAMINED) {
                rejected.add(new Rejected(type, issuer, "not examined: one validation examines an entity's first "
                        + MAX_MARKS_EXAMINED + " Trust Marks (§18.1)"));
                continue;
            }
            try {
                Verified mark = this.validateOne(type, jwt, subject, anchor, issuerConfigurations);
                verified.add(mark);
                FederationEvents.event(FederationEvents.TRUST_MARK_VERIFIED).subject(subject.leafSubject()).partner(mark.issuer())
                        .field("trust_mark_type", type).field("trust_anchor", subject.trustAnchorIssuer()).emit();
            } catch (Refusal r) {
                rejected.add(new Rejected(type, issuer, r.getMessage()));
                LOGGER.debug("Trust Mark " + LogSafe.value(type) + " from " + LogSafe.value(issuer) + " about " + subject.leafSubject()
                        + " rejected: " + LogSafe.value(r.getMessage()));
            }
        }
        return new Result(verified, rejected);
    }

    private Verified validateOne(String type, String jwt, TrustChainValidationResult subject, JwtClaims anchor,
                                 Map<String, Object> issuerConfigurations) throws Refusal {
        if (anchor == null) {
            throw new Refusal("the trust anchor's configuration, which says whose Trust Marks it recognises, could not be read");
        }
        signedHeader(jwt, "the Trust Mark", TRUST_MARK_TYP);
        JwtClaims claims = unverifiedClaims(jwt, "the Trust Mark");
        String issuer = requiredString(claims, "iss");
        requiredString(claims, "sub");
        requiredNumber(claims, "iat");
        if (!type.equals(claims.getClaimValue("trust_mark_type"))) {
            throw new Refusal("its trust_mark_type is not the one it is listed under");
        }
        if (!EntityId.same((String) claims.getClaimValue("sub"), subject.leafSubject())) {
            throw new Refusal("it is about another entity (§7.3 step 4)");
        }
        recognised(anchor, type, issuer, subject.trustAnchorIssuer());
        JwtClaims issuerConfiguration = this.issuerConfiguration(issuer, subject, issuerConfigurations);
        verify(jwt, keysOf(issuerConfiguration, "the issuer's"), "the Trust Mark");
        long now = this.clock.instant().getEpochSecond();
        long iat = ((Number) claims.getClaimValue("iat")).longValue();
        if (iat > now + CLOCK_SKEW_SECONDS) {
            throw new Refusal("it was issued in the future (§7.3 step 5)");
        }
        Object exp = claims.getClaimValue("exp");
        if (exp != null && !(exp instanceof Number)) {
            throw new Refusal("its exp is not a number");
        }
        long expiresAt = exp == null ? -1L : ((Number) exp).longValue();
        if (exp != null && now >= expiresAt + CLOCK_SKEW_SECONDS) {
            throw new Refusal("it has expired (§7.3 step 6)");
        }
        this.delegation(anchor, type, issuer, claims.getClaimValue("delegation"), now);
        this.status(jwt, issuer, issuerConfiguration);
        return new Verified(type, issuer, subject.leafSubject(), iat, expiresAt, jwt);
    }

    /** §7 and §3.1.2: the anchor lists the type, and either lets anyone issue it ({@code []}) or names this issuer. */
    @SuppressWarnings("unchecked")
    private static void recognised(JwtClaims anchor, String type, String issuer, String anchorId) throws Refusal {
        Object issuers = anchor.getClaimValue("trust_mark_issuers");
        Object allowed = issuers instanceof Map<?, ?> map ? map.get(type) : null;
        if (!(allowed instanceof List<?> list)) {
            throw new Refusal("the trust anchor " + anchorId + " does not recognise Trust Marks of this type (trust_mark_issuers)");
        }
        // EntityStatementChecks has held the claim to arrays of Entity Identifiers.
        if (!list.isEmpty() && list.stream().noneMatch(i -> EntityId.same((String) i, issuer))) {
            throw new Refusal(issuer + " is not an issuer the trust anchor accepts for this type");
        }
    }

    /**
     * The issuer's verified configuration: the subject's own for a self-issued mark, otherwise the configuration its
     * chain to the same anchor ends with (§7.3: established "by following the procedure defined in Section 10").
     * {@code resolved} keeps each issuer's outcome - its configuration, or why not - for the rest of the validation.
     */
    private JwtClaims issuerConfiguration(String issuer, TrustChainValidationResult subject, Map<String, Object> resolved) throws Refusal {
        if (EntityId.same(issuer, subject.leafSubject())) {
            return subject.leafEntityStatement();
        }
        String key = EntityId.comparable(issuer);
        Object outcome = resolved.get(key);
        if (outcome == null) {
            outcome = resolved.size() >= MAX_ISSUERS_RESOLVED
                    ? new Refusal("its issuer " + issuer + " was not resolved: one validation resolves at most " + MAX_ISSUERS_RESOLVED
                            + " issuers (§18.1)")
                    : this.resolveIssuer(issuer, subject.trustAnchorIssuer());
            resolved.put(key, outcome);
        }
        if (outcome instanceof Refusal refusal) {
            throw refusal;
        }
        return (JwtClaims) outcome;
    }

    private Object resolveIssuer(String issuer, String anchor) {
        try {
            return this.issuers.validate(ValidationRequest.forSubject(issuer).requestedAnchors(List.of(anchor)).build()).leafEntityStatement();
        } catch (FederationException e) {
            return new Refusal("its issuer " + issuer + " does not validate to the same trust anchor (" + e.error().code() + ")");
        }
    }

    /** The anchor's configuration, from the anchor resolved as its own subject: verified against its pinned keys. */
    private JwtClaims resolveAnchorConfiguration(String anchor) {
        try {
            return this.issuers.validate(ValidationRequest.forSubject(anchor).requestedAnchors(List.of(anchor)).build()).leafEntityStatement();
        } catch (FederationException e) {
            return null;
        }
    }

    /**
     * §7.2.2: required when the anchor names an owner for the type (§7.3 step 8), and validated whenever present
     * (step 9) - which needs that owner's keys, so a delegation for a type with no owner cannot validate.
     */
    @SuppressWarnings("unchecked")
    private void delegation(JwtClaims anchor, String type, String issuer, Object delegation, long now) throws Refusal {
        Object owners = anchor.getClaimValue("trust_mark_owners");
        Object owner = owners instanceof Map<?, ?> map ? map.get(type) : null;
        if (owner == null && delegation == null) {
            return;
        }
        if (owner == null) {
            throw new Refusal("it carries a delegation, but the trust anchor names no owner for its type to have delegated it");
        }
        if (!(delegation instanceof String jwt)) {
            throw new Refusal("its type has an owner, so it needs a delegation from that owner (§7.3 step 8)");
        }
        Map<String, Object> ownerEntry = (Map<String, Object>) owner;
        signedHeader(jwt, "the delegation", DELEGATION_TYP);
        JwtClaims claims = unverifiedClaims(jwt, "the delegation");
        requiredNumber(claims, "iat");
        if (!EntityId.same(String.valueOf(claims.getClaimValue("sub")), issuer)) {
            throw new Refusal("the delegation is not to this issuer (§7.2.2 step 4)");
        }
        if (!EntityId.same(String.valueOf(claims.getClaimValue("iss")), String.valueOf(ownerEntry.get("sub")))) {
            throw new Refusal("the delegation is not from the type's owner (§7.2.2 step 5)");
        }
        if (((Number) claims.getClaimValue("iat")).longValue() > now + CLOCK_SKEW_SECONDS) {
            throw new Refusal("the delegation was issued in the future (§7.2.2 step 6)");
        }
        Object exp = claims.getClaimValue("exp");
        if (exp != null && (!(exp instanceof Number n) || now >= n.longValue() + CLOCK_SKEW_SECONDS)) {
            throw new Refusal("the delegation has expired (§7.2.2 step 7)");
        }
        if (!type.equals(claims.getClaimValue("trust_mark_type"))) {
            throw new Refusal("the delegation is for another type (§7.2.2 step 8)");
        }
        verify(jwt, federationKeys(ownerEntry.get("jwks"), "the owner's"), "the delegation");
    }

    /**
     * §8.4, when a status client is configured and the issuer publishes a status endpoint: the issuer's signed
     * {@code trust-mark-status-response+jwt} about this very mark must say {@code active}.
     */
    private void status(String jwt, String issuer, JwtClaims issuerConfiguration) throws Refusal {
        if (this.statusClient == null) {
            return;
        }
        Object endpoint = federationEntity(issuerConfiguration).get("federation_trust_mark_status_endpoint");
        if (!(endpoint instanceof String url)) {
            return;
        }
        HttpPostClient.Response response;
        try {
            response = this.statusClient.postForm(url, Map.of("trust_mark", jwt), null, "application/trust-mark-status-response+jwt");
        } catch (Exception e) {
            throw new Refusal("its issuer's status endpoint could not be reached");
        }
        if (response.status() == 404) {
            throw new Refusal("its issuer does not know it (§8.4.2)");
        }
        if (response.status() != 200) {
            throw new Refusal("its issuer's status endpoint answered " + response.status());
        }
        String statusJwt = response.body();
        signedHeader(statusJwt, "the status response", STATUS_RESPONSE_TYP);
        JwtClaims status = verify(statusJwt, keysOf(issuerConfiguration, "the issuer's"), "the status response");
        if (!EntityId.same(String.valueOf(status.getClaimValue("iss")), issuer) || !jwt.equals(status.getClaimValue("trust_mark"))) {
            throw new Refusal("the status response is not its issuer's answer about this mark");
        }
        Object state = status.getClaimValue("status");
        if (!"active".equals(state)) {
            throw new Refusal("its issuer says it is " + state + " (§8.4.2)");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> federationEntity(JwtClaims configuration) {
        Object metadata = configuration.getClaimValue("metadata");
        Object entity = metadata instanceof Map<?, ?> m ? m.get("federation_entity") : null;
        return entity instanceof Map<?, ?> e ? (Map<String, Object>) e : Map.of();
    }

    /** §7.3 steps 1-3 and §7 (4): a JWS (not a JWE), explicitly typed, an acceptable {@code alg}, and a {@code kid}. */
    private void signedHeader(String jwt, String what, String typ) throws Refusal {
        if (JwtCodec.isCompactJwe(jwt)) {
            throw new Refusal(what + " is not a signed JWT");
        }
        Map<String, Object> header;
        try {
            header = JwtCodec.getJwtHeaders(jwt);
        } catch (JwtVerificationException e) {
            throw new Refusal(what + " is not a signed JWT");
        }
        if (!typ.equals(header.get("typ"))) {
            throw new Refusal(what + " is not typed " + typ);
        }
        Object alg = header.get("alg");
        if (!(alg instanceof String a) || "none".equalsIgnoreCase(a) || a.toUpperCase(Locale.ROOT).startsWith("HS")
                || !this.acceptedAlgorithms.isEmpty() && !this.acceptedAlgorithms.contains(a)) {
            throw new Refusal(what + "'s alg is not acceptable");
        }
        if (!(header.get("kid") instanceof String kid) || kid.isEmpty()) {
            throw new Refusal(what + " has no kid");
        }
    }

    private JwtClaims verify(String jwt, List<JsonWebKey> keys, String what) throws Refusal {
        try {
            return JwtCodec.verifySignature(jwt, keys, this.acceptedAlgorithms);
        } catch (JwtVerificationException e) {
            throw new Refusal(what + "'s signature does not verify with the key its kid names (" + e.code() + ")");
        }
    }

    private static List<JsonWebKey> keysOf(JwtClaims configuration, String whose) throws Refusal {
        return federationKeys(configuration.getClaimValue("jwks"), whose);
    }

    @SuppressWarnings("unchecked")
    private static List<JsonWebKey> federationKeys(Object jwks, String whose) throws Refusal {
        try {
            return Jwks.parseFederationKeySet(jwks instanceof Map<?, ?> ? (Map<String, Object>) jwks : null);
        } catch (IllegalArgumentException e) {
            throw new Refusal(whose + " keys are not a usable set of Federation Entity Keys");
        }
    }

    private static JwtClaims unverifiedClaims(String jwt, String what) throws Refusal {
        try {
            return JwtCodec.parseUnverifiedClaims(jwt);
        } catch (Exception e) {
            throw new Refusal(what + " is not a signed JWT");
        }
    }

    private static String requiredString(JwtClaims claims, String name) throws Refusal {
        if (!(claims.getClaimValue(name) instanceof String value) || value.isBlank()) {
            throw new Refusal("it has no " + name + " (§7.1)");
        }
        return value;
    }

    private static void requiredNumber(JwtClaims claims, String name) throws Refusal {
        if (!(claims.getClaimValue(name) instanceof Number)) {
            throw new Refusal("it has no " + name + " (§7.1)");
        }
    }

    private static String unverifiedIssuer(String jwt) {
        try {
            Object iss = JwtCodec.parseUnverifiedClaims(jwt).getClaimValue("iss");
            return iss instanceof String s ? s : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The anchor's configuration: the chain's last statement, when it is the anchor's own. */
    static JwtClaims anchorConfiguration(TrustChainValidationResult chain) {
        List<String> statements = chain.trustChain();
        try {
            JwtClaims last = JwtCodec.parseUnverifiedClaims(statements.get(statements.size() - 1));
            String anchor = chain.trustAnchorIssuer();
            return EntityId.same(last.getIssuer(), anchor) && EntityId.same(last.getSubject(), anchor) ? last : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Why one mark was rejected; never escapes {@link #validate}. */
    private static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;

        Refusal(String reason) {
            super(reason, null, false, false);
        }
    }
}
