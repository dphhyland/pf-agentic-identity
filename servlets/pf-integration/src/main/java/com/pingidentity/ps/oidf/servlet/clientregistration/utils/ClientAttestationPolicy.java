/*
 * One client's attestation_* extended properties, parsed strictly.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * One client's {@code attestation_*} extended properties, parsed strictly (plan item S4c), and the rule that applies
 * them to the server's policy: each can only tighten it.
 *
 * <ul>
 *   <li>{@code attestation_pop_max_age} and {@code attestation_dpop_max_age}: a whole number of seconds, at least 1 and
 *       no more than the server's (a proof older than that is refused).</li>
 *   <li>{@code attestation_clock_skew}: a whole number of seconds, 0 or more and no more than the server's.</li>
 *   <li>{@code attestation_challenge_required}: {@code true} turns the challenge on; {@code false} leaves the server's
 *       setting as it is.</li>
 *   <li>{@code attestation_accepted_algs}, {@code attestation_pop_algs} and {@code attestation_dpop_algs}: the
 *       algorithms kept are those the server also accepts; none left is an error.</li>
 *   <li>{@code attestation_required_claims}: added to the claims the server requires.</li>
 *   <li>{@code attestation_expected_htu}: pins the token endpoint URL a DPoP proof must name to one of the URLs the
 *       server answers at for the request; any other URL is an error, because RFC 9449 §4.3 has the proof name "the
 *       HTTP URI value for the HTTP request in which the JWT was received", and a pin naming another URL could never be
 *       met.</li>
 *   <li>{@code attestation_required}: {@code true} means the client may authenticate at the token endpoint only with
 *       an attestation.</li>
 * </ul>
 *
 * <p>A property that does not parse, holds more than one value, or would loosen the server's policy is a policy error
 * for the client: the client is refused (401 {@code invalid_client}), never given a default. The error names the
 * property and never its value. In the development profile only, the spellings the old reader accepted - the booleans
 * {@code yes}, {@code no}, {@code on}, {@code off}, {@code 1}, {@code 0} and {@code true} or {@code false} in another
 * case, and any value with spaces around it - are read as what they say, with a warning naming the strict spelling
 * (the programme's decision 11); production refuses them.
 */
public final class ClientAttestationPolicy {

    public static final String REQUIRED = "attestation_required";
    public static final String POP_MAX_AGE = "attestation_pop_max_age";
    public static final String DPOP_MAX_AGE = "attestation_dpop_max_age";
    public static final String CLOCK_SKEW = "attestation_clock_skew";
    public static final String CHALLENGE_REQUIRED = "attestation_challenge_required";
    public static final String EXPECTED_HTU = "attestation_expected_htu";
    public static final String ACCEPTED_ALGS = "attestation_accepted_algs";
    public static final String POP_ALGS = "attestation_pop_algs";
    public static final String DPOP_ALGS = "attestation_dpop_algs";
    public static final String REQUIRED_CLAIMS = "attestation_required_claims";

    /** Every property this class reads, in catalogue order. */
    public static final List<String> PROPERTIES = List.of(REQUIRED, POP_MAX_AGE, DPOP_MAX_AGE, CLOCK_SKEW, CHALLENGE_REQUIRED,
            EXPECTED_HTU, ACCEPTED_ALGS, POP_ALGS, DPOP_ALGS, REQUIRED_CLAIMS);

    private final String clientId;
    private final boolean known;
    private final boolean attestationRequired;
    private final Long popMaxAge;
    private final Long dpopMaxAge;
    private final Integer clockSkew;
    private final boolean challengeRequired;
    private final String expectedHtu;
    private final Set<String> acceptedAlgs;
    private final Set<String> popAlgs;
    private final Set<String> dpopAlgs;
    private final Set<String> requiredClaims;
    private final AttestationPolicyException invalid;

    private ClientAttestationPolicy(Builder b) {
        this.clientId = b.clientId;
        this.known = b.known;
        this.attestationRequired = b.attestationRequired;
        this.popMaxAge = b.popMaxAge;
        this.dpopMaxAge = b.dpopMaxAge;
        this.clockSkew = b.clockSkew;
        this.challengeRequired = b.challengeRequired;
        this.expectedHtu = b.expectedHtu;
        this.acceptedAlgs = b.acceptedAlgs;
        this.popAlgs = b.popAlgs;
        this.dpopAlgs = b.dpopAlgs;
        this.requiredClaims = b.requiredClaims;
        this.invalid = b.invalid;
    }

    /** The policy of a client PingFederate does not have: the server's policy, nothing required. */
    public static ClientAttestationPolicy unknown(String clientId) {
        Builder b = new Builder(clientId);
        b.known = false;
        return new ClientAttestationPolicy(b);
    }

    /**
     * Parses {@code properties} (the client's extended properties, name to values). The first property that does not
     * parse makes the whole policy invalid ({@link #invalid()}); nothing else of it is applied.
     *
     * @param development whether the deployment profile is development (the legacy boolean spellings)
     * @param warnings    told of each legacy spelling accepted, by property name and its strict spelling
     */
    public static ClientAttestationPolicy parse(String clientId, Map<String, List<String>> properties, boolean development,
            Consumer<String> warnings) {
        Builder b = new Builder(clientId);
        try {
            b.attestationRequired = Boolean.TRUE.equals(bool(clientId, properties, REQUIRED, development, warnings));
            b.popMaxAge = seconds(clientId, properties, POP_MAX_AGE, 1L, Long.MAX_VALUE, development, warnings);
            b.dpopMaxAge = seconds(clientId, properties, DPOP_MAX_AGE, 1L, Long.MAX_VALUE, development, warnings);
            Long skew = seconds(clientId, properties, CLOCK_SKEW, 0L, Integer.MAX_VALUE, development, warnings);
            b.clockSkew = skew == null ? null : skew.intValue();
            b.challengeRequired = Boolean.TRUE.equals(bool(clientId, properties, CHALLENGE_REQUIRED, development, warnings));
            b.expectedHtu = htu(clientId, properties, development, warnings);
            b.acceptedAlgs = words(clientId, properties, ACCEPTED_ALGS, development, warnings);
            b.popAlgs = words(clientId, properties, POP_ALGS, development, warnings);
            b.dpopAlgs = words(clientId, properties, DPOP_ALGS, development, warnings);
            b.requiredClaims = words(clientId, properties, REQUIRED_CLAIMS, development, warnings);
        } catch (AttestationPolicyException e) {
            b.invalid = e;
        }
        return new ClientAttestationPolicy(b);
    }

    public String clientId() {
        return this.clientId;
    }

    /** Whether PingFederate has the client. */
    public boolean known() {
        return this.known;
    }

    /** Whether the client may authenticate at the token endpoint only with an attestation ({@code attestation_required}). */
    public boolean attestationRequired() {
        return this.attestationRequired;
    }

    /** Why the client's properties are refused, or null when they parse. */
    public AttestationPolicyException invalid() {
        return this.invalid;
    }

    /**
     * The effective policy: {@code global} tightened by this client's properties.
     *
     * @param htuAliases the URLs the server answers at for this request's endpoint (its advertised URL, and the issuer
     *                   followed by the endpoint's path), none of them null. Empty when the endpoint is not the token endpoint, and then
     *                   {@code attestation_expected_htu}, a token endpoint pin, is not applied.
     * @throws AttestationPolicyException when the properties do not parse, or one would loosen {@code global}
     */
    public ClientAttestationConfig apply(ClientAttestationConfig global, Set<String> htuAliases) throws AttestationPolicyException {
        if (this.invalid != null) {
            throw this.invalid;
        }
        ClientAttestationConfig.Builder b = ClientAttestationConfig.builder()
                .expectedAudience(global.expectedAudience())
                .expectedHtm(global.expectedHtm())
                .expectedHtu(global.expectedHtu())
                .maxAttestationLifetimeSeconds(global.maxAttestationLifetimeSeconds());
        b.popMaxAgeSeconds(this.notLonger(POP_MAX_AGE, this.popMaxAge, global.popMaxAgeSeconds()));
        b.dpopMaxAgeSeconds(this.notLonger(DPOP_MAX_AGE, this.dpopMaxAge, global.dpopMaxAgeSeconds()));
        b.allowedClockSkewSeconds((int) this.notLonger(CLOCK_SKEW, this.clockSkew == null ? null : this.clockSkew.longValue(),
                global.allowedClockSkewSeconds()));
        b.challengeRequired(global.challengeRequired() || this.challengeRequired);
        b.attestationAlgorithms(this.narrowed(ACCEPTED_ALGS, this.acceptedAlgs, global.attestationAlgorithms()));
        b.popAlgorithms(this.narrowed(POP_ALGS, this.popAlgs, global.popAlgorithms()));
        b.dpopAlgorithms(this.narrowed(DPOP_ALGS, this.dpopAlgs, global.dpopAlgorithms()));
        Set<String> claims = new LinkedHashSet<>(global.requiredDisclosedClaims());
        if (this.requiredClaims != null) {
            claims.addAll(this.requiredClaims);
        }
        b.requiredDisclosedClaims(claims);
        if (this.expectedHtu != null && !htuAliases.isEmpty()) {
            b.expectedHtu(this.pinned(htuAliases));
        }
        return b.build();
    }

    /**
     * The server's value, or the client's when it is set, which may only be smaller. A server with no proof age limit
     * (0 or less, which {@code ClientAttestationVerifier} reads as none) takes any limit; a skew of 0 is a skew.
     */
    private long notLonger(String property, Long client, long global) throws AttestationPolicyException {
        if (client == null) {
            return global;
        }
        boolean limited = CLOCK_SKEW.equals(property) || global > 0L;
        if (limited && client > global) {
            throw this.error(property, "loosens", "would loosen the server's " + global + " s");
        }
        return client;
    }

    /** The server's algorithms that the client also names; none in common is an error. */
    private Set<String> narrowed(String property, Set<String> client, Set<String> global) throws AttestationPolicyException {
        if (client == null) {
            return global;
        }
        Set<String> kept = new LinkedHashSet<>(client);
        kept.retainAll(global);
        if (kept.isEmpty()) {
            throw this.error(property, "empty_intersection", "names no algorithm the server accepts");
        }
        return kept;
    }

    /** The alias the pin names, as the pin spells it; a pin naming none of them is an error. */
    private String pinned(Set<String> htuAliases) throws AttestationPolicyException {
        String pin = normalise(this.expectedHtu);
        for (String alias : htuAliases) {
            if (pin.equals(normalise(alias))) {
                return this.expectedHtu;
            }
        }
        throw this.error(EXPECTED_HTU, "foreign_htu", "is not a URL this server answers at for the token endpoint");
    }

    private AttestationPolicyException error(String property, String problem, String why) {
        return new AttestationPolicyException(this.clientId, property, problem, why);
    }

    /**
     * {@code url} as RFC 3986 §6.2.2 and §6.2.3 normalise it for a comparison: the scheme and host in lower case, the
     * scheme's default port removed, dot segments removed, an empty path as {@code /}. The query and fragment are left
     * out, as RFC 9449 §4.3 item 9 ignores them. A URL that does not parse compares as itself.
     */
    static String normalise(String url) {
        try {
            URI u = new URI(url.trim()).normalize();
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
            int port = u.getPort();
            boolean defaultPort = port == 443 && "https".equals(scheme) || port == 80 && "http".equals(scheme);
            String path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
            return scheme + "://" + host + (port < 0 || defaultPort ? "" : ":" + port) + path;
        } catch (Exception e) {
            return url;
        }
    }

    // ---- strict readers ------------------------------------------------------------------------------------------

    /**
     * The one value set for {@code name}, or null when unset or blank; more than one value is an error, and so is a
     * value with spaces around it, which the development profile reads trimmed with a warning.
     */
    static String single(String clientId, Map<String, List<String>> properties, String name, boolean development,
            Consumer<String> warnings) throws AttestationPolicyException {
        List<String> values = properties.get(name);
        if (values == null) {
            return null;
        }
        List<String> set = new ArrayList<>();
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                set.add(v);
            }
        }
        if (set.size() > 1) {
            throw new AttestationPolicyException(clientId, name, "unparsable", "holds more than one value");
        }
        if (set.isEmpty()) {
            return null;
        }
        String value = set.get(0);
        String trimmed = value.trim();
        if (!trimmed.equals(value)) {
            if (!development) {
                throw new AttestationPolicyException(clientId, name, "unparsable", "has spaces around its value");
            }
            warnings.accept(name + " on client " + clientId + " is read without the spaces around its value in the"
                    + " development profile only; remove them, which production requires");
        }
        return trimmed;
    }

    private static Boolean bool(String clientId, Map<String, List<String>> properties, String name, boolean development,
            Consumer<String> warnings) throws AttestationPolicyException {
        String value = single(clientId, properties, name, development, warnings);
        if (value == null) {
            return null;
        }
        if ("true".equals(value) || "false".equals(value)) {
            return "true".equals(value);
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (development && List.of("true", "yes", "on", "1", "false", "no", "off", "0").contains(lower)) {
            boolean read = List.of("true", "yes", "on", "1").contains(lower);
            warnings.accept(name + " on client " + clientId + " is read as " + read + " in the development profile only;"
                    + " write " + read + ", which production requires");
            return read;
        }
        throw new AttestationPolicyException(clientId, name, "unparsable", "must be true or false");
    }

    private static Long seconds(String clientId, Map<String, List<String>> properties, String name, long min, long max,
            boolean development, Consumer<String> warnings) throws AttestationPolicyException {
        String value = single(clientId, properties, name, development, warnings);
        if (value == null) {
            return null;
        }
        long read;
        try {
            read = Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new AttestationPolicyException(clientId, name, "unparsable", "must be a whole number of seconds");
        }
        if (read < min || read > max) {
            throw new AttestationPolicyException(clientId, name, "unparsable", "must be between " + min + " and " + max + " seconds");
        }
        return read;
    }

    private static Set<String> words(String clientId, Map<String, List<String>> properties, String name, boolean development,
            Consumer<String> warnings) throws AttestationPolicyException {
        String value = single(clientId, properties, name, development, warnings);
        if (value == null) {
            return null;
        }
        Set<String> words = new LinkedHashSet<>();
        for (String word : value.split("[\\s,]+")) {
            if (!word.isEmpty()) {
                words.add(word);
            }
        }
        if (words.isEmpty()) {
            throw new AttestationPolicyException(clientId, name, "unparsable", "lists nothing");
        }
        return words;
    }

    private static String htu(String clientId, Map<String, List<String>> properties, boolean development,
            Consumer<String> warnings) throws AttestationPolicyException {
        String value = single(clientId, properties, EXPECTED_HTU, development, warnings);
        if (value == null) {
            return null;
        }
        try {
            URI u = new URI(value);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!("https".equals(scheme) || "http".equals(scheme)) || u.getHost() == null || u.getRawQuery() != null
                    || u.getRawFragment() != null) {
                throw new AttestationPolicyException(clientId, EXPECTED_HTU, "unparsable",
                        "must be an absolute http or https URL with a host, and no query or fragment");
            }
        } catch (java.net.URISyntaxException e) {
            throw new AttestationPolicyException(clientId, EXPECTED_HTU, "unparsable", "is not a URL");
        }
        return value;
    }

    private static final class Builder {
        private final String clientId;
        private boolean known = true;
        private boolean attestationRequired;
        private Long popMaxAge;
        private Long dpopMaxAge;
        private Integer clockSkew;
        private boolean challengeRequired;
        private String expectedHtu;
        private Set<String> acceptedAlgs;
        private Set<String> popAlgs;
        private Set<String> dpopAlgs;
        private Set<String> requiredClaims;
        private AttestationPolicyException invalid;

        private Builder(String clientId) {
            this.clientId = clientId;
        }
    }
}
