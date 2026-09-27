/*
 * Verified evidence selectors: what a validator proved about an instance, as a bounded, sorted multimap.
 */
package com.pingidentity.ps.oidf.issuer;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;

/**
 * The selectors an {@link InstanceAttestationValidator} proved about an instance (plan item X-B01): an immutable,
 * sorted multimap from {@code <source>:<name>} to a sorted set of values, in one namespace. {@code source} is the
 * validator's evidence type id ({@code spiffe-jwt}, {@code gke-sa-token}, ...); {@code name} comes from the fixed
 * list the validator declares ({@link InstanceAttestationValidator#selectorNames()}). The selectors are what a later
 * policy may condition on (X-B09's selector-conditioned ceilings); nothing reads them yet, and a minted attestation
 * does not carry them.
 *
 * <p>A selector is built only inside a validator, only from a claim of the evidence whose signature it verified, and
 * only after every check passed. Nothing else reaches it: not request parameters, not binding metadata, not
 * introspected attributes ({@link SpireSelectorIntrospector}), not the caller-asserted context. {@link #of} is
 * package-private for that reason, so the servlet package cannot build a non-empty set; the only public value is
 * {@link #none()}.
 *
 * <p>Values are kept exactly as the evidence states them, compared by exact string equality - the way
 * {@link SpiffeBinding#matches(String)} compares an instance subject: case-sensitive, never trimmed or folded. An
 * absent or empty value gives no selector. Above either bound, {@link #MAX_SELECTORS} values in all or
 * {@link #MAX_VALUE_BYTES} bytes in one value, the evidence is refused; it is never truncated.
 */
public final class EvidenceSelectors {

    /**
     * The most values one identity may carry, across every name. The largest built-in list has four names with one
     * value each; the bound is for the sources to come - X-B08's SPIRE reader adds one value per registration
     * selector - and keeps what X-B09 matches per issuance small. An identity with more is refused, not cut short,
     * because a truncated set could drop the one selector a condition turns on.
     */
    public static final int MAX_SELECTORS = 32;

    /**
     * The longest value, in UTF-8 bytes. SPIFFE-ID §2.3: "SPIFFE implementations MUST support SPIFFE URIs up to 2048
     * bytes in length and SHOULD NOT generate URIs of length greater than 2048 bytes". A SPIFFE ID is the longest
     * value any validator here takes from its evidence, so 2048 accepts every conforming one and nothing longer.
     */
    public static final int MAX_VALUE_BYTES = 2048;

    /** A selector name: lower case, digits and underscores, starting with a letter, so {@code source:name} parses. */
    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9_]*");

    private static final EvidenceSelectors NONE = new EvidenceSelectors(new TreeMap<>());

    private final SortedMap<String, SortedSet<String>> selectors;

    private EvidenceSelectors(TreeMap<String, SortedSet<String>> selectors) {
        this.selectors = Collections.unmodifiableSortedMap(selectors);
    }

    /** No selectors: a format that proves nothing beyond its subject, or an identity built outside a validator. */
    public static EvidenceSelectors none() {
        return NONE;
    }

    /**
     * Builds the selectors a validator proved. Call it only after every check on the evidence has passed, and only
     * with values read from the verified evidence.
     *
     * @param source         the validator's evidence type id; becomes the {@code source:} prefix of every key
     * @param names          the validator's fixed list of selector names; a name outside it is a programming error
     * @param refusal        how the validator refuses evidence ({@code invalid_svid}, {@code invalid_instance_attestation})
     * @param nameValuePairs name, value, name, value, ...; a name may repeat to give it several values; a null or
     *                       empty value is skipped
     * @throws IssuanceException        through {@code refusal}, when a value or the count is over its bound
     * @throws IllegalArgumentException when the source, a name or the pairs are malformed - never the evidence's doing
     */
    static EvidenceSelectors of(String source, Collection<String> names,
                                Function<String, IssuanceException> refusal, String... nameValuePairs)
            throws IssuanceException {
        if (source == null || source.isBlank() || source.indexOf(':') >= 0) {
            throw new IllegalArgumentException("a selector source must be a non-blank evidence type id without ':'");
        }
        if (nameValuePairs.length % 2 != 0) {
            throw new IllegalArgumentException("selectors come in name, value pairs");
        }
        TreeMap<String, SortedSet<String>> out = new TreeMap<>();
        int count = 0;
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            String name = nameValuePairs[i];
            if (name == null || !NAME.matcher(name).matches() || !names.contains(name)) {
                throw new IllegalArgumentException("'" + name + "' is not on the selector list of " + source);
            }
            String value = nameValuePairs[i + 1];
            if (value == null || value.isEmpty()) {
                continue;
            }
            String key = source + ":" + name;
            if (value.getBytes(StandardCharsets.UTF_8).length > MAX_VALUE_BYTES) {
                throw refusal.apply("evidence selector " + key + " is longer than " + MAX_VALUE_BYTES + " bytes");
            }
            SortedSet<String> values = out.computeIfAbsent(key, k -> new TreeSet<>());
            if (values.add(value)) {
                count++;
            }
            if (count > MAX_SELECTORS) {
                throw refusal.apply("the evidence gives more than " + MAX_SELECTORS + " selectors");
            }
        }
        for (Map.Entry<String, SortedSet<String>> entry : out.entrySet()) {
            entry.setValue(Collections.unmodifiableSortedSet(entry.getValue()));
        }
        return out.isEmpty() ? NONE : new EvidenceSelectors(out);
    }

    /**
     * A claim's value when it is a JSON string, else null: a selector is taken only from a string claim, never from
     * the text of an array, an object or a number.
     */
    static String stringClaim(JwtClaims claims, String name) {
        Object value = claims.getClaimValue(name);
        return value instanceof String ? (String) value : null;
    }

    /** The selectors: {@code source:name} to its values, both sorted, neither modifiable. */
    public SortedMap<String, SortedSet<String>> asMap() {
        return this.selectors;
    }

    /** Whether there are none. */
    public boolean isEmpty() {
        return this.selectors.isEmpty();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof EvidenceSelectors && ((EvidenceSelectors) other).selectors.equals(this.selectors);
    }

    @Override
    public int hashCode() {
        return this.selectors.hashCode();
    }

    @Override
    public String toString() {
        return this.selectors.toString();
    }
}
