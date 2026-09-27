/*
 * The model set, and the three questions asked of authorization_details: within, grant, meet.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * The per-type containment model for RFC 9396 {@code authorization_details}: the built-in types,
 * whatever a deployment adds through {@value #ENV_MODELS_FILE} or {@value #ENV_MODELS}, and the three
 * operations every enforcement point in this repo asks - the client-attestation authenticator and the
 * attestation issuer at issuance, the RAR plugin after the policy engine answers, the refresh path's
 * {@code isEqualOrSubset}. One model in every classloader; the {@link #fingerprint()} says whether two
 * of them agree.
 *
 * <ul>
 *   <li>{@link #contains}: is every candidate detail within some same-type entry of the ceiling? Strict:
 *       a field the ceiling constrains and the candidate omits is not contained.</li>
 *   <li>{@link #authorize}: the details granted for a candidate, or a refusal. Under
 *       {@link Omission#INHERIT} an omitted constrained field takes the ceiling's value; the result is
 *       always within the ceiling, and the method checks that itself before returning.</li>
 *   <li>{@link #intersect}: the meet - the largest details within both lists, pairwise by type. Used
 *       where two ceilings apply (an evidenced binding's and an asserted context's) and where a policy
 *       engine narrows a grant.</li>
 * </ul>
 *
 * <p>Every operation first holds both lists to {@link Limits} and checks every detail against its
 * type's model, and refuses rather than skips what it cannot compare: an unmodelled type, an undeclared
 * field, a {@code null}, an empty array, a value of the wrong shape, one thing said two ways. A type no
 * model names is refused ({@link RarModelException.Reason#UNMODELLED_TYPE}) unless the deployment
 * profile is {@value #DEVELOPMENT_PROFILE}, when the common-fields model (RFC 9396 §2.2's fields and
 * nothing more) stands in. Every refusal is a {@link RarModelException} with its reason; an
 * {@link IllegalStateException} out of {@link #authorize} is this library's defect, not the request's.
 *
 * <p>Instances are immutable and safe to share.
 */
public final class RarModels {

    /** A file holding the models document; read once, UTF-8. */
    public static final String ENV_MODELS_FILE = "OIDF_RAR_MODELS_FILE";
    /** The models document inline. Setting both this and the file is refused. */
    public static final String ENV_MODELS = "OIDF_RAR_MODELS";
    /**
     * The deployment profile. Read directly here until plan item PR-1 centralises it in the platform
     * library; unset means production, and only the exact value {@value #DEVELOPMENT_PROFILE} enables
     * the common-fields fallback.
     */
    public static final String ENV_PROFILE = "OIDF_DEPLOYMENT_PROFILE";
    /** The profile value that enables the common-fields fallback. */
    public static final String DEVELOPMENT_PROFILE = "development";
    /**
     * The version of what the rules mean, part of {@link #canonicalJson()} so that two builds of this
     * library that compare differently never share a fingerprint, whatever models they load. Raise it
     * with any change to what a rule accepts or contains, and re-pin the fingerprints in the vector file.
     */
    public static final int SEMANTICS = 1;

    private final Map<String, TypeModel> types;
    private final TypeModel commonFields;
    private final boolean commonFieldsFallback;
    private final String canonical;
    private final String fingerprint;

    private RarModels(Map<String, TypeModel> types, boolean commonFieldsFallback) {
        this.types = Collections.unmodifiableMap(new LinkedHashMap<>(types));
        this.commonFields = BuiltIn.commonFields();
        this.commonFieldsFallback = commonFieldsFallback;
        Map<String, Object> described = new TreeMap<>();
        for (Map.Entry<String, TypeModel> e : types.entrySet()) {
            described.put(e.getKey(), e.getValue().describe());
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("common_fields_fallback", commonFieldsFallback);
        doc.put("semantics", SEMANTICS);
        doc.put("types", described);
        this.canonical = Json.write(doc);
        this.fingerprint = sha256(canonical);
    }

    /** The built-in models only, production semantics (no fallback). */
    public static RarModels builtIn() {
        return new RarModels(BuiltIn.models(), false);
    }

    /**
     * The built-ins plus a models document, production semantics (no fallback). The fallback is the
     * environment's to allow, through {@link #fromEnvironment(Map)}, not a caller's.
     *
     * @param modelsJson the document ({@link ModelSchema} has the shape), or {@code null} for none
     */
    public static RarModels load(String modelsJson) throws RarModelException {
        return load(modelsJson, false);
    }

    /**
     * The built-ins plus a models document, with the fallback as given: for {@link #fromEnvironment(Map)},
     * which has read the profile, and for the tests and the vector runner in this package.
     *
     * @param modelsJson           the document, or {@code null} for none
     * @param commonFieldsFallback whether an unmodelled type falls back to the common fields
     */
    static RarModels load(String modelsJson, boolean commonFieldsFallback) throws RarModelException {
        Map<String, TypeModel> builtIn = BuiltIn.models();
        return new RarModels(modelsJson == null ? builtIn : ModelSchema.parse(modelsJson, builtIn), commonFieldsFallback);
    }

    /** {@link #fromEnvironment(Map)} over the process environment. */
    public static RarModels fromEnvironment() throws RarModelException {
        return fromEnvironment(System.getenv());
    }

    /**
     * The models the environment describes: {@value #ENV_MODELS_FILE} or {@value #ENV_MODELS} (not
     * both; either blank counts as unset), with the fallback on only when {@value #ENV_PROFILE} is
     * {@value #DEVELOPMENT_PROFILE}.
     */
    public static RarModels fromEnvironment(Map<String, String> env) throws RarModelException {
        String file = blankToNull(env.get(ENV_MODELS_FILE));
        String inline = blankToNull(env.get(ENV_MODELS));
        if (file != null && inline != null) {
            throw RarModelException.modelInvalid(ENV_MODELS_FILE + " and " + ENV_MODELS + " are both set; set one");
        }
        String json = inline;
        if (file != null) {
            try {
                json = Files.readString(Path.of(file), StandardCharsets.UTF_8);
            } catch (IOException | RuntimeException e) {
                throw RarModelException.modelInvalid(ENV_MODELS_FILE + " could not be read: " + e.getMessage());
            }
        }
        boolean development = DEVELOPMENT_PROFILE.equals(trimmed(env.get(ENV_PROFILE)));
        return load(json, development);
    }

    /**
     * SHA-256, lower-case hex, over {@link #canonicalJson()}. Equal fingerprints mean the same types, fields,
     * rules and alternatives, the same fallback, and the same {@link #SEMANTICS}.
     */
    public String fingerprint() {
        return fingerprint;
    }

    /**
     * The model set as canonical JSON: {@code common_fields_fallback}, {@code semantics}, and every type's
     * fields by name with rules described as a models document writes them, and its alternatives when it
     * has any. What {@link #fingerprint()} hashes.
     */
    public String canonicalJson() {
        return canonical;
    }

    /** The modelled type names, built-ins first. */
    public Set<String> types() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(types.keySet()));
    }

    /** Whether an unmodelled type falls back to the common fields (development only). */
    public boolean commonFieldsFallback() {
        return commonFieldsFallback;
    }

    /**
     * The model for a type.
     *
     * @throws RarModelException {@link RarModelException.Reason#UNMODELLED_TYPE} when none is defined
     *                           and the fallback is off
     */
    public TypeModel model(String type) throws RarModelException {
        TypeModel model = types.get(type);
        if (model != null) {
            return model;
        }
        if (commonFieldsFallback) {
            return commonFields;
        }
        throw RarModelException.unmodelled("no model for authorization_details type " + RarModelException.quote(type));
    }

    /**
     * A parsed {@code authorization_details} value as a list of objects, refusing any other shape.
     * Sizes and contents are checked by the operation that receives it.
     */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> details(Object parsed) throws RarModelException {
        if (!(parsed instanceof List<?> list)) {
            throw RarModelException.malformed("authorization_details must be a JSON array");
        }
        List<Map<String, Object>> out = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof Map<?, ?>)) {
                throw RarModelException.malformed("each authorization_details entry must be a JSON object");
            }
            out.add((Map<String, Object>) item);
        }
        return out;
    }

    /**
     * {@link #details} over JSON text; blank text is an empty list. Text longer than
     * {@link Limits#MAX_TEXT}, nesting past the reader's cap and a number literal past its cap are
     * {@link RarModelException.Reason#TOO_LARGE}; anything else the reader refuses is
     * {@link RarModelException.Reason#MALFORMED}.
     */
    public static List<Map<String, Object>> parseDetails(String json) throws RarModelException {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        if (json.length() > Limits.MAX_TEXT) {
            throw RarModelException.tooLarge("authorization_details is longer than " + Limits.MAX_TEXT + " characters");
        }
        try {
            return details(Json.parse(json));
        } catch (Json.TooLarge e) {
            throw RarModelException.tooLarge("authorization_details is too large to read: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw RarModelException.malformed("authorization_details is not valid JSON: " + e.getMessage());
        }
    }

    /**
     * Holds a list to the size limits and every detail to its type's model.
     *
     * @param details the list
     * @param side    which list, for messages ({@code ceiling}, {@code candidate}, ...)
     * @return the same details, as given - the caller's maps, not copies
     */
    public List<Map<String, Object>> validate(List<? extends Map<String, Object>> details, String side)
            throws RarModelException {
        List<Map<String, Object>> checked = Limits.check(details, side);
        int i = 0;
        for (Map<String, Object> detail : checked) {
            String where = side + " authorization_details[" + i + "]";
            model(typeOf(detail, where)).check(detail, where);
            i++;
        }
        return checked;
    }

    /**
     * Whether every candidate detail is within some ceiling entry of the same type (CAS §7 rule 1:
     * "for a candidate to be within the ceiling there must be a ceiling object of the same type whose
     * constraints it does not exceed"). A candidate must fit one entry; it is never pieced together
     * from several. An empty candidate is within anything; nothing is within an empty ceiling.
     *
     * @throws RarModelException when either list is malformed or names an unmodelled type - a
     *                           question that cannot be answered is refused, not answered "no"
     */
    public boolean contains(List<? extends Map<String, Object>> ceiling, List<? extends Map<String, Object>> candidate)
            throws RarModelException {
        List<Map<String, Object>> c = validate(ceiling, "ceiling");
        List<Map<String, Object>> d = validate(candidate, "candidate");
        for (Map<String, Object> detail : d) {
            if (containing(c, detail, Omission.STRICT).isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /**
     * The details granted for a candidate against a ceiling: each candidate detail, fitted to the
     * first same-type ceiling entry that contains it, in the candidate's order. Under
     * {@link Omission#INHERIT} the fitted detail carries the ceiling's value for every constrained
     * field the candidate omitted (RFC 9396 §7.1 enrichment, the CAS's "narrow" reading of a silent
     * field); under {@link Omission#STRICT} it is the candidate as sent. An empty candidate grants
     * nothing - CAS §7 rule 2's full-ceiling reading of an empty request is {@link #fullCeiling}, for
     * the caller that wants it.
     *
     * @return new objects, never aliasing the inputs
     * @throws RarModelException {@link RarModelException.Reason#EXCEEDS_CEILING} when a detail fits no
     *                           entry (CAS §7 rule 3, {@code reject}), or a malformed-input reason
     */
    public List<Map<String, Object>> authorize(List<? extends Map<String, Object>> candidate,
                                               List<? extends Map<String, Object>> ceiling, Omission mode)
            throws RarModelException {
        Objects.requireNonNull(mode, "mode");
        List<Map<String, Object>> c = validate(ceiling, "ceiling");
        List<Map<String, Object>> d = Limits.check(candidate, "candidate");
        List<Map<String, Object>> granted = new ArrayList<>(d.size());
        int i = 0;
        for (Map<String, Object> detail : d) {
            String where = "candidate authorization_details[" + i + "]";
            String type = typeOf(detail, where);
            TypeModel model = model(type);
            if (mode == Omission.STRICT) {
                model.check(detail, where);
            } else {
                model.checkValues(detail, where);
            }
            Optional<Map<String, Object>> fitted = containing(c, detail, mode);
            if (fitted.isEmpty()) {
                throw RarModelException.exceeds(where + " of type " + RarModelException.quote(type) + " is not within the ceiling");
            }
            granted.add(fitted.get());
            i++;
        }
        assertWithin(c, granted);
        return granted;
    }

    /**
     * The post-condition of {@link #authorize}: what it grants is within the ceiling. Cannot fail
     * unless this library has a defect, which is why it is checked - a containment model that grants
     * outside its ceiling must stop the request, not serve it.
     */
    void assertWithin(List<Map<String, Object>> ceiling, List<Map<String, Object>> granted) throws RarModelException {
        if (!contains(ceiling, granted)) {
            throw new IllegalStateException("authorize produced a grant outside the ceiling; this is a defect in rar-model");
        }
    }

    /**
     * The ceiling itself, validated and copied: what an empty request is granted where CAS §7 rule 2
     * applies ("An empty or absent authorization_details request means the instance asks for its full
     * ceiling").
     */
    public List<Map<String, Object>> fullCeiling(List<? extends Map<String, Object>> ceiling) throws RarModelException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> detail : validate(ceiling, "ceiling")) {
            out.add(asMap(Json.copy(detail)));
        }
        return out;
    }

    /**
     * The meet: the largest details within both lists. Every pair of same-type entries, one from each
     * list, contributes the largest detail within both of them, when one exists (disjoint sets, unequal
     * values, different currencies or a thing spelt two ways mean none). The result is deduplicated and
     * sorted by canonical JSON, so it is the same list whichever way round the arguments come, and it is
     * within each argument. Two details of different types never meet.
     *
     * @return new objects, never aliasing the inputs
     * @throws RarModelException {@link RarModelException.Reason#TOO_LARGE} when the meet has more than
     *                           {@link Limits#MAX_DETAILS} entries - sixteen entries each side can meet
     *                           in 256 ways - since no operation could take it as a list; or a
     *                           malformed-input reason
     */
    public List<Map<String, Object>> intersect(List<? extends Map<String, Object>> a, List<? extends Map<String, Object>> b)
            throws RarModelException {
        List<Map<String, Object>> x = validate(a, "first");
        List<Map<String, Object>> y = validate(b, "second");
        TreeMap<String, Map<String, Object>> out = new TreeMap<>();
        for (Map<String, Object> p : x) {
            String type = (String) p.get("type");
            TypeModel model = model(type);
            for (Map<String, Object> q : y) {
                if (!type.equals(q.get("type"))) {
                    continue;
                }
                Optional<Map<String, Object>> m = model.meet(p, q);
                if (m.isPresent()) {
                    out.putIfAbsent(Json.write(m.get()), m.get());
                    if (out.size() > Limits.MAX_DETAILS) {
                        throw RarModelException.tooLarge("the intersection has more than " + Limits.MAX_DETAILS + " entries");
                    }
                }
            }
        }
        return new ArrayList<>(out.values());
    }

    /**
     * The first ceiling entry of the detail's type that contains it, as the fitted detail: the
     * candidate as sent under STRICT, or with the entry's constrained fields inherited under INHERIT.
     * The candidate has passed the size limits and its own checks; under INHERIT the fitted detail is
     * checked again, because a limit sent without its unit is well formed only once an entry supplies
     * the unit. An entry that does not is passed over; when no same-type entry does, the candidate's
     * limit has no unit anywhere and it is refused as malformed rather than as over the ceiling.
     */
    private Optional<Map<String, Object>> containing(List<Map<String, Object>> ceiling, Map<String, Object> detail,
                                                     Omission mode) throws RarModelException {
        String type = (String) detail.get("type");
        TypeModel model = model(type);
        RarModelException unpaired = null;
        boolean fittedOne = false;
        for (Map<String, Object> entry : ceiling) {
            if (!type.equals(entry.get("type"))) {
                continue;
            }
            Map<String, Object> fitted = mode == Omission.INHERIT ? model.inherit(entry, detail) : asMap(Json.copy(detail));
            if (mode == Omission.INHERIT) {
                try {
                    model.check(fitted, "candidate authorization_details entry of type " + RarModelException.quote(type));
                } catch (RarModelException e) {
                    unpaired = unpaired == null ? e : unpaired;
                    continue;
                }
            }
            if (model.contains(entry, fitted)) {
                return Optional.of(fitted);
            }
            fittedOne = true;
        }
        if (unpaired != null && !fittedOne) {
            throw unpaired;
        }
        return Optional.empty();
    }

    private static String typeOf(Map<String, Object> detail, String where) throws RarModelException {
        Object type = detail.get("type");
        if (!(type instanceof String s) || s.isBlank()) {
            throw RarModelException.malformed(where + " has no 'type'");
        }
        return s;
    }

    private static String blankToNull(String value) {
        String t = trimmed(value);
        return t == null || t.isEmpty() ? null : t;
    }

    private static String trimmed(String value) {
        return value == null ? null : value.trim();
    }

    private static String sha256(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JDK", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }
}
