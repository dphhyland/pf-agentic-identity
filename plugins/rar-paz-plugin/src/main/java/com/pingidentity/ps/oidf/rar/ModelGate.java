/*
 * The containment model as this plugin asks it: one model set per classloader, and the three questions.
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.rar.model.FieldRule;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.rar.model.Rule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This plugin's one door to {@code libs/rar-model} (plan S-1, package S1c). It holds the model set, strips the
 * repository's two bookkeeping markers before anything is asked, and asks the model the plugin's three questions:
 * <ul>
 *   <li>is a requested detail one the model can read ({@link #check}), before any PDP call, and
 *       ({@link #conformance}) where the detail arrives, in {@code validate};</li>
 *   <li>is what the PDP granted within what was requested ({@link #within}, requested as the ceiling): the PDP
 *       may narrow, never widen;</li>
 *   <li>is a refresh's detail within the detail already granted ({@link #within}, the grant as the ceiling):
 *       the model's strict {@code contains}.</li>
 * </ul>
 *
 * <p>The library is shaded and relocated into this jar, so the model set here is this classloader's own copy.
 * The attestation filter loads its own, and publishes its {@code RarModels.fingerprint()} in the attestation
 * context under {@value #FINGERPRINT_MEMBER}; {@link #fingerprintProblem} is the comparison, and a context that
 * is there without the member, or with another fingerprint, is a refusal.
 *
 * <p>The process's set is read from the environment once, when this class is first used - PingFederate
 * instantiates the processor at start-up to read its descriptor - and logged there with its fingerprint. A
 * models document the library refuses leaves the set unloaded, and every question is then refused, never
 * answered from a model the plugin could not read. Refusing only the owning component, with a 503 and health
 * DOWN, is plan item S-9 (Phase 3); until then this is the plugin's form of "does not start".
 */
final class ModelGate {

    /** The attestation context member that carries the filter's {@code RarModels.fingerprint()}. */
    static final String FINGERPRINT_MEMBER = "rar_models_fingerprint";

    /**
     * The client-asserted principal a front-end folds into a detail; the principal resolver reads it, and it is
     * never a field the model compares. The model declares it {@code forbidden}, so a detail that reaches the
     * model carrying it is malformed.
     */
    static final String PRINCIPAL_MARKER = "_principal_sub";

    /** The agent instance the attestation filter writes into every detail of a request it verified; likewise. */
    static final String AGENT_MARKER = "_agent_id";

    private static final Logger LOG = Logger.getLogger(ModelGate.class.getName());

    /** The process's model set: {@code OIDF_RAR_MODELS_FILE} or {@code OIDF_RAR_MODELS}, read once per classloader. */
    private static final ModelGate PROCESS = fromEnvironment(System.getenv());

    /** One answer: contained, not contained, or refused with the reason the question could not be answered. */
    record Verdict(boolean contained, RarModelException.Reason reason, String refusal) {

        static final Verdict CONTAINED = new Verdict(true, null, null);
        static final Verdict NOT_CONTAINED = new Verdict(false, null, null);

        static Verdict refused(RarModelException.Reason reason, String refusal) {
            return new Verdict(false, reason, refusal);
        }

        /** Whether the question was refused rather than answered. */
        boolean isRefused() {
            return refusal != null;
        }
    }

    private final RarModels models;
    private final String loadFailure;

    private ModelGate(RarModels models, String loadFailure) {
        this.models = models;
        this.loadFailure = loadFailure;
    }

    /** The process's model set, loaded when this class was first used. */
    static ModelGate process() {
        return PROCESS;
    }

    /** A gate over a given model set: for tests, and for the vector runner, which names each case's models. */
    static ModelGate of(RarModels models) {
        return new ModelGate(models, null);
    }

    /**
     * The model set an environment describes ({@link RarModels#fromEnvironment(Map)}), logged once: its fingerprint
     * and types when it loaded, and why not when it did not.
     */
    static ModelGate fromEnvironment(Map<String, String> env) {
        try {
            RarModels loaded = RarModels.fromEnvironment(env);
            LOG.info("RAR models loaded: fingerprint=" + loaded.fingerprint() + " types=" + loaded.types()
                    + " commonFieldsFallback=" + loaded.commonFieldsFallback() + " source=" + sourceOf(env));
            return new ModelGate(loaded, null);
        } catch (RarModelException e) {
            String failure = "the RAR models could not be loaded (" + e.reason() + "): " + e.getMessage();
            LOG.severe(failure + ". Every authorization_details request this plugin is asked about is refused until "
                    + RarModels.ENV_MODELS_FILE + " / " + RarModels.ENV_MODELS + " is fixed and PingFederate restarted.");
            return new ModelGate(null, failure);
        }
    }

    /** Where the models document came from, for the start-up line: the file, the inline value, or nowhere. */
    static String sourceOf(Map<String, String> env) {
        if (notBlank(env.get(RarModels.ENV_MODELS_FILE))) {
            return RarModels.ENV_MODELS_FILE;
        }
        return notBlank(env.get(RarModels.ENV_MODELS)) ? RarModels.ENV_MODELS : "built-in";
    }

    /** Whether the model set loaded; when it did not, every question is refused. */
    boolean loaded() {
        return models != null;
    }

    /** Why the model set did not load, or {@code null} when it did. */
    String loadFailure() {
        return loadFailure;
    }

    /** The model set's {@code RarModels.fingerprint()}, or {@code null} when it did not load. */
    String fingerprint() {
        return models == null ? null : models.fingerprint();
    }

    /**
     * A copy of a detail without the two bookkeeping markers: what the model is asked about, what the PDP is sent
     * and what is granted. Nested values are copied too, so nothing done to the copy reaches the caller's map.
     * {@code null} stays {@code null}.
     */
    static Map<String, Object> strip(Map<String, Object> detail) {
        if (detail == null) {
            return null;
        }
        Map<String, Object> copy = deepCopy(detail);
        copy.remove(PRINCIPAL_MARKER);
        copy.remove(AGENT_MARKER);
        return copy;
    }

    /**
     * A copy of a map with every nested map and list copied as well, and the leaves (strings, numbers, booleans)
     * shared, since none of them can change. {@link StatementApplier} writes into nested maps in place, so a
     * shallow copy of the requested detail would take the PDP's statements too, and the check that the grant is
     * within the request would compare the grant with itself. Member names are kept as they are, so a name that
     * is not a string still reaches the model, which refuses it.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> deepCopy(Map<?, ?> map) {
        Map<Object, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            copy.put(e.getKey(), copyValue(e.getValue()));
        }
        return (Map<String, Object>) (Map<?, ?>) copy;
    }

    private static Object copyValue(Object value) {
        if (value instanceof Map<?, ?> m) {
            return deepCopy(m);
        }
        if (value instanceof List<?> l) {
            List<Object> copy = new ArrayList<>(l.size());
            for (Object item : l) {
                copy.add(copyValue(item));
            }
            return copy;
        }
        return value;
    }

    /**
     * Holds one requested detail, markers already stripped, to its type's model and the size limits: before any
     * PDP call, so a detail the model cannot compare is refused rather than decided, and neither the PDP nor the
     * fail-open path is ever handed one.
     *
     * @throws RarModelException the model's refusal: an unmodelled type, an undeclared field, a malformed or
     *                           too-large value; or {@code MODEL_INVALID} when the model set did not load
     */
    void check(Map<String, Object> detail) throws RarModelException {
        if (models == null) {
            throw new RarModelException(RarModelException.Reason.MODEL_INVALID, loadFailure);
        }
        models.validate(listOf(detail), "requested");
    }

    /**
     * Why one requested detail, markers already stripped, does not conform to its type's model and the size limits, or
     * {@code null} when it does: {@link #check} as an answer rather than a throw, for {@code validate}, which refuses a
     * detail where it arrives (RFC 9396 section 5) and must never throw. The message names the field the model refused,
     * never a value.
     */
    Verdict conformance(Map<String, Object> detail) {
        try {
            check(detail);
            return null;
        } catch (RarModelException e) {
            return Verdict.refused(e.reason(), e.getMessage());
        }
    }

    /**
     * Whether {@code candidate} is within {@code ceiling}, as the model's strict {@code contains} answers it for a
     * one-entry ceiling and a one-entry candidate (CAS §7 rule 1): same type, every field the ceiling constrains
     * present in the candidate and within it, and every field of both declared by the type's model. A question
     * the model cannot answer - either side malformed, an undeclared field, an unmodelled type, no model set - is
     * refused with its reason, which a caller treats as "not contained".
     */
    Verdict within(Map<String, Object> ceiling, Map<String, Object> candidate) {
        if (models == null) {
            return Verdict.refused(RarModelException.Reason.MODEL_INVALID, loadFailure);
        }
        if (ceiling == null || candidate == null) {
            return Verdict.refused(RarModelException.Reason.MALFORMED, "a detail to compare is missing");
        }
        try {
            return models.contains(listOf(ceiling), listOf(candidate)) ? Verdict.CONTAINED : Verdict.NOT_CONTAINED;
        } catch (RarModelException e) {
            return Verdict.refused(e.reason(), e.getMessage());
        }
    }

    /**
     * The top-level members {@code type}'s model declares, a forbidden one (the two markers) left out: what the AuthZEN
     * context allow-list's {@code @model} stands for (package PLG, H-RAR-1). Empty when the model set did not load or
     * no model names the type. A read of the model, never a question about a detail; added here, in this class's own
     * structure, because the model set is held nowhere else in the plugin.
     */
    Set<String> declaredMembers(String type) {
        if (models == null) {
            return Set.of();
        }
        try {
            Set<String> members = new LinkedHashSet<>();
            for (Map.Entry<String, FieldRule> field : models.model(type).fields().entrySet()) {
                if (field.getValue().rule() != Rule.FORBIDDEN) {
                    members.add(field.getKey());
                }
            }
            return Collections.unmodifiableSet(members);
        } catch (RarModelException e) {
            return Set.of();
        }
    }

    /**
     * Why the attestation context rules this model set out, or {@code null} when it does not. Without a context
     * at all - a client the attestation filter did not verify, or an endpoint it does not run on - there is
     * nothing to compare, and the plugin decides as it did before the model (the PDP decides on the request
     * alone, with no attested ceiling). A context that is there must carry the filter's fingerprint, and it must
     * be this plugin's: two classloaders with different models would answer one containment question two ways.
     */
    String fingerprintProblem(AttestationSubject subject) {
        if (subject == null || !subject.isContextPresent()) {
            return null;
        }
        if (models == null) {
            return loadFailure;
        }
        String theirs = subject.getRarModelsFingerprint();
        if (theirs == null) {
            return "the attestation context carries no " + FINGERPRINT_MEMBER + ": the attestation filter that published "
                    + "it predates the RAR containment model, so the two cannot be shown to use one model";
        }
        String ours = fingerprint();
        if (!theirs.equals(ours)) {
            return "the attestation context's " + FINGERPRINT_MEMBER + " (" + shortForm(theirs) + ") is not this plugin's ("
                    + shortForm(ours) + "): the attestation filter and this plugin load different RAR models - give the "
                    + "whole PingFederate process one " + RarModels.ENV_MODELS_FILE + ", and deploy the plugin and the "
                    + "filter from one release";
        }
        return null;
    }

    /**
     * The first twelve characters of a fingerprint for a message, when it is lower-case hex; anything else is
     * named only as not being one, since the context member is written by another component and a log line is no
     * place to repeat an arbitrary string.
     */
    static String shortForm(String fingerprint) {
        if (fingerprint == null) {
            return "none";
        }
        if (!fingerprint.matches("[0-9a-f]{64}")) {
            return "not a lower-case SHA-256 hex value";
        }
        return fingerprint.substring(0, 12) + "...";
    }

    /** A one-entry list, refusing a missing entry as the model would a {@code null} list entry. */
    private static List<Map<String, Object>> listOf(Map<String, Object> detail) throws RarModelException {
        if (detail == null) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the authorization_details entry is missing");
        }
        List<Map<String, Object>> one = new ArrayList<>(1);
        one.add(detail);
        return one;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
