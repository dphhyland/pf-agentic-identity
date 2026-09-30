/*
 * The details PingFederate is about to issue, held to the client attestation's ceiling: an OGNL issuance criterion, and
 * the check the token endpoint's response belt shares with it.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.ognl.CriterionGuard;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * An access-token mapping's issuance criterion over what PingFederate is about to issue (plan item S4d, F-0032):
 *
 * <pre>{@code com.pingidentity.ps.oidf.servlet.clientregistration.utils.IssuedDetailsCriterion.withinCeiling(#this)}</pre>
 *
 * <p>PingFederate hands an access-token mapping's criteria {@code context.OAuthAuthorizationDetails}: an
 * {@code AttributeValue} whose object values are the details the token will carry, one map per detail - the request's on
 * the client-credentials grant, the stored ones on the code, CIBA and device grants, the grant's on a refresh without the
 * parameter and the narrower ones on a refresh with it (seen on the rig with PingFederate 13.1.3, 2026-09-30, U-0018).
 * CAS §7.1 asks exactly this of the authorization server: it "MUST, when authenticating a client via an attestation
 * containing authorization_details, ensure that any authority granted in issued tokens is a subset of the attestation's
 * authorization_details". So:
 *
 * <ul>
 *   <li>A request whose attestation was verified - by the token-endpoint filter, which publishes it, or here, by the
 *       criterion route {@link ClientAttestationUtils#verifyAtTheCriterion} takes when no filter did - is held to that
 *       attestation's {@code authorization_details} by the model's strict {@link RarModels#contains}: every detail about
 *       to be issued within a ceiling entry of its type, every constrained field present and within. Anything else is
 *       {@code false}, and PingFederate refuses the token with the criterion's Error Result.</li>
 *   <li>A request with no attestation passes for a client that may authenticate without one, whatever it is issued:
 *       the criterion does not invent a ceiling. A client with {@code attestation_required} is {@code false}.</li>
 *   <li>A refresh that sends no {@code authorization_details}, of a grant holding a detail of a type named in
 *       {@value #REDECIDE_SETTING} (default {@code payment_initiation,account_information}), is {@code false} for every
 *       client, attested or not. PingFederate reissues a bare refresh's stored details without calling the RAR
 *       processor's {@code enrich} (F-0105); a client that repeats its details is decided again. RFC 9396 §7 leaves the
 *       bare refresh to the authorization server: "If the client does not specify the authorization_details token
 *       request parameters, the AS determines the resulting authorization_details at its discretion."</li>
 * </ul>
 *
 * <p>It runs on PingFederate's engine classloader, where statics are this copy's own: it learns whether
 * {@code ATTESTATION_AUTH} is serving from the component's switch and the production profile's refusals, which both
 * copies read from the same process-wide sources ({@link ProfileRefusals#refused}), and loads the containment models on
 * its first call. A component that is failed or refused answers {@code false}, never a throw (S9B's rule for criteria);
 * one switched off holds nothing, so only attestation traffic - which nothing on this server verifies then - is
 * {@code false}. {@link CriterionGuard} turns anything thrown into a logged {@code false}.
 *
 * <p>Every refusal is {@code attestation.issued.refused} in pf-integration's {@code attestation} catalogue: which enforcer
 * refused, the client and the types refused, never a value.
 */
public final class IssuedDetailsCriterion {
    private static final Log LOGGER = LogFactory.getLog(IssuedDetailsCriterion.class);

    /** What the log calls the criterion. */
    static final String NAME = "IssuedDetailsCriterion.withinCeiling";
    /** The setting naming the types whose bare refresh is sent back to be decided again. */
    public static final String REDECIDE_SETTING = "OIDF_ATTESTATION_REDECIDE_ON_REFRESH_TYPES";
    /** The catalogue {@value #REDECIDE_SETTING} is in. */
    static final String SETTINGS = "attestation-token-endpoint";
    /** The criteria key PingFederate gives the details about to be issued. */
    static final String ISSUED_DETAILS = "context.OAuthAuthorizationDetails";
    static final String HTTP_REQUEST = "context.HttpRequest";
    static final String CLIENT_ID = "context.ClientId";
    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP";
    static final String REFRESH_GRANT = "refresh_token";
    static final String DETAILS_PARAMETER = "authorization_details";
    /** The bookkeeping names this repository writes into a detail, which are not authority (AuthorizationDetailsGate). */
    static final Set<String> MARKERS = Set.of("_principal_sub", "_agent_id");

    /** The event catalogue and code (pf-integration's {@code attestation} catalogue). */
    static final String ATTESTATION = "attestation";
    public static final String ISSUED_REFUSED = "attestation.issued.refused";
    /** The {@code enforcer} field's values. */
    public static final String BELT = "response_belt";
    public static final String CRITERION = "issuance_criterion";
    /** The refusal reasons, the event's failure. */
    public static final String EXCEEDS = "exceeds_ceiling";
    public static final String UNCHECKABLE = "uncheckable";
    public static final String TOO_LARGE = "too_large";
    public static final String REDECIDE = "redecide_on_refresh";
    public static final String NOT_ATTESTED = "attestation_required";
    /** The most types an event names, and the longest name it keeps. */
    static final int MAX_TYPES = 8;
    static final int MAX_TYPE_LENGTH = 64;

    private static volatile Engine engine;
    private static volatile Set<String> redecideTypes;

    private IssuedDetailsCriterion() {
    }

    /**
     * The OGNL entry point: {@code true} when the token may be issued with what it carries. Never throws.
     *
     * @param inObj the criteria context, {@code #this}
     */
    public static boolean withinCeiling(Object inObj) {
        return CriterionGuard.evaluate(NAME, () -> IssuedDetailsCriterion.decide(inObj, IssuedDetailsCriterion.engine(),
                Collaborators.pingFederate()));
    }

    /** What the criterion needs from PingFederate and the rest of the module; a test supplies its own. */
    record Collaborators(Function<HttpServletRequest, String> issuerOf, Supplier<String> tokenEndpointBaseUrl,
            AttestationPolicyResolver resolver, SubjectTokenVerifier subjectTokens, Supplier<RarModels> models,
            Supplier<Set<String>> redecideTypes) {

        static Collaborators pingFederate() {
            return new Collaborators(PfIssuer.INSTANCE, ClientAttestationUtils::configuredTokenEndpointBaseUrl,
                    AttestationPolicyResolver.shared(), SubjectTokenVerifier.pingFederate(), AttestationRarModels::require,
                    IssuedDetailsCriterion::configuredRedecideTypes);
        }
    }

    /** PingFederate's issuer for a request, resolved on first use: its class cannot load outside a booted server. */
    private enum PfIssuer implements Function<HttpServletRequest, String> {
        INSTANCE;

        @Override
        public String apply(HttpServletRequest request) {
            return com.pingidentity.ps.oidf.platform.pf.internals.PfInternals.issuer(request);
        }
    }

    /**
     * What this copy knows about {@code ATTESTATION_AUTH}, from its switch and the production profile - not from the
     * webapp's parts, which are the other loader's statics.
     */
    enum Engine {
        /** Enabled or inferred, and not refused: the criterion decides. */
        SERVING,
        /** Switched off: nothing verifies an attestation, so nothing is held to one. */
        DISABLED,
        /** A switch that cannot be read, or a profile that refuses the component: every token is refused. */
        FAILED;

        static Engine of(ComponentSwitches.Verdict verdict, boolean refused) {
            if (verdict.kind() == ComponentSwitches.Kind.DISABLED) {
                return DISABLED;
            }
            if (verdict.kind() == ComponentSwitches.Kind.FAILED_CONFIG || refused) {
                return FAILED;
            }
            return SERVING;
        }
    }

    /** This copy's view of the component, read once: both sources are the process's environment, which does not change. */
    static Engine engine() {
        Engine known = engine;
        if (known == null) {
            ComponentSwitches.Verdict verdict = ComponentSwitches.process().verdict(Startup.ATTESTATION_AUTH);
            known = Engine.of(verdict, verdict.kind() != ComponentSwitches.Kind.DISABLED
                    && ProfileRefusals.refused(Startup.ATTESTATION_AUTH, verdict.kind() == ComponentSwitches.Kind.ENABLED));
            engine = known;
        }
        return known;
    }

    /** {@value #REDECIDE_SETTING}, read once from this copy's catalogue. */
    static Set<String> configuredRedecideTypes() {
        Set<String> known = redecideTypes;
        if (known == null) {
            Set<String> read = Settings.load(IssuedDetailsCriterion.class.getClassLoader(), SETTINGS).words(REDECIDE_SETTING);
            known = read == null ? Set.of() : Set.copyOf(read);
            redecideTypes = known;
        }
        return known;
    }

    /** Test seam: forgets what {@link #engine} and {@link #configuredRedecideTypes} read. */
    static void resetForTest() {
        engine = null;
        redecideTypes = null;
    }

    /**
     * The criterion's decision. The component's state comes first (S9B's rule): a failed component refuses every token,
     * a disabled one refuses only attestation traffic.
     */
    static boolean decide(Object inObj, Engine state, Collaborators with) {
        if (state == Engine.FAILED) {
            LOGGER.warn((Object) (NAME + ": ATTESTATION_AUTH is not serving (its switch or the production profile); refused"));
            return false;
        }
        if (!(inObj instanceof Map<?, ?> in)) {
            LOGGER.error((Object) (NAME + ": the criteria context is not a map"));
            return false;
        }
        HttpServletRequest request = (HttpServletRequest) ((AttributeValue) in.get(HTTP_REQUEST)).getObjectValue();
        String clientId = in.get(CLIENT_ID) instanceof AttributeValue v ? v.getValue() : null;
        List<Map<String, Object>> issued;
        try {
            issued = IssuedDetailsCriterion.issued(in.get(ISSUED_DETAILS));
        } catch (RarModelException e) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, List.of(), "the details about to be issued could not"
                    + " be read (" + e.getMessage() + ")");
        }
        String bareRefresh = IssuedDetailsCriterion.bareRefreshOf(request, issued, with.redecideTypes().get());
        if (bareRefresh != null) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, REDECIDE, List.of(Map.of("type", bareRefresh)),
                    "a refresh without authorization_details of a grant holding " + bareRefresh + ", which "
                            + REDECIDE_SETTING + " sends back to be decided again");
        }
        boolean attested = hasHeader(request, ATTESTATION_HEADER) || hasHeader(request, ATTESTATION_POP_HEADER);
        if (state == Engine.DISABLED) {
            if (attested) {
                return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, issued,
                        "an attested request while ATTESTATION_AUTH is switched off: nothing here holds its ceiling");
            }
            return true;
        }
        Object published = request.getAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE);
        if (published instanceof Map<?, ?> verified) {
            if (clientId == null || !clientId.equals(verified.get("client_id"))) {
                return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, issued,
                        "the verified attestation is for another client than the one PingFederate authenticated");
            }
        } else if (attested) {
            // No filter verified this request: verify it here, as validateClientAttestation's own route does, which
            // publishes the context so that criterion reuses it rather than verifying twice.
            FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
            try {
                if (ClientAttestationUtils.verifyAtTheCriterion(in, request, clientId, with.issuerOf(), runtime.ignoreSslErrors(),
                        runtime.trustControllerHost(), runtime.trustControllerBaseUrl(), with.tokenEndpointBaseUrl(), with.resolver(),
                        with.subjectTokens()) == null) {
                    return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, issued, "the containment models could not be loaded");
                }
            } catch (Exception e) {
                return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, issued,
                        "the attestation did not verify at the criterion (" + e.getMessage() + ")");
            }
        } else if (ClientAttestationUtils.TOKEN_ENDPOINT_PATH.equals(ClientAttestationUtils.endpointPath(request))) {
            return IssuedDetailsCriterion.withoutAttestation(clientId, with.resolver());
        } else {
            // PingFederate also asks the mapping's criteria where the authorization endpoint resumes (seen on the rig,
            // 2026-09-30), and the front channel carries no attestation: details pushed at PAR were held there, and an
            // attestation-required client's details without PAR are refused by ClientAttestationAuth. The token request
            // that follows is decided at the token endpoint.
            return true;
        }
        RarModels models;
        try {
            models = with.models().get();
        } catch (IllegalStateException e) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, issued, e.getMessage());
        }
        Outcome outcome = IssuedDetailsCriterion.held(models, singleHeader(request, ATTESTATION_HEADER), issued);
        if (outcome != Outcome.WITHIN) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, outcome.reason(), issued,
                    "the details about to be issued are not within the client attestation's");
        }
        return true;
    }

    /**
     * A request with no attestation: {@code true} unless the client authenticates only with one, or its
     * {@code attestation_required} cannot be read.
     */
    static boolean withoutAttestation(String clientId, AttestationPolicyResolver resolver) {
        ClientAttestationPolicy client;
        try {
            client = resolver.policy(clientId);
        } catch (AttestationPolicyResolver.Unavailable e) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, UNCHECKABLE, List.of(),
                    "the client's attestation policy could not be read");
        }
        if (client.invalid() != null && ClientAttestationPolicy.REQUIRED.equals(client.invalid().property())) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, NOT_ATTESTED, List.of(),
                    "the client's " + ClientAttestationPolicy.REQUIRED + " cannot be read");
        }
        if (client.attestationRequired()) {
            return IssuedDetailsCriterion.refuse(CRITERION, clientId, NOT_ATTESTED, List.of(),
                    "the client has " + ClientAttestationPolicy.REQUIRED + "=true and presented no attestation");
        }
        return true;
    }

    /**
     * The first listed type a bare refresh would reissue, or null: the request is a refresh that sends no
     * {@code authorization_details}, and a detail about to be issued has a type in {@code listed}.
     */
    static String bareRefreshOf(HttpServletRequest request, List<Map<String, Object>> issued, Set<String> listed) {
        if (listed.isEmpty() || !REFRESH_GRANT.equals(request.getParameter("grant_type"))
                || present(request.getParameter(DETAILS_PARAMETER))) {
            return null;
        }
        for (Map<String, Object> detail : issued) {
            if (detail.get("type") instanceof String type && listed.contains(type)) {
                return type;
            }
        }
        return null;
    }

    /**
     * The details {@code context.OAuthAuthorizationDetails} holds: each of the attribute's object values, a map (as
     * PingFederate 13.1.3 gives them) or JSON text of one; none when the key is absent or holds nothing.
     *
     * @throws RarModelException for a value that is neither
     */
    static List<Map<String, Object>> issued(Object attribute) throws RarModelException {
        if (!(attribute instanceof AttributeValue value)) {
            return List.of();
        }
        List<Object> objects = new ArrayList<>();
        Iterable<?> all = value.getAllObjectValues();
        if (all != null) {
            for (Object o : all) {
                if (o != null) {
                    objects.add(o instanceof String text ? parsedObject(text) : o);
                }
            }
        }
        return IssuedDetailsCriterion.withoutMarkers(RarModels.details(objects));
    }

    private static Object parsedObject(String text) throws RarModelException {
        try {
            return Json.parse(text);
        } catch (IllegalArgumentException e) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "an issued detail is not JSON");
        }
    }

    /** What a check of issued details against a ceiling found. */
    public enum Outcome {
        /** Every issued detail is within the ceiling, or none is issued. */
        WITHIN(null),
        /** A detail is not within the ceiling. */
        EXCEEDS(IssuedDetailsCriterion.EXCEEDS),
        /** The question cannot be answered: a list the model refuses, or no attestation to read the ceiling from. */
        UNCHECKABLE(IssuedDetailsCriterion.UNCHECKABLE);

        private final String reason;

        Outcome(String reason) {
            this.reason = reason;
        }

        /** The event's failure reason; null for {@link #WITHIN}. */
        public String reason() {
            return this.reason;
        }
    }

    /**
     * Holds {@code issued} to the ceiling of {@code attestationJwt}, an attestation this request has already verified:
     * the model's strict {@link RarModels#contains}, the ceiling read from the attestation's payload by the model's own
     * reader, so its numbers are compared as the attester wrote them. An attestation without
     * {@code authorization_details} is an empty ceiling, as it is at the token gate: nothing is within it. Issued details
     * are taken without the {@code _principal_sub} and {@code _agent_id} markers. Never throws.
     */
    public static Outcome held(RarModels models, String attestationJwt, List<? extends Map<String, Object>> issued) {
        List<Map<String, Object>> candidate = IssuedDetailsCriterion.withoutMarkers(issued);
        if (candidate.isEmpty()) {
            return Outcome.WITHIN;
        }
        if (models == null || attestationJwt == null || attestationJwt.isBlank()) {
            return Outcome.UNCHECKABLE;
        }
        try {
            return models.contains(IssuedDetailsCriterion.ceilingOf(attestationJwt), candidate) ? Outcome.WITHIN : Outcome.EXCEEDS;
        } catch (RarModelException | RuntimeException e) {
            LOGGER.info((Object) ("issued authorization_details could not be held to the attestation: " + e.getMessage()));
            return Outcome.UNCHECKABLE;
        }
    }

    /** The attestation's {@code authorization_details}, read by the model's reader; empty when it has none. */
    static List<Map<String, Object>> ceilingOf(String attestationJwt) throws RarModelException {
        String[] parts = attestationJwt.split("\\.", -1);
        if (parts.length != 3) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the client attestation is not a compact JWS");
        }
        Object claims;
        try {
            claims = Json.parse(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the client attestation's claims could not be read");
        }
        if (!(claims instanceof Map<?, ?> set)) {
            throw new RarModelException(RarModelException.Reason.MALFORMED, "the client attestation's claims are not a JSON object");
        }
        return set.containsKey(DETAILS_PARAMETER) ? RarModels.details(set.get(DETAILS_PARAMETER)) : List.of();
    }

    /** Copies of the details without the markers. */
    static List<Map<String, Object>> withoutMarkers(List<? extends Map<String, Object>> details) {
        List<Map<String, Object>> out = new ArrayList<>(details.size());
        for (Map<String, Object> detail : details) {
            Map<String, Object> copy = new LinkedHashMap<>(detail);
            copy.keySet().removeAll(MARKERS);
            out.add(copy);
        }
        return out;
    }

    /**
     * The types of {@code details}, for an event: at most {@value #MAX_TYPES}, each cut at {@value #MAX_TYPE_LENGTH}
     * characters with anything outside printable ASCII replaced, comma-separated. A type is a category the server
     * registers, never a value.
     */
    public static String types(List<? extends Map<String, Object>> details) {
        Set<String> types = new LinkedHashSet<>();
        for (Map<String, Object> detail : details) {
            if (types.size() == MAX_TYPES) {
                break;
            }
            Object type = detail.get("type");
            if (type instanceof String s) {
                StringBuilder clean = new StringBuilder();
                for (int i = 0; i < Math.min(s.length(), MAX_TYPE_LENGTH); i++) {
                    char c = s.charAt(i);
                    clean.append(c > 0x20 && c < 0x7f && c != ',' ? c : '?');
                }
                types.add(clean.toString());
            }
        }
        return String.join(",", types);
    }

    /**
     * Records {@code attestation.issued.refused} and answers {@code false}.
     *
     * @param enforcer {@value #BELT} or {@value #CRITERION}
     * @param reason   why, the event's failure
     * @param details  the details refused, whose types the event names
     * @param log      one line for the log, naming no value
     */
    public static boolean refuse(String enforcer, String clientId, String reason, List<? extends Map<String, Object>> details,
            String log) {
        LOGGER.info((Object) (enforcer + ": refused client_id=" + com.pingidentity.ps.oidf.platform.events.LogSafe.value(clientId)
                + " [" + reason + "]: " + log));
        Events.event(ATTESTATION, ISSUED_REFUSED).failure(reason).subject(clientId).audit()
                .field("enforcer", enforcer).field("detail_types", IssuedDetailsCriterion.types(details)).emit();
        return false;
    }

    /** The request's one value of header {@code name}; null when absent; a repeated header is refused as unreadable. */
    static String singleHeader(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null || !values.hasMoreElements()) {
            return null;
        }
        String first = values.nextElement();
        return values.hasMoreElements() ? "" : first;
    }

    /** Whether the request carries header {@code name} with a value that is not blank, once or more. */
    static boolean hasHeader(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        while (values != null && values.hasMoreElements()) {
            if (present(values.nextElement())) {
                return true;
            }
        }
        return false;
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }
}
