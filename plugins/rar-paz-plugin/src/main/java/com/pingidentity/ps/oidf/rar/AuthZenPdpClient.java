/*
 * Calls an OpenID AuthZEN 1.0 PDP (/access/v1/evaluation) and maps the response into DecisionResponse.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The AuthZEN dialect of {@link PdpClient}. POSTs the {@link AuthZenRequestBuilder} evaluation body to
 * the configured PDP URL (point it at the PDP's {@code /access/v1/evaluation}) with the same optional
 * shared-secret header as the governance-engine dialect, reads the status the way {@link PdpResponses}
 * says, and maps the response:
 *
 * <ul>
 *   <li>{@code decision} (boolean, required) → PERMIT / DENY.</li>
 *   <li>{@code context} → {@link DecisionResponse.Statement}s, so AuthZEN enrichment flows through the
 *       same {@link StatementApplier} pipeline as governance-engine statements:
 *     <ul>
 *       <li>{@code context.statements: [{name, payload}…]} is the symmetric form;</li>
 *       <li>every other context member becomes one statement — {@code context.access.limits} lands at
 *           {@code detail["access"]["limits"]} via the applier's dot-path merge;</li>
 *       <li>{@code id}, {@code reason_admin}, and {@code reason_user} are display/ops metadata, not
 *           enrichment — logged upstream via {@link DecisionResponse#getRawBody()}, never merged.</li>
 *     </ul>
 *     Both forms are held to the {@link ContextAllowList} for the detail's type: a member the list does not name is
 *     dropped and counted, never merged (plan item H-RAR-1, finding F-0065).
 *   </li>
 * </ul>
 */
public final class AuthZenPdpClient implements PdpClient {

    /** AuthZEN response-context members that are metadata, not detail enrichment. */
    private static final Set<String> NON_ENRICHMENT = Set.of("id", "reason_admin", "reason_user");

    private final GovernanceEngineConfig config;
    private final HttpTransport transport;
    private final AuthZenRequestBuilder requestBuilder;
    private final ObjectMapper mapper;
    private final String batchUrl;
    private final ContextAllowList allowList;

    public AuthZenPdpClient(GovernanceEngineConfig config, HttpTransport transport,
                            AuthZenRequestBuilder requestBuilder, ObjectMapper mapper) {
        this(config, transport, requestBuilder, mapper, null);
    }

    /** The default context allow-list over the built-in models: what {@code configure} uses for a blank field. */
    public AuthZenPdpClient(GovernanceEngineConfig config, HttpTransport transport,
                            AuthZenRequestBuilder requestBuilder, ObjectMapper mapper, String batchUrl) {
        this(config, transport, requestBuilder, mapper, batchUrl, ContextAllowList.of(null,
                ModelGate.of(com.pingidentity.ps.oidf.rar.model.RarModels.builtIn())::declaredMembers));
    }

    /**
     * @param batchUrl  the PDP's Access Evaluations endpoint ({@code /access/v1/evaluations}), or {@code null} for none:
     *                  then every detail is its own evaluation call
     * @param allowList the context members each type may take from an answer
     */
    AuthZenPdpClient(GovernanceEngineConfig config, HttpTransport transport, AuthZenRequestBuilder requestBuilder,
                     ObjectMapper mapper, String batchUrl, ContextAllowList allowList) {
        this.allowList = allowList;
        this.config = config;
        this.transport = transport;
        this.requestBuilder = requestBuilder;
        this.mapper = mapper;
        this.batchUrl = batchUrl == null || batchUrl.isBlank() ? null : batchUrl.trim();
    }

    /** Whether a batch URL is configured, so {@link #decideAll} may be called. */
    boolean batches() {
        return batchUrl != null;
    }

    String batchUrl() {
        return batchUrl;
    }

    @Override
    public DecisionResponse decide(String type, Map<String, Object> detail, AttestationSubject subject,
                                   String resourceOwner, String fallbackClientId, String principalSource) throws IOException {
        Map<String, Object> request = requestBuilder.build(type, detail, subject, resourceOwner, fallbackClientId, principalSource);
        String body = mapper.writeValueAsString(request);
        HttpTransport.Response response = transport.post(config.getPdpUrl(), body, headers());
        String answer = PdpResponses.bodyOf(response, "AuthZEN PDP");
        return parse(PdpResponses.jsonObjectOf(answer, mapper, "AuthZEN"), answer, type);
    }

    /**
     * Every ask in one Access Evaluations call (OpenID AuthZEN Authorization API 1.0, section 7), the answers in the
     * order asked.
     *
     * <p>The request is {@code {"evaluations": [...]}}, each element the same evaluation {@link #decide} would send
     * for that detail, with no top-level defaults and no {@code options}: section 7.1 lets the top-level keys be
     * omitted "if the evaluations array is present, contains one or more objects, and every object in the evaluations
     * array contains the respective top-level key", and section 7.1.2.1 makes {@code execute_all} the default, which
     * is the only semantic that answers every evaluation.
     *
     * <p>The answer is read as strictly as a single one: 429 and 502-504 are the PDP unavailable, any other non-2xx
     * and a non-JSON body are refusals ({@link PdpResponses}). Then section 7.2: "an evaluations array that lists the
     * decisions in the same order they were provided in the evaluations array in the request", each typed as a
     * Decision. A body with no {@code evaluations} array, with more or fewer decisions than were asked, or with one
     * that is not an object carrying a boolean {@code decision}, is malformed and refused as a whole - an
     * {@link IOException} that is not {@link PdpUnavailableException}, so it fails closed and never trips the
     * breaker. A top-level {@code decision} is ignored, as section 7.2 allows ("If present, it can be ignored by the
     * PEP"). Position is the only correlation AuthZEN 1.0 gives: a PDP that returned the right number of decisions in
     * another order cannot be told from one that did not (finding F-0290).
     */
    List<DecisionResponse> decideAll(List<PdpDecisions.Ask> asks) throws IOException {
        if (batchUrl == null) {
            throw new IllegalStateException("no AuthZEN batch URL is configured");
        }
        List<Object> evaluations = new ArrayList<>(asks.size());
        for (PdpDecisions.Ask ask : asks) {
            evaluations.add(requestBuilder.build(ask.type(), ask.detail(), ask.subject(), ask.owner(), ask.clientId(),
                    ask.source()));
        }
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("evaluations", evaluations);
        String body = mapper.writeValueAsString(request);
        HttpTransport.Response response = transport.post(batchUrl, body, headers());
        String answer = PdpResponses.bodyOf(response, "AuthZEN PDP (evaluations)");
        List<String> types = new ArrayList<>(asks.size());
        for (PdpDecisions.Ask ask : asks) {
            types.add(ask.type());
        }
        return parseAll(PdpResponses.jsonObjectOf(answer, mapper, "AuthZEN evaluations"), answer, types);
    }

    /**
     * Section 7.2's shape, exactly as many decisions as {@code types} long, each read as {@link #decide} reads one, for
     * the type asked in its place.
     */
    List<DecisionResponse> parseAll(JsonNode root, String body, List<String> types) throws IOException {
        int expected = types.size();
        JsonNode array = root.path("evaluations");
        if (!array.isArray()) {
            throw new IOException("AuthZEN evaluations response has no 'evaluations' array: " + PdpResponses.excerpt(body));
        }
        if (array.size() != expected) {
            throw new IOException("AuthZEN evaluations response answers " + array.size() + " of the " + expected
                    + " evaluations asked, so no answer can be matched to its request: " + PdpResponses.excerpt(body));
        }
        List<DecisionResponse> decisions = new ArrayList<>(expected);
        for (int i = 0; i < expected; i++) {
            JsonNode element = array.get(i);
            if (!element.isObject()) {
                throw new IOException("AuthZEN evaluations response element " + i + " is not a decision object: "
                        + PdpResponses.excerpt(body));
            }
            decisions.add(parse(element, element.toString(), types.get(i)));
        }
        return decisions;
    }

    private Map<String, String> headers() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        if (config.getSecretHeader() != null && config.getSecret() != null && !config.getSecret().isEmpty()) {
            headers.put(config.getSecretHeader(), config.getSecret());
        }
        return headers;
    }

    /**
     * A decision with no boolean {@code decision} is refused: a PDP that answered, not one that permitted. The context's
     * statements are those the allow-list names for {@code type}.
     */
    private DecisionResponse parse(JsonNode root, String body, String type) throws IOException {
        boolean permit = decisionOf(root, body);

        List<DecisionResponse.Statement> symmetric = new ArrayList<>();
        List<DecisionResponse.Statement> members = new ArrayList<>();
        JsonNode context = root.path("context");
        if (context.isObject()) {
            JsonNode arr = context.path("statements");
            if (arr.isArray()) {
                for (JsonNode n : arr) {
                    String name = n.path("name").isMissingNode() ? null : n.path("name").asText(null);
                    JsonNode payloadNode = n.path("payload");
                    Object payload = payloadNode.isMissingNode() || payloadNode.isNull() ? null
                            : payloadNode.isValueNode() ? payloadNode.asText()
                            : mapper.convertValue(payloadNode, Object.class);
                    symmetric.add(new DecisionResponse.Statement(name, payload));
                }
            }
            for (Iterator<Map.Entry<String, JsonNode>> it = context.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> e = it.next();
                if ("statements".equals(e.getKey()) || NON_ENRICHMENT.contains(e.getKey())) {
                    continue;
                }
                JsonNode v = e.getValue();
                Object payload = v.isNull() ? null
                        : v.isValueNode() ? v.asText()
                        : mapper.convertValue(v, Object.class);
                members.add(new DecisionResponse.Statement(e.getKey(), payload));
            }
        }
        List<DecisionResponse.Statement> statements = new ArrayList<>(
                allowList.filter(type, symmetric, ContextAllowList.FORM_STATEMENT));
        statements.addAll(allowList.filter(type, members, ContextAllowList.FORM_MEMBER));
        return new DecisionResponse(permit ? "PERMIT" : "DENY", permit, statements, body);
    }

    /**
     * AuthZEN 1.0's {@code decision}: a JSON boolean, required. A string {@code "true"}, a number or no member
     * at all is refused rather than read as anything.
     */
    static boolean decisionOf(JsonNode root, String body) throws IOException {
        JsonNode decision = root.path("decision");
        if (!decision.isBoolean()) {
            throw new IOException("AuthZEN response has no boolean 'decision': " + PdpResponses.excerpt(body));
        }
        return decision.booleanValue();
    }
}
