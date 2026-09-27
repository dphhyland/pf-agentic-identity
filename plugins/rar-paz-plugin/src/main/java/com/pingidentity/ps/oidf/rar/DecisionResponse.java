/*
 * Parsed governance-engine decision response.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The governance-engine decision response: {@code decision} (PERMIT/DENY/NOT_APPLICABLE/INDETERMINATE),
 * a boolean {@code authorised}, and any {@code statements} (obligations / enrichment).
 *
 * <p>Unlike the reference plugin — which read only {@code statements} and so could never actually deny —
 * {@link #isPermit()} treats the request as authorized only on an explicit permit.
 */
public final class DecisionResponse {

    /** A single policy statement (obligation / advice / enrichment) returned by the engine. */
    public static final class Statement {
        private final String name;
        private final Object payload;

        public Statement(String name, Object payload) {
            this.name = name;
            this.payload = payload;
        }

        public String getName() { return name; }
        public Object getPayload() { return payload; }
    }

    private final String decision;
    private final Boolean authorised;
    private final List<Statement> statements;
    private final String rawBody;

    public DecisionResponse(String decision, Boolean authorised, List<Statement> statements, String rawBody) {
        this.decision = decision;
        this.authorised = authorised;
        this.statements = statements == null ? List.of() : statements;
        this.rawBody = rawBody;
    }

    public String getDecision() { return decision; }
    public Boolean getAuthorised() { return authorised; }
    public List<Statement> getStatements() { return statements; }
    public String getRawBody() { return rawBody; }

    /**
     * @return {@code true} only when the engine authorized the request: the explicit {@code authorised}
     *         boolean when present, otherwise a {@code decision} of {@code PERMIT}.
     */
    public boolean isPermit() {
        if (authorised != null) {
            return authorised;
        }
        return "PERMIT".equalsIgnoreCase(decision);
    }

    /**
     * A body that is not a JSON object is refused ({@link PdpResponses#jsonObjectOf}): a malformed answer is not a
     * permit. So is a {@code decision} that is not a string and an {@code authorised} that is not a boolean.
     */
    public static DecisionResponse fromJson(String body, ObjectMapper mapper) throws IOException {
        JsonNode root = PdpResponses.jsonObjectOf(body, mapper, "governance engine");
        String decision = decisionOf(root, body);
        Boolean authorised = authorisedOf(root, body);

        List<Statement> statements = new ArrayList<>();
        JsonNode arr = root.path("statements");
        if (arr.isArray()) {
            for (JsonNode n : arr) {
                String name = n.path("name").isMissingNode() ? null : n.path("name").asText(null);
                JsonNode payloadNode = n.path("payload");
                Object payload = payloadNode.isMissingNode() || payloadNode.isNull() ? null
                        : payloadNode.isValueNode() ? payloadNode.asText()
                        : mapper.convertValue(payloadNode, Object.class);
                statements.add(new Statement(name, payload));
            }
        }
        return new DecisionResponse(decision, authorised, statements, body);
    }

    /** {@code decision}, a JSON string, or {@code null} when absent or null. A number or an array is refused, not read as text. */
    static String decisionOf(JsonNode root, String body) throws IOException {
        JsonNode decision = root.path("decision");
        if (decision.isMissingNode() || decision.isNull()) {
            return null;
        }
        if (!decision.isTextual()) {
            throw new IOException("governance engine 'decision' is not a string: " + PdpResponses.excerpt(body));
        }
        return decision.textValue();
    }

    /**
     * {@code authorised}, a JSON boolean, or {@code null} when absent or null. A string {@code "true"} or a number
     * is refused: Jackson's {@code asBoolean} would read both as a permit.
     */
    static Boolean authorisedOf(JsonNode root, String body) throws IOException {
        JsonNode authorised = root.path("authorised");
        if (authorised.isMissingNode() || authorised.isNull()) {
            return null;
        }
        if (!authorised.isBoolean()) {
            throw new IOException("governance engine 'authorised' is not a boolean: " + PdpResponses.excerpt(body));
        }
        return authorised.booleanValue();
    }
}
