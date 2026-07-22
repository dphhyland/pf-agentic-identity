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

    public static DecisionResponse fromJson(String body, ObjectMapper mapper) throws IOException {
        JsonNode root = mapper.readTree(body == null ? "{}" : body);
        String decision = root.hasNonNull("decision") ? root.get("decision").asText() : null;
        Boolean authorised = root.hasNonNull("authorised") ? root.get("authorised").asBoolean() : null;

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
}
