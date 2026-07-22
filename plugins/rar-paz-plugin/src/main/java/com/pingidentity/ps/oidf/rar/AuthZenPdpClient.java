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
 * shared-secret header as the governance-engine dialect, and maps the response:
 *
 * <ul>
 *   <li>{@code decision} (boolean, required) → PERMIT / DENY.</li>
 *   <li>{@code context} → {@link DecisionResponse.Statement}s, so AuthZEN enrichment flows through the
 *       same {@link StatementApplier} pipeline as governance-engine statements:
 *     <ul>
 *       <li>{@code context.statements: [{name, payload}…]} is taken verbatim (the symmetric form);</li>
 *       <li>every other context member becomes one statement — {@code context.access.limits} lands at
 *           {@code detail["access"]["limits"]} via the applier's dot-path merge;</li>
 *       <li>{@code id}, {@code reason_admin}, and {@code reason_user} are display/ops metadata, not
 *           enrichment — logged upstream via {@link DecisionResponse#getRawBody()}, never merged.</li>
 *     </ul>
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

    public AuthZenPdpClient(GovernanceEngineConfig config, HttpTransport transport,
                            AuthZenRequestBuilder requestBuilder, ObjectMapper mapper) {
        this.config = config;
        this.transport = transport;
        this.requestBuilder = requestBuilder;
        this.mapper = mapper;
    }

    @Override
    public DecisionResponse decide(String type, Map<String, Object> detail, AttestationSubject subject,
                                   String resourceOwner, String fallbackClientId) throws IOException {
        Map<String, Object> request = requestBuilder.build(type, detail, subject, resourceOwner, fallbackClientId);
        String body = mapper.writeValueAsString(request);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        if (config.getSecretHeader() != null && config.getSecret() != null && !config.getSecret().isEmpty()) {
            headers.put(config.getSecretHeader(), config.getSecret());
        }
        HttpTransport.Response response = transport.post(config.getPdpUrl(), body, headers);
        if (response.status() < 200 || response.status() >= 300) {
            throw new IOException("AuthZEN PDP returned HTTP " + response.status() + ": " + response.body());
        }
        return parse(response.body());
    }

    private DecisionResponse parse(String body) throws IOException {
        JsonNode root = mapper.readTree(body == null ? "{}" : body);
        if (!root.path("decision").isBoolean()) {
            throw new IOException("AuthZEN response has no boolean 'decision': " + body);
        }
        boolean permit = root.get("decision").asBoolean();

        List<DecisionResponse.Statement> statements = new ArrayList<>();
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
                    statements.add(new DecisionResponse.Statement(name, payload));
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
                statements.add(new DecisionResponse.Statement(e.getKey(), payload));
            }
        }
        return new DecisionResponse(permit ? "PERMIT" : "DENY", permit, statements, body);
    }
}
