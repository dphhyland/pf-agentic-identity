/*
 * Calls the PingAuthorize governance-engine decision API and parses the decision.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sends a {@link DecisionRequest} to the governance engine (shared-secret header auth) and returns the parsed
 * {@link DecisionResponse}. A non-2xx status is a transport error and throws; the permit/deny call is left to
 * {@link DecisionResponse#isPermit()} so the caller decides how to enforce it.
 */
public final class GovernanceEngineClient {

    private final GovernanceEngineConfig config;
    private final HttpTransport transport;
    private final DecisionRequestBuilder requestBuilder;
    private final ObjectMapper mapper;

    public GovernanceEngineClient(GovernanceEngineConfig config, HttpTransport transport,
                                  DecisionRequestBuilder requestBuilder, ObjectMapper mapper) {
        this.config = config;
        this.transport = transport;
        this.requestBuilder = requestBuilder;
        this.mapper = mapper;
    }

    public DecisionResponse decide(String type, Map<String, Object> detail, AttestationSubject subject, String fallbackClientId) throws IOException {
        return decide(requestBuilder.build(type, detail, subject, fallbackClientId));
    }

    public DecisionResponse decide(DecisionRequest request) throws IOException {
        String body = mapper.writeValueAsString(request.toMap());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        if (config.getSecretHeader() != null && config.getSecret() != null && !config.getSecret().isEmpty()) {
            headers.put(config.getSecretHeader(), config.getSecret());
        }
        HttpTransport.Response response = transport.post(config.getPdpUrl(), body, headers);
        if (response.status() < 200 || response.status() >= 300) {
            throw new IOException("governance engine returned HTTP " + response.status() + ": " + response.body());
        }
        return DecisionResponse.fromJson(response.body(), mapper);
    }
}
