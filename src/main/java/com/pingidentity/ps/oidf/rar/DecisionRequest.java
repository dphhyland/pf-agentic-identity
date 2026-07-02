/*
 * The decision request sent to the PingAuthorize governance engine.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The native governance-engine "JSON API" request shape:
 * {@code { "domain", "service", "action", "attributes" }}.
 */
public final class DecisionRequest {
    private final String domain;
    private final String service;
    private final String action;
    private final Map<String, Object> attributes;

    public DecisionRequest(String domain, String service, String action, Map<String, Object> attributes) {
        this.domain = domain;
        this.service = service;
        this.action = action;
        this.attributes = attributes == null ? new LinkedHashMap<>() : attributes;
    }

    public String getDomain() { return domain; }
    public String getService() { return service; }
    public String getAction() { return action; }
    public Map<String, Object> getAttributes() { return attributes; }

    /** Ordered map ready for JSON serialization. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("domain", domain);
        m.put("service", service);
        m.put("action", action);
        m.put("attributes", attributes);
        return m;
    }
}
