/*
 * Decisions kept a while.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;

/**
 * Keeps each decision - permit or denial - for {@code ttl}, keyed on the request less what is particular to one request
 * (its tracking id, the caller's address). No decision is never kept: the next request asks again.
 */
public final class CachingPolicyDecisionPoint implements FederationPolicyDecisionPoint {
    private static final int MEMORY = 1024;

    private record Kept(PolicyDecision decision, long until) {
    }

    private final FederationPolicyDecisionPoint delegate;
    private final Duration ttl;
    private final Clock clock;
    private final Map<String, Kept> kept = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Kept> eldest) {
            return this.size() > MEMORY;
        }
    });

    public CachingPolicyDecisionPoint(FederationPolicyDecisionPoint delegate, Duration ttl, Clock clock) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public PolicyDecision decide(PolicyDecisionRequest request) throws PolicyDecisionException {
        String key = key(request);
        long now = this.clock.millis();
        Kept found = this.kept.get(key);
        if (found != null && now < found.until()) {
            return found.decision();
        }
        PolicyDecision decision = this.delegate.decide(request);
        this.kept.put(key, new Kept(decision, now + this.ttl.toMillis()));
        return decision;
    }

    private static String key(PolicyDecisionRequest request) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(JsonUtil.toJson(request.cacheKey()).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }
}
