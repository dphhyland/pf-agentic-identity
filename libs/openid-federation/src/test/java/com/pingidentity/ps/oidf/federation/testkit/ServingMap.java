/*
 * An in-memory HTTP GET seam that serves a federation.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import com.pingidentity.ps.oidf.jose.HttpGetClient;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Answers the {@link HttpGetClient} seam from a map, the way a federation's HTTPS endpoints would.
 *
 * <p>Entity Configurations are served at {@code <entity id>/.well-known/openid-federation}. Subordinate
 * Statements are served at a fetch endpoint keyed by the {@code sub} query parameter alone, so the kit
 * answers a fetch whether or not the caller also sends {@code iss}. Exact-URL entries ({@link #put}),
 * queued answers ({@link #sequence}) and failures ({@link #failing}) take precedence. Every request is
 * recorded.
 */
public final class ServingMap implements HttpGetClient {

    /** One request the seam received. */
    public record Request(String url, String accept) {
    }

    private final Map<String, String> exact = new ConcurrentHashMap<>();
    private final Map<String, Deque<String>> sequences = new ConcurrentHashMap<>();
    private final Map<String, Exception> failures = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> fetchEndpoints = new ConcurrentHashMap<>();
    private final List<Request> requests = java.util.Collections.synchronizedList(new ArrayList<>());

    /** Serves {@code body} at exactly {@code url}. */
    public ServingMap put(String url, String body) {
        this.exact.put(url, body);
        return this;
    }

    /** Serves {@code entityConfiguration} at {@code <entityId>/.well-known/openid-federation}. */
    public ServingMap entityConfiguration(String entityId, String entityConfiguration) {
        return this.put(stripSlash(entityId) + "/.well-known/openid-federation", entityConfiguration);
    }

    /** Serves {@code statement} from {@code fetchEndpoint} for {@code sub}, whatever else the query carries. */
    public ServingMap subordinateStatement(String fetchEndpoint, String sub, String statement) {
        this.fetchEndpoints.computeIfAbsent(fetchEndpoint, k -> new ConcurrentHashMap<>()).put(sub, statement);
        return this;
    }

    /** Answers {@code url} with each body in turn, then with the last one forever. */
    public ServingMap sequence(String url, String... bodies) {
        this.sequences.put(url, new ArrayDeque<>(List.of(bodies)));
        return this;
    }

    /** Fails every request for {@code url} with {@code failure}. */
    public ServingMap failing(String url, Exception failure) {
        this.failures.put(url, failure);
        return this;
    }

    public ServingMap remove(String url) {
        this.exact.remove(url);
        return this;
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        this.requests.add(new Request(url, acceptHeader));
        Exception failure = this.failures.get(url);
        if (failure != null) {
            throw failure;
        }
        Deque<String> queued = this.sequences.get(url);
        if (queued != null && !queued.isEmpty()) {
            return queued.size() > 1 ? queued.pollFirst() : queued.peekFirst();
        }
        String body = this.exact.get(url);
        if (body != null) {
            return body;
        }
        URI uri = URI.create(url);
        String base = uri.getScheme() + "://" + uri.getRawAuthority() + (uri.getRawPath() == null ? "" : uri.getRawPath());
        Map<String, String> bySub = this.fetchEndpoints.get(base);
        if (bySub != null) {
            String sub = query(uri).get("sub");
            if (sub != null && bySub.containsKey(sub)) {
                return bySub.get(sub);
            }
        }
        throw new IllegalArgumentException("GET failed: " + url + " status=404");
    }

    /** Every request received, in order. */
    public List<Request> requests() {
        synchronized (this.requests) {
            return List.copyOf(this.requests);
        }
    }

    /** How many requests went to exactly {@code url}. */
    public long hits(String url) {
        synchronized (this.requests) {
            return this.requests.stream().filter(r -> r.url().equals(url)).count();
        }
    }

    /** How many requests went to a URL starting with {@code prefix}. */
    public long hitsStartingWith(String prefix) {
        synchronized (this.requests) {
            return this.requests.stream().filter(r -> r.url().startsWith(prefix)).count();
        }
    }

    public void clearRequests() {
        this.requests.clear();
    }

    static Map<String, String> query(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return params;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.putIfAbsent(name, value);
        }
        return params;
    }

    static String stripSlash(String id) {
        return id.endsWith("/") ? id.substring(0, id.length() - 1) : id;
    }
}
