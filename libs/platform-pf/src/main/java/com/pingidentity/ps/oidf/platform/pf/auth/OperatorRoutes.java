/*
 * The route table an operator surface fills: method and path to route.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Which {@link OperatorRoute} a request is, by its method and path within the surface (plan item S8b fills one table
 * per surface). The first entry that matches wins. A path ending in {@code /*} matches that prefix and anything under
 * it; any other path matches only itself. The method is compared exactly - RFC 9110 §9.1: "The method token is
 * case-sensitive" - and {@code *} matches any. A request no entry matches has no route, and the surface answers it
 * 404 or 405 before any token is looked at.
 */
public final class OperatorRoutes {
    private record Entry(String method, String path, boolean prefix, OperatorRoute route) {
    }

    private final List<Entry> entries;

    private OperatorRoutes(List<Entry> entries) {
        this.entries = List.copyOf(entries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The route {@code method} and {@code path} are, if any. */
    public Optional<OperatorRoute> match(String method, String path) {
        if (method == null || path == null) {
            return Optional.empty();
        }
        for (Entry e : this.entries) {
            boolean methodMatches = "*".equals(e.method()) || e.method().equals(method);
            boolean pathMatches = e.prefix()
                    ? path.equals(e.path()) || path.startsWith(e.path() + "/")
                    : path.equals(e.path());
            if (methodMatches && pathMatches) {
                return Optional.of(e.route());
            }
        }
        return Optional.empty();
    }

    /** Builds an {@link OperatorRoutes}. */
    public static final class Builder {
        private final List<Entry> entries = new ArrayList<>();

        private Builder() {
        }

        /** Adds {@code method} {@code path} as {@code route}; see the class for the path's form. */
        public Builder route(String method, String path, OperatorRoute route) {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(route, "route");
            if (path == null || !path.startsWith("/")) {
                throw new IllegalArgumentException("a route's path starts with '/', not " + path);
            }
            boolean prefix = path.endsWith("/*");
            this.entries.add(new Entry(method, prefix ? path.substring(0, path.length() - 2) : path, prefix, route));
            return this;
        }

        public OperatorRoutes build() {
            return new OperatorRoutes(this.entries);
        }
    }
}
