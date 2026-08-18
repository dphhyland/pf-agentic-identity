package com.pingidentity.ps.oidf.jose;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;

/**
 * What this process is willing to fetch over HTTP, applied before any outbound request.
 *
 * <p>Federation resolution follows identifiers supplied by the caller: a client presenting a
 * {@code trust_chain} names its own leaf, and every {@code authority_hints} entry in it is another
 * URL to fetch. That makes the trust-chain path a request-forgery primitive reachable by anyone who
 * can reach the token endpoint - a chain whose leaf claims to be {@code http://169.254.169.254/...}
 * turns the AS into a fetcher for its own cloud metadata service. The chain is worthless (it will
 * never reach the anchor) but the fetch has already happened, and the response body would be read
 * into memory unbounded.
 *
 * <p>So: HTTPS only, no credentials in the URL, and no address that belongs to the infrastructure
 * rather than the internet. The address check resolves the host and rejects if <em>any</em> resolved
 * address is non-public - a name with both a public and a loopback record must not pass because the
 * first record happened to be public. Bodies are capped.
 *
 * <p>Operator-configured endpoints are exempt via {@link #trusting}: a trust controller on
 * {@code *.railway.internal}, a SPIRE agent on loopback, a bundle URL an administrator typed. Those
 * are configuration, not attacker input, and the distinction this class draws is exactly that. The
 * exemption is pinned to the configured <em>origin and path prefix</em>, not merely its host: the
 * same policy instance screens wholly caller-supplied identifiers (a trust chain names its own leaf),
 * so a host-only exemption would let a caller name {@code http://<that-host>:6379/...} and have the
 * scheme, port and address rules all waved through - an internal port scan with the operator's own
 * controller as the pivot. Residual: within an exempt origin and prefix the path is not constrained.
 *
 * <p>Residual: a name that resolves publicly here and privately when the connection is made (DNS
 * rebinding) is not addressed - that needs the check at socket level.
 */
public final class OutboundUrlPolicy {

    public static final String ALLOW_HTTP_ENV = "OIDF_FETCH_ALLOW_HTTP";
    public static final String ALLOW_PRIVATE_ENV = "OIDF_FETCH_ALLOW_PRIVATE_NETWORKS";
    public static final String HOST_ALLOWLIST_ENV = "OIDF_FETCH_HOST_ALLOWLIST";
    public static final String MAX_BODY_ENV = "OIDF_FETCH_MAX_BODY_BYTES";

    /** Entity statements and JWKS documents are small; 256 KiB is generous. */
    public static final long DEFAULT_MAX_BODY_BYTES = 256L * 1024L;

    private final boolean allowHttp;
    private final boolean allowPrivateNetworks;
    private final List<String> addressExemptHosts;
    private final List<ExemptEndpoint> exemptEndpoints;
    private final long maxBodyBytes;
    private final Function<String, InetAddress[]> resolver;

    private OutboundUrlPolicy(boolean allowHttp, boolean allowPrivateNetworks, List<String> addressExemptHosts,
            List<ExemptEndpoint> exemptEndpoints, long maxBodyBytes, Function<String, InetAddress[]> resolver) {
        this.allowHttp = allowHttp;
        this.allowPrivateNetworks = allowPrivateNetworks;
        this.addressExemptHosts = List.copyOf(addressExemptHosts);
        this.exemptEndpoints = List.copyOf(exemptEndpoints);
        this.maxBodyBytes = maxBodyBytes;
        this.resolver = resolver;
    }

    public static OutboundUrlPolicy fromEnvironment() {
        return from(System::getenv);
    }

    /** Test seam: build from a supplied environment lookup. */
    public static OutboundUrlPolicy from(Function<String, String> env) {
        Objects.requireNonNull(env, "env");
        return new OutboundUrlPolicy(
                Boolean.parseBoolean(env.apply(ALLOW_HTTP_ENV)),
                Boolean.parseBoolean(env.apply(ALLOW_PRIVATE_ENV)),
                csv(env.apply(HOST_ALLOWLIST_ENV)),
                List.<ExemptEndpoint>of(),
                parseLong(env.apply(MAX_BODY_ENV), DEFAULT_MAX_BODY_BYTES),
                OutboundUrlPolicy::resolveAll);
    }

    /**
     * No restrictions. For tests and for callers that have already established the URL is
     * operator-supplied; prefer {@link #trusting} so the exemption is scoped to specific hosts.
     */
    public static OutboundUrlPolicy permissive() {
        return new OutboundUrlPolicy(true, true, List.of(), List.<ExemptEndpoint>of(), Long.MAX_VALUE, OutboundUrlPolicy::resolveAll);
    }

    /** Test seam: same policy, but with host resolution stubbed. */
    public OutboundUrlPolicy withResolver(Function<String, InetAddress[]> stub) {
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.addressExemptHosts,
                this.exemptEndpoints, this.maxBodyBytes, Objects.requireNonNull(stub, "stub"));
    }

    /**
     * Returns a policy that additionally exempts the hosts of the given operator-configured URLs from
     * the scheme and address rules. Null/blank entries are ignored, so callers can pass optional
     * configuration straight through.
     */
    public OutboundUrlPolicy trusting(String... operatorConfiguredUrls) {
        List<ExemptEndpoint> exempt = new ArrayList<>(this.exemptEndpoints);
        for (String url : operatorConfiguredUrls) {
            ExemptEndpoint endpoint = ExemptEndpoint.of(url);
            if (endpoint != null && !exempt.contains(endpoint)) {
                exempt.add(endpoint);
            }
        }
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.addressExemptHosts,
                exempt, this.maxBodyBytes, this.resolver);
    }

    public long maxBodyBytes() {
        return this.maxBodyBytes;
    }

    /**
     * @return the parsed URI when the fetch is permitted
     * @throws IllegalArgumentException with a reason when it is not - the caller surfaces this as a
     *     rejected chain, never as a server error
     */
    public URI check(String url) {
        URI uri;
        try {
            uri = new URI(url);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("refusing to fetch a malformed URL: " + url, e);
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("refusing to fetch a URL with no host: " + url);
        }
        if (uri.getUserInfo() != null) {
            // Credentials in a federation identifier are never legitimate and would be sent onward.
            throw new IllegalArgumentException("refusing to fetch a URL carrying credentials: " + host);
        }
        if (isExemptEndpoint(uri)) {
            return uri;
        }
        if (!scheme.equals("https") && !(scheme.equals("http") && this.allowHttp)) {
            throw new IllegalArgumentException("refusing to fetch over " + (scheme.isEmpty() ? "(no scheme)" : scheme)
                    + " (https required; set " + ALLOW_HTTP_ENV + "=true for a plaintext dev endpoint): " + url);
        }
        // The allowlist EXEMPTS its hosts from the address rule; it is not an additional restriction.
        // Making it exclusive would mean naming one private SPIRE endpoint refused every public leaf
        // entity-configuration fetch, killing federation resolution process-wide.
        if (!this.allowPrivateNetworks && !addressExempt(host)) {
            requirePublicAddresses(host);
        }
        return uri;
    }

    private boolean isExemptEndpoint(URI uri) {
        for (ExemptEndpoint endpoint : this.exemptEndpoints) {
            if (endpoint.matches(uri)) {
                return true;
            }
        }
        return false;
    }

    /** Hosts an operator has declared may resolve to a non-public address. Suffix match on a label boundary. */
    private boolean addressExempt(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        for (String suffix : this.addressExemptHosts) {
            if (lower.equals(suffix) || lower.endsWith("." + suffix)) {
                return true;
            }
        }
        return false;
    }

    /** Rejects if ANY resolved address is non-public - one private record is enough to poison a name. */
    private void requirePublicAddresses(String host) {
        InetAddress[] addresses;
        try {
            addresses = this.resolver.apply(host);
        }
        catch (RuntimeException e) {
            throw new IllegalArgumentException("refusing to fetch " + host + ": cannot resolve it", e);
        }
        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("refusing to fetch " + host + ": resolves to no address");
        }
        for (InetAddress address : addresses) {
            if (!isPublic(address)) {
                throw new IllegalArgumentException("refusing to fetch " + host + ": resolves to the non-public address "
                        + address.getHostAddress() + " (name the host in " + HOST_ALLOWLIST_ENV
                        + " if it is a legitimate internal endpoint, or set " + ALLOW_PRIVATE_ENV
                        + "=true to disable this check entirely)");
            }
        }
    }

    private static boolean isPublic(InetAddress address) {
        if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isAnyLocalAddress() || address.isMulticastAddress()
                || address.isLoopbackAddress()) {
            return false;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF, second = bytes[1] & 0xFF;
            // 100.64/10 carrier-grade NAT: not site-local by the JDK's definition, still not the internet.
            if (first == 100 && second >= 64 && second <= 127) {
                return false;
            }
            // 192.0.0/24 IETF protocol assignments, and 198.18/15 benchmarking.
            if (first == 192 && second == 0 && (bytes[2] & 0xFF) == 0) {
                return false;
            }
            if (first == 198 && (second == 18 || second == 19)) {
                return false;
            }
        } else if (bytes.length == 16) {
            // fc00::/7 unique local addresses - the IPv6 equivalent of RFC 1918.
            if ((bytes[0] & 0xFE) == 0xFC) {
                return false;
            }
        }
        return true;
    }

    private static InetAddress[] resolveAll(String host) {
        try {
            return InetAddress.getAllByName(host);
        }
        catch (UnknownHostException e) {
            throw new IllegalArgumentException("cannot resolve " + host, e);
        }
    }

    /** An operator-configured endpoint: scheme, host, port and path prefix must all match. */
    private static final class ExemptEndpoint {
        private final String scheme;
        private final String host;
        private final int port;
        private final String pathPrefix;

        private ExemptEndpoint(String scheme, String host, int port, String pathPrefix) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.pathPrefix = pathPrefix;
        }

        static ExemptEndpoint of(String url) {
            if (url == null || url.isBlank()) {
                return null;
            }
            try {
                URI uri = new URI(url.trim());
                String host = uri.getHost();
                String scheme = uri.getScheme();
                if (host == null || host.isBlank() || scheme == null) {
                    return null;
                }
                String path = uri.getPath() == null ? "" : uri.getPath();
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                }
                return new ExemptEndpoint(scheme.toLowerCase(Locale.ROOT), host.toLowerCase(Locale.ROOT),
                        defaultedPort(scheme, uri.getPort()), path);
            }
            catch (Exception e) {
                return null;
            }
        }

        boolean matches(URI uri) {
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            if (!this.scheme.equals(scheme) || !this.host.equals(host)
                    || this.port != defaultedPort(scheme, uri.getPort())) {
                return false;
            }
            String path = uri.getPath() == null ? "" : uri.getPath();
            return this.pathPrefix.isEmpty() || path.equals(this.pathPrefix) || path.startsWith(this.pathPrefix + "/");
        }

        private static int defaultedPort(String scheme, int port) {
            if (port != -1) {
                return port;
            }
            return "https".equalsIgnoreCase(scheme) ? 443 : "http".equalsIgnoreCase(scheme) ? 80 : -1;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof ExemptEndpoint)) {
                return false;
            }
            ExemptEndpoint other = (ExemptEndpoint) o;
            return this.port == other.port && this.scheme.equals(other.scheme)
                    && this.host.equals(other.host) && this.pathPrefix.equals(other.pathPrefix);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.scheme, this.host, this.port, this.pathPrefix);
        }
    }

    private static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        try {
            String host = new URI(url.trim()).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        }
        catch (Exception e) {
            return null;
        }
    }

    private static List<String> csv(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    private static long parseLong(String value, long fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            long parsed = Long.parseLong(value.trim());
            return parsed > 0 ? parsed : fallback;
        }
        catch (NumberFormatException e) {
            return fallback;
        }
    }
}
