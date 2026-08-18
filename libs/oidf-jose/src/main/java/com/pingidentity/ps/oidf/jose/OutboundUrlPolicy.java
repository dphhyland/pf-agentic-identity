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
 * are configuration, not attacker input, and the distinction this class draws is exactly that.
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
    private final List<String> hostAllowlist;
    private final List<String> exemptHosts;
    private final long maxBodyBytes;
    private final Function<String, InetAddress[]> resolver;

    private OutboundUrlPolicy(boolean allowHttp, boolean allowPrivateNetworks, List<String> hostAllowlist,
            List<String> exemptHosts, long maxBodyBytes, Function<String, InetAddress[]> resolver) {
        this.allowHttp = allowHttp;
        this.allowPrivateNetworks = allowPrivateNetworks;
        this.hostAllowlist = List.copyOf(hostAllowlist);
        this.exemptHosts = List.copyOf(exemptHosts);
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
                List.of(),
                parseLong(env.apply(MAX_BODY_ENV), DEFAULT_MAX_BODY_BYTES),
                OutboundUrlPolicy::resolveAll);
    }

    /**
     * No restrictions. For tests and for callers that have already established the URL is
     * operator-supplied; prefer {@link #trusting} so the exemption is scoped to specific hosts.
     */
    public static OutboundUrlPolicy permissive() {
        return new OutboundUrlPolicy(true, true, List.of(), List.of(), Long.MAX_VALUE, OutboundUrlPolicy::resolveAll);
    }

    /** Test seam: same policy, but with host resolution stubbed. */
    public OutboundUrlPolicy withResolver(Function<String, InetAddress[]> stub) {
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.hostAllowlist,
                this.exemptHosts, this.maxBodyBytes, Objects.requireNonNull(stub, "stub"));
    }

    /**
     * Returns a policy that additionally exempts the hosts of the given operator-configured URLs from
     * the scheme and address rules. Null/blank entries are ignored, so callers can pass optional
     * configuration straight through.
     */
    public OutboundUrlPolicy trusting(String... operatorConfiguredUrls) {
        List<String> exempt = new ArrayList<>(this.exemptHosts);
        for (String url : operatorConfiguredUrls) {
            String host = hostOf(url);
            if (host != null && !exempt.contains(host)) {
                exempt.add(host);
            }
        }
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.hostAllowlist,
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
        boolean exempt = this.exemptHosts.contains(host.toLowerCase(Locale.ROOT));
        if (!exempt) {
            if (!scheme.equals("https") && !(scheme.equals("http") && this.allowHttp)) {
                throw new IllegalArgumentException("refusing to fetch over " + (scheme.isEmpty() ? "(no scheme)" : scheme)
                        + " (https required; set " + ALLOW_HTTP_ENV + "=true for a plaintext dev endpoint): " + url);
            }
            if (!this.hostAllowlist.isEmpty() && !allowlisted(host)) {
                throw new IllegalArgumentException("refusing to fetch " + host + ": not in " + HOST_ALLOWLIST_ENV);
            }
            if (!this.allowPrivateNetworks) {
                requirePublicAddresses(host);
            }
        }
        return uri;
    }

    private boolean allowlisted(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        for (String suffix : this.hostAllowlist) {
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
                        + address.getHostAddress() + " (set " + ALLOW_PRIVATE_ENV
                        + "=true, or name the host in " + HOST_ALLOWLIST_ENV + ", if that is intended)");
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
