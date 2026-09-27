/*
 * Which URLs this process may fetch, and which addresses it may connect to for them.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * The rules an outbound request passes before a socket is opened, carried over from oidf-jose's
 * {@code OutboundUrlPolicy} and moved to the socket: the host is resolved <em>once</em>, here, every address it
 * resolves to is checked, and {@link OutboundHttp} connects only to an address in the {@link Target} this returns.
 * Nothing resolves the name again, so a name that answers with a public address for the check and a private one for
 * the connection (DNS rebinding, the residual {@code OutboundUrlPolicy}'s javadoc names) has nothing to rebind.
 *
 * <p>The rules:
 * <ul>
 *   <li>{@code https} only, or {@code http} as well when {@link Builder#allowHttp} says so.</li>
 *   <li>A host is required, credentials in the URL are refused, and a port must be 1-65535.</li>
 *   <li>Every address the host resolves to must be public ({@link #nonPublicReason}): one private record refuses the
 *       whole name, because a connection may go to any of them.</li>
 *   <li>{@link Builder#addressExemptHosts} names hosts (and their subdomains, on a label boundary) that may resolve
 *       to non-public addresses: they still resolve once and are still pinned.</li>
 *   <li>{@link Builder#trusting} exempts operator-configured endpoints from the scheme and address rules. The
 *       exemption is pinned to the endpoint's scheme, host, port and path prefix, never its host alone: the same
 *       policy screens caller-supplied identifiers, and a host-only exemption would let a caller name
 *       {@code http://<that-host>:6379/} and turn the operator's own endpoint into a port scanner. A path is inside
 *       an exempt prefix only when, decoded once, it has no dot segment (with or without {@code ;} parameters), no
 *       backslash and no percent sign, so a server's own normalisation cannot take it out of the prefix.</li>
 *   <li>{@link Builder#allowPrivateNetworks} turns the address rule off altogether (development only).</li>
 * </ul>
 * There is no port rule beyond the range: {@code OutboundUrlPolicy} has none either, and the port matters only to an
 * exemption, which pins it.
 *
 * <p>Resolution goes through {@link Resolver}, {@link InetAddress#getAllByName} by default. It is the one blocking
 * step no deadline bounds: the JDK's resolver takes no timeout, so a slow DNS server costs the system resolver's
 * own timeout (U-0195).
 */
public final class AddressPolicy {

    /** Resolves a host to its addresses. */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /** The JVM's resolver. */
    public static final Resolver SYSTEM_RESOLVER = InetAddress::getAllByName;

    private final boolean allowHttp;
    private final boolean allowPrivateNetworks;
    private final List<String> addressExemptHosts;
    private final List<Endpoint> exemptEndpoints;
    private final Resolver resolver;
    private final Predicate<InetAddress> publicAddress;

    private AddressPolicy(Builder builder) {
        this.allowHttp = builder.allowHttp;
        this.allowPrivateNetworks = builder.allowPrivateNetworks;
        this.addressExemptHosts = List.copyOf(builder.addressExemptHosts);
        this.exemptEndpoints = List.copyOf(builder.exemptEndpoints);
        this.resolver = builder.resolver;
        this.publicAddress = builder.publicAddress;
    }

    /** The strict policy: https only, public addresses only, no exemptions, the JVM's resolver. */
    public static AddressPolicy strict() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builds an {@link AddressPolicy}. */
    public static final class Builder {
        private boolean allowHttp;
        private boolean allowPrivateNetworks;
        private final List<String> addressExemptHosts = new ArrayList<>();
        private final List<Endpoint> exemptEndpoints = new ArrayList<>();
        private Resolver resolver = SYSTEM_RESOLVER;
        private Predicate<InetAddress> publicAddress = address -> nonPublicReason(address) == null;

        private Builder() {
        }

        /** Allows plaintext {@code http} as well as {@code https}. */
        public Builder allowHttp(boolean allow) {
            this.allowHttp = allow;
            return this;
        }

        /** Turns the address rule off: any address may be connected to. Development only. */
        public Builder allowPrivateNetworks(boolean allow) {
            this.allowPrivateNetworks = allow;
            return this;
        }

        /**
         * Hosts, and their subdomains on a label boundary, that may resolve to non-public addresses. Blank entries are
         * ignored; case does not matter.
         */
        public Builder addressExemptHosts(Collection<String> hosts) {
            for (String host : Objects.requireNonNull(hosts, "hosts")) {
                if (host != null && !host.isBlank()) {
                    this.addressExemptHosts.add(host.trim().toLowerCase(Locale.ROOT));
                }
            }
            return this;
        }

        /**
         * Exempts these operator-configured endpoints from the scheme and address rules, each pinned to its scheme,
         * host, port and path prefix. Null, blank and unparseable entries are ignored, so optional configuration can be
         * passed straight through.
         */
        public Builder trusting(String... operatorConfiguredUrls) {
            for (String url : operatorConfiguredUrls) {
                Endpoint endpoint = Endpoint.of(url);
                if (endpoint != null && !this.exemptEndpoints.contains(endpoint)) {
                    this.exemptEndpoints.add(endpoint);
                }
            }
            return this;
        }

        /** Resolves hosts with {@code resolver} instead of the JVM's. */
        public Builder resolver(Resolver resolver) {
            this.resolver = Objects.requireNonNull(resolver, "resolver");
            return this;
        }

        /** Test seam: which addresses count as public, in place of {@link #nonPublicReason}. */
        Builder publicAddress(Predicate<InetAddress> rule) {
            this.publicAddress = Objects.requireNonNull(rule, "rule");
            return this;
        }

        public AddressPolicy build() {
            return new AddressPolicy(this);
        }
    }

    /** A URL that passed, and the addresses its host resolved to: the only ones a connection may go to. */
    public static final class Target {
        private final URI uri;
        private final boolean tls;
        private final String host;
        private final int port;
        private final List<InetAddress> addresses;

        Target(URI uri, boolean tls, String host, int port, List<InetAddress> addresses) {
            this.uri = uri;
            this.tls = tls;
            this.host = host;
            this.port = port;
            this.addresses = List.copyOf(addresses);
        }

        public URI uri() {
            return this.uri;
        }

        /** Whether the scheme is {@code https}. */
        public boolean tls() {
            return this.tls;
        }

        /** The host, lower case, an IPv6 literal without its brackets: the name TLS sends and checks. */
        public String host() {
            return this.host;
        }

        public int port() {
            return this.port;
        }

        /** The checked addresses, in the resolver's order. */
        public List<InetAddress> addresses() {
            return this.addresses;
        }

        /** {@code scheme://host:port}, the port always written: the key a per-host bulkhead counts under. */
        public String origin() {
            String literal = this.host.indexOf(':') >= 0 ? "[" + this.host + "]" : this.host;
            return (this.tls ? "https" : "http") + "://" + literal + ":" + this.port;
        }
    }

    /**
     * Checks {@code url}, resolves its host once and checks every address.
     *
     * @throws OutboundHttpException {@code REFUSED_URL}, {@code UNRESOLVED} or {@code REFUSED_ADDRESS}
     */
    public Target check(String url) throws OutboundHttpException {
        Objects.requireNonNull(url, "url");
        try {
            return check(new URI(url));
        } catch (URISyntaxException e) {
            throw new OutboundHttpException(OutboundHttpException.Reason.REFUSED_URL,
                    "refusing to fetch a malformed URL: " + e.getMessage(), e);
        }
    }

    /**
     * Checks {@code uri}, resolves its host once and checks every address.
     *
     * @throws OutboundHttpException {@code REFUSED_URL}, {@code UNRESOLVED} or {@code REFUSED_ADDRESS}
     */
    public Target check(URI uri) throws OutboundHttpException {
        Objects.requireNonNull(uri, "uri");
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw refusedUrl("refusing to fetch over " + (scheme.isEmpty() ? "(no scheme)" : scheme) + ": " + uri);
        }
        String rawHost = uri.getHost();
        if (rawHost == null) {
            throw refusedUrl("refusing to fetch a URL with no host: " + uri);
        }
        if (uri.getRawUserInfo() != null) {
            // Credentials in a fetched URL are never legitimate here and would travel onward.
            throw refusedUrl("refusing to fetch a URL carrying credentials: " + rawHost);
        }
        int port = uri.getPort() == -1 ? defaultPort(scheme) : uri.getPort();
        if (port < 1 || port > 65535) {
            throw refusedUrl("refusing to fetch from port " + port + ": " + rawHost);
        }
        String host = unbracket(rawHost).toLowerCase(Locale.ROOT);
        boolean exempt = isExemptEndpoint(scheme, host, port, uri.getPath());
        if (!exempt && scheme.equals("http") && !this.allowHttp) {
            throw refusedUrl("refusing to fetch over http (https required): " + uri);
        }
        List<InetAddress> addresses = resolve(host);
        if (!exempt && !this.allowPrivateNetworks && !addressExempt(host)) {
            for (InetAddress address : addresses) {
                if (!this.publicAddress.test(address)) {
                    String why = nonPublicReason(address);
                    throw new OutboundHttpException(OutboundHttpException.Reason.REFUSED_ADDRESS, "refusing to fetch "
                            + host + ": it resolves to " + address.getHostAddress()
                            + (why == null ? "" : ", " + why) + ", which is not a public address");
                }
            }
        }
        return new Target(uri, scheme.equals("https"), host, port, addresses);
    }

    private List<InetAddress> resolve(String host) throws OutboundHttpException {
        InetAddress[] resolved;
        try {
            resolved = this.resolver.resolve(host);
        } catch (UnknownHostException | RuntimeException e) {
            throw new OutboundHttpException(OutboundHttpException.Reason.UNRESOLVED, "cannot resolve " + host, e);
        }
        if (resolved == null || resolved.length == 0) {
            throw new OutboundHttpException(OutboundHttpException.Reason.UNRESOLVED, host + " resolves to no address");
        }
        List<InetAddress> addresses = new ArrayList<>(resolved.length);
        for (InetAddress address : resolved) {
            if (address == null) {
                throw new OutboundHttpException(OutboundHttpException.Reason.UNRESOLVED, host + " resolves to a null address");
            }
            addresses.add(address);
        }
        return addresses;
    }

    private boolean isExemptEndpoint(String scheme, String host, int port, String path) {
        for (Endpoint endpoint : this.exemptEndpoints) {
            if (endpoint.matches(scheme, host, port, path)) {
                return true;
            }
        }
        return false;
    }

    /** Whether {@code host} is one of, or a subdomain of, the address-exempt hosts. */
    boolean addressExempt(String host) {
        for (String suffix : this.addressExemptHosts) {
            if (host.equals(suffix) || host.endsWith("." + suffix)) {
                return true;
            }
        }
        return false;
    }

    private static OutboundHttpException refusedUrl(String message) {
        return new OutboundHttpException(OutboundHttpException.Reason.REFUSED_URL, message);
    }

    static int defaultPort(String scheme) {
        return scheme.equals("https") ? 443 : 80;
    }

    static String unbracket(String host) {
        return host.length() > 1 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']'
                ? host.substring(1, host.length() - 1) : host;
    }

    /** Whether {@code host} is an IP literal rather than a name: TLS sends no server name for one. */
    static boolean isLiteral(String host) {
        if (host.indexOf(':') >= 0) {
            return true;
        }
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code address} is public: {@link #nonPublicReason} has nothing against it. */
    public static boolean isPublic(InetAddress address) {
        return nonPublicReason(address) == null;
    }

    /**
     * Why {@code address} is not a public internet address, or null when it is.
     *
     * <p>IPv4: this network 0.0.0.0/8, the RFC 1918 ranges, shared address space 100.64.0.0/10, loopback
     * 127.0.0.0/8, link-local 169.254.0.0/16, IETF protocol assignments 192.0.0.0/24, the three documentation ranges,
     * benchmarking 198.18.0.0/15, multicast 224.0.0.0/4, and reserved 240.0.0.0/4 with the broadcast address.
     *
     * <p>IPv6: all of ::/96 (the unspecified address, loopback and the deprecated IPv4-compatible form, which no
     * public host uses), discard-only 100::/64, Teredo 2001::/32 (below), documentation 2001:db8::/32, unique local
     * fc00::/7, link-local fe80::/10, the deprecated site-local fec0::/10 and multicast ff00::/8. Forms that embed an
     * IPv4 address are judged by it: IPv4-mapped ::ffff:0:0/96 and IPv4-translated ::ffff:0:0:0/96 (a dual-stack
     * socket connects to the IPv4 address itself), NAT64 64:ff9b::/96, 6to4 2002::/16, and NAT64's local-use
     * 64:ff9b:1::/48, where the prefix length is the operator's choice (RFC 8215), so the address is read at every
     * position RFC 6052 allows for it (/48, /56, /64 and /96) and refused if any reading is not public
     * ({@link #nat64LocalUse}). The cost is a false refusal where an operator's own prefix bits happen to read as a
     * non-public address at a shorter position (U-0196).
     *
     * <p>Teredo is refused outright rather than judged by what it embeds: the client address is only reachable
     * through whichever Teredo relay the network routes 2001::/32 to, so what the embedded address means depends on a
     * relay this process does not choose, and no federation peer is served from a Teredo address.
     */
    public static String nonPublicReason(InetAddress address) {
        byte[] bytes = Objects.requireNonNull(address, "address").getAddress();
        return bytes.length == 4 ? ipv4Reason(bytes, 0) : ipv6Reason(bytes);
    }

    /** Why the IPv4 address at {@code bytes[offset..offset+3]} is not public, or null. */
    static String ipv4Reason(byte[] bytes, int offset) {
        int a = bytes[offset] & 0xFF;
        int b = bytes[offset + 1] & 0xFF;
        int c = bytes[offset + 2] & 0xFF;
        if (a == 0) {
            return "in 0.0.0.0/8 (this network)";
        }
        if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)) {
            return "in a private range (RFC 1918)";
        }
        if (a == 100 && b >= 64 && b <= 127) {
            return "in 100.64.0.0/10 (shared address space)";
        }
        if (a == 127) {
            return "in 127.0.0.0/8 (loopback)";
        }
        if (a == 169 && b == 254) {
            return "in 169.254.0.0/16 (link-local)";
        }
        if (a == 192 && b == 0 && c == 0) {
            return "in 192.0.0.0/24 (IETF protocol assignments)";
        }
        if ((a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)) {
            return "in a documentation range";
        }
        if (a == 198 && (b == 18 || b == 19)) {
            return "in 198.18.0.0/15 (benchmarking)";
        }
        if (a >= 224 && a <= 239) {
            return "in 224.0.0.0/4 (multicast)";
        }
        if (a >= 240) {
            return "in 240.0.0.0/4 (reserved)";
        }
        return null;
    }

    /** Why the IPv6 address is not public, or null. */
    static String ipv6Reason(byte[] bytes) {
        int first = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;
        if (zero(bytes, 0, 12)) {
            return "in ::/96 (unspecified, loopback or IPv4-compatible)";
        }
        if (zero(bytes, 0, 10) && ffff(bytes, 10)) {
            return embedded("IPv4-mapped", bytes, 12);
        }
        if (zero(bytes, 0, 8) && ffff(bytes, 8) && zero(bytes, 10, 12)) {
            return embedded("IPv4-translated", bytes, 12);
        }
        if (first == 0x00 && second == 0x64 && (bytes[2] & 0xFF) == 0xFF && (bytes[3] & 0xFF) == 0x9B) {
            if (zero(bytes, 4, 12)) {
                return embedded("NAT64 64:ff9b::/96", bytes, 12);
            }
            if (bytes[4] == 0 && bytes[5] == 1) {
                return nat64LocalUse(bytes);
            }
            return null;
        }
        if (first == 0x01 && second == 0x00 && zero(bytes, 2, 8)) {
            return "in 100::/64 (discard-only)";
        }
        if (first == 0x20 && second == 0x01 && bytes[2] == 0 && bytes[3] == 0) {
            return "in 2001::/32 (Teredo)";
        }
        if (first == 0x20 && second == 0x01 && (bytes[2] & 0xFF) == 0x0D && (bytes[3] & 0xFF) == 0xB8) {
            return "in 2001:db8::/32 (documentation)";
        }
        if (first == 0x20 && second == 0x02) {
            return embedded("6to4 2002::/16", bytes, 2);
        }
        if ((first & 0xFE) == 0xFC) {
            return "in fc00::/7 (unique local)";
        }
        if (first == 0xFE && (second & 0xC0) == 0x80) {
            return "in fe80::/10 (link-local)";
        }
        if (first == 0xFE && (second & 0xC0) == 0xC0) {
            return "in fec0::/10 (site-local)";
        }
        if (first == 0xFF) {
            return "in ff00::/8 (multicast)";
        }
        return null;
    }

    /**
     * 64:ff9b:1::/48 with the IPv4 address read at each RFC 6052 position a prefix of /48 or longer allows (bits 64-71,
     * the "u" octet, never carry it). A reading at /48, /56 or /64 that falls in 0.0.0.0/8 is skipped: it is what the
     * zero padding of a longer prefix looks like - 64:ff9b:1::8.8.8.8 read at /48 is 0.0.0.0 - and 0.0.0.0/8 is no
     * destination a translator forwards to. The /96 reading is judged in full.
     */
    static String nat64LocalUse(byte[] bytes) {
        int[][] positions = {{6, 7, 9, 10}, {7, 9, 10, 11}, {9, 10, 11, 12}, {12, 13, 14, 15}};
        for (int p = 0; p < positions.length; p++) {
            int[] position = positions[p];
            byte[] v4 = {bytes[position[0]], bytes[position[1]], bytes[position[2]], bytes[position[3]]};
            String why = v4[0] == 0 && p < positions.length - 1 ? null : ipv4Reason(v4, 0);
            if (why != null) {
                return "NAT64 local-use 64:ff9b:1::/48 embedding " + (v4[0] & 0xFF) + "." + (v4[1] & 0xFF) + "."
                        + (v4[2] & 0xFF) + "." + (v4[3] & 0xFF) + ", " + why;
            }
        }
        return null;
    }

    private static String embedded(String form, byte[] bytes, int offset) {
        String why = ipv4Reason(bytes, offset);
        return why == null ? null : form + " embedding " + (bytes[offset] & 0xFF) + "." + (bytes[offset + 1] & 0xFF)
                + "." + (bytes[offset + 2] & 0xFF) + "." + (bytes[offset + 3] & 0xFF) + ", " + why;
    }

    private static boolean zero(byte[] bytes, int from, int to) {
        for (int i = from; i < to; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean ffff(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) == 0xFF && (bytes[offset + 1] & 0xFF) == 0xFF;
    }

    /** An operator-configured endpoint: scheme, host, port and path prefix must all match. */
    static final class Endpoint {
        private final String scheme;
        private final String host;
        private final int port;
        private final String pathPrefix;

        private Endpoint(String scheme, String host, int port, String pathPrefix) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.pathPrefix = pathPrefix;
        }

        /** The endpoint {@code url} names, or null when it is null, blank, unparseable or not http(s). */
        static Endpoint of(String url) {
            if (url == null || url.isBlank()) {
                return null;
            }
            URI uri;
            try {
                uri = new URI(url.trim());
            } catch (URISyntaxException e) {
                return null;
            }
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost();
            if (host == null || !(scheme.equals("https") || scheme.equals("http"))) {
                return null;
            }
            // A URI with a host is hierarchical, so it has a path, if only an empty one.
            String path = uri.getPath();
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return new Endpoint(scheme, unbracket(host).toLowerCase(Locale.ROOT),
                    uri.getPort() == -1 ? defaultPort(scheme) : uri.getPort(), path);
        }

        boolean matches(String scheme, String host, int port, String path) {
            if (!this.scheme.equals(scheme) || !this.host.equals(host) || this.port != port) {
                return false;
            }
            String candidate = path == null ? "" : path;
            // This is the path decoded once. A backslash (a separator to some servers) or a percent sign (a second
            // round of encoding, %252e or %252f) left in it could climb out of the prefix after the server's own
            // decoding, so a path with either is never exempt.
            if (candidate.indexOf('\\') >= 0 || candidate.indexOf('%') >= 0) {
                return false;
            }
            for (String segment : candidate.split("/", -1)) {
                // A dot segment, percent-encoded or not and with any ';' path parameters stripped (Tomcat and
                // Spring read "..;" as ".."), could climb out of the prefix once the server normalises it.
                int parameters = segment.indexOf(';');
                String name = parameters < 0 ? segment : segment.substring(0, parameters);
                if (name.equals(".") || name.equals("..")) {
                    return false;
                }
            }
            return this.pathPrefix.isEmpty() || candidate.equals(this.pathPrefix)
                    || candidate.startsWith(this.pathPrefix + "/");
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Endpoint)) {
                return false;
            }
            Endpoint other = (Endpoint) o;
            return this.port == other.port && this.scheme.equals(other.scheme) && this.host.equals(other.host)
                    && this.pathPrefix.equals(other.pathPrefix);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.scheme, this.host, this.port, this.pathPrefix);
        }
    }
}
