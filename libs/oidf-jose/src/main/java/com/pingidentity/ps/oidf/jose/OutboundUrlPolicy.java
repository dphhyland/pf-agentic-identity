package com.pingidentity.ps.oidf.jose;

import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
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
 * controller as the pivot. Residual: within an exempt origin and prefix the path is not constrained,
 * beyond platform's rule that a path with a dot segment, a backslash or a percent sign left after one
 * decoding is never inside an exemption.
 *
 * <p>The rules themselves are platform's {@link AddressPolicy} (plan item S5a): this class reads the
 * settings and keeps the API its callers use, and {@link JdkHttpClient} sends through platform's
 * {@code OutboundHttp} with the same rules. There the host is resolved once, every address is checked,
 * and the connection goes to a checked address and nowhere else, so a name that resolves publicly for
 * the check and privately for the connection (DNS rebinding) has nothing to rebind. {@link #check} on
 * its own still only checks: a caller that sends through another client resolves the name again when it
 * connects, so a caller that sends does so through {@link #addressPolicy()} instead.
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
    private final List<String> trustedUrls;
    private final long maxBodyBytes;
    private final Function<String, InetAddress[]> resolver;
    /** The rules, resolving through {@link #resolver}: what checks and what a connection is pinned to. */
    private final AddressPolicy addresses;
    /** The same rules with every name resolving to loopback: passes exactly when the address rule does not apply. */
    private final AddressPolicy addressRuleProbe;

    private OutboundUrlPolicy(boolean allowHttp, boolean allowPrivateNetworks, List<String> addressExemptHosts,
            List<String> trustedUrls, long maxBodyBytes, Function<String, InetAddress[]> resolver) {
        this.allowHttp = allowHttp;
        this.allowPrivateNetworks = allowPrivateNetworks;
        this.addressExemptHosts = List.copyOf(addressExemptHosts);
        this.trustedUrls = List.copyOf(trustedUrls);
        this.maxBodyBytes = maxBodyBytes;
        this.resolver = resolver;
        this.addresses = rules(resolver::apply);
        this.addressRuleProbe = rules(host -> new InetAddress[] {InetAddress.getLoopbackAddress()});
    }

    private AddressPolicy rules(AddressPolicy.Resolver names) {
        return AddressPolicy.builder()
                .allowHttp(this.allowHttp)
                .allowPrivateNetworks(this.allowPrivateNetworks)
                .addressExemptHosts(this.addressExemptHosts)
                .trusting(this.trustedUrls.toArray(new String[0]))
                .resolver(names)
                .build();
    }

    /** The settings catalogue the fetch rules are in ({@code META-INF/oidf-settings/outbound-fetch.json}). */
    public static final String CATALOGUE = "outbound-fetch";

    public static OutboundUrlPolicy fromEnvironment() {
        return from(Sources.process());
    }

    /** Test seam: build from a supplied environment lookup, and no system properties. */
    public static OutboundUrlPolicy from(Function<String, String> env) {
        Objects.requireNonNull(env, "env");
        return from(Sources.of(env, name -> null, null));
    }

    /** The fetch rules' settings, read from {@code sources}; the federation runtime reads {@link #ALLOW_HTTP_ENV} here too. */
    public static Settings settings(Sources sources) {
        return Settings.load(OutboundUrlPolicy.class.getClassLoader(), CATALOGUE).with(sources);
    }

    /**
     * The policy {@code sources} give, each setting through its {@value #CATALOGUE} catalogue entry and parsed strictly
     * (plan item ST-5): a switch that is not {@code true} or {@code false}, a body limit that is not a whole number of at
     * least 1, or an allow-list of nothing is refused, naming the setting, where the reader before 0.6.0 read the switch
     * as false and the limit as its default.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its entry refuses
     */
    public static OutboundUrlPolicy from(Sources sources) {
        Settings settings = settings(sources);
        java.util.Set<String> allowlist = settings.words(HOST_ALLOWLIST_ENV);
        List<String> hosts = new ArrayList<>();
        if (allowlist != null) {
            for (String host : allowlist) {
                hosts.add(host.toLowerCase(Locale.ROOT));
            }
        }
        return new OutboundUrlPolicy(
                settings.bool(ALLOW_HTTP_ENV),
                settings.bool(ALLOW_PRIVATE_ENV),
                hosts,
                List.<String>of(),
                settings.longValue(MAX_BODY_ENV),
                OutboundUrlPolicy::resolveAll);
    }

    /**
     * No restrictions. For tests and for callers that have already established the URL is
     * operator-supplied; prefer {@link #trusting} so the exemption is scoped to specific hosts.
     */
    public static OutboundUrlPolicy permissive() {
        return new OutboundUrlPolicy(true, true, List.of(), List.<String>of(), Long.MAX_VALUE, OutboundUrlPolicy::resolveAll);
    }

    /**
     * Test seam: same policy, but with host resolution stubbed. The stub is the only resolver
     * {@link JdkHttpClient} uses, so the addresses it returns are the ones a connection goes to.
     */
    public OutboundUrlPolicy withResolver(Function<String, InetAddress[]> stub) {
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.addressExemptHosts,
                this.trustedUrls, this.maxBodyBytes, Objects.requireNonNull(stub, "stub"));
    }

    /**
     * Returns a policy that additionally exempts the given operator-configured endpoints from the
     * scheme and address rules, each pinned to its scheme, host, port and path prefix. Null/blank
     * entries are ignored, so callers can pass optional configuration straight through.
     */
    public OutboundUrlPolicy trusting(String... operatorConfiguredUrls) {
        List<String> trusted = new ArrayList<>(this.trustedUrls);
        for (String url : operatorConfiguredUrls) {
            if (url != null && !url.isBlank() && !trusted.contains(url)) {
                trusted.add(url);
            }
        }
        return new OutboundUrlPolicy(this.allowHttp, this.allowPrivateNetworks, this.addressExemptHosts,
                trusted, this.maxBodyBytes, this.resolver);
    }

    public long maxBodyBytes() {
        return this.maxBodyBytes;
    }

    /**
     * The rules as platform's {@link AddressPolicy}, for a transport that sends through platform's {@code OutboundHttp}:
     * {@link JdkHttpClient}, and the SSF push delivery and device-enrolment's PingOne JWKS fetch (plan item S5d).
     */
    public AddressPolicy addressPolicy() {
        return this.addresses;
    }

    /**
     * @return the parsed URI when the fetch is permitted
     * @throws IllegalArgumentException with a reason when it is not - the caller surfaces this as a
     *     rejected chain, never as a server error
     */
    public URI check(String url) {
        URI uri = parse(url);
        try {
            return this.addresses.check(uri).uri();
        }
        catch (OutboundHttpException e) {
            IllegalArgumentException refused = refusal(e, uri);
            if (refused != null) {
                throw refused;
            }
            // A name that does not resolve where the address rule does not apply was never resolved
            // here: the connection finds out, as a transport failure rather than a refusal.
            return uri;
        }
    }

    /** {@code url} as a URI, or the refusal of a malformed one. */
    static URI parse(String url) {
        if (url == null) {
            throw new IllegalArgumentException("refusing to fetch a null URL");
        }
        try {
            return new URI(url);
        }
        catch (URISyntaxException e) {
            throw new IllegalArgumentException("refusing to fetch a malformed URL: " + url, e);
        }
    }

    /**
     * The refusal a policy failure becomes, or null when it is not one. The URL and address rules
     * refuse; a name that does not resolve is refused only where the address rule applies (the
     * rule cannot pass a name it cannot resolve), and is otherwise a failed fetch like any other.
     */
    public IllegalArgumentException refusal(OutboundHttpException e, URI uri) {
        switch (e.reason()) {
            case REFUSED_URL:
                String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
                return new IllegalArgumentException(e.getMessage() + (scheme.equals("http")
                        ? " (set " + ALLOW_HTTP_ENV + "=true for a plaintext dev endpoint)" : ""), e);
            case REFUSED_ADDRESS:
                return new IllegalArgumentException(e.getMessage() + " (name the host in " + HOST_ALLOWLIST_ENV
                        + " if it is a legitimate internal endpoint, or set " + ALLOW_PRIVATE_ENV
                        + "=true to disable this check entirely)", e);
            case UNRESOLVED:
                return addressRuleApplies(uri)
                        ? new IllegalArgumentException("refusing to fetch " + uri.getHost() + ": " + e.getMessage(), e)
                        : null;
            default:
                return null;
        }
    }

    /** Whether the address rule applies to {@code uri}: the probe, which resolves every name to loopback, refuses it. */
    boolean addressRuleApplies(URI uri) {
        try {
            this.addressRuleProbe.check(uri);
            return false;
        }
        catch (OutboundHttpException e) {
            return true;
        }
    }

    private static InetAddress[] resolveAll(String host) {
        try {
            return InetAddress.getAllByName(host);
        }
        catch (UnknownHostException e) {
            throw new IllegalArgumentException("cannot resolve " + host, e);
        }
    }
}
