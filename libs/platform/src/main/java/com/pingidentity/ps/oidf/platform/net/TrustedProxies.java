/*
 * Which proxies' forwarding headers are believed: the client address, scheme and host behind a trusted proxy.
 */
package com.pingidentity.ps.oidf.platform.net;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The one rule for forwarding headers (plan item H-ATT-3): {@value #SETTING} lists the proxies, as CIDR ranges, whose
 * {@code X-Forwarded-*} or RFC 7239 {@code Forwarded} headers are believed. A request whose remote address is not in
 * the list - and every request, while the list is empty, which is the default - is taken at its word: its client
 * address is its remote address, and its scheme and host are its own, whatever headers it carries. A request from a
 * listed proxy has as its client address the right-most hop of the forwarding chain that is not itself a listed proxy,
 * and as its scheme and host what the proxy that received it from that hop says.
 *
 * <p>Right-most, because each proxy appends the address it received the request from and a client can write anything
 * to the left of that. RFC 7239 section 5.2 describes the {@code for} parameter as identifying "the client that
 * initiated the request and subsequent proxies in a chain of proxies", and section 8.1 says that "the header field
 * value can be modified by any node along the path" and that the values are "not trustworthy" beyond a proxy the
 * receiver trusts; the right-most untrusted hop is the one a trusted proxy wrote. The same holds for the de-facto
 * {@code X-Forwarded-For}, whose convention is that each proxy appends the address it saw.
 *
 * <p>Which header family is read is {@value #HEADERS_SETTING}: {@code x-forwarded} (the default) reads
 * {@code X-Forwarded-For}, {@code X-Forwarded-Proto}, {@code X-Forwarded-Host} and {@code X-Forwarded-Port};
 * {@code forwarded} reads only RFC 7239's {@code Forwarded}. One family, never both, because a proxy that writes one
 * passes the other through from the client unchanged. A hop that is not an IP address - {@code unknown}, an obfuscated
 * identifier, a host name - ends the walk: the client address is then the hop to its right, the last one a listed
 * proxy vouched for. A forwarded scheme is believed only as {@code http} or {@code https}, and a forwarded host only
 * as a host name or address literal with an optional port; anything else is ignored, and the request's own is used.
 *
 * <p>PingFederate can rewrite the remote address itself: its incoming proxy settings name a header whose first or
 * last value becomes {@code getRemoteAddr()}, from any sender - it has no list of trusted proxies (read from
 * {@code com.pingidentity.appserver.jetty.server.customizer.ForwardedRequestCustomizer} in 13.1.3's
 * {@code pf-appserver-ext.jar}, 2026-09-30). This class reads the remote address it is given; with those settings set,
 * that is already the header's value, and the proxy's own address is not seen here. The platform README's "net"
 * section says which of the two to configure.
 *
 * <p>Parsed without the resolver: an address is only ever a literal ({@link IpAddresses}), so no header value causes
 * a DNS lookup, and a client address is returned in one canonical spelling, so a caller cannot vary a rate-limit key
 * by writing its address another way.
 */
public final class TrustedProxies {

    private static final PlatformLog LOG = PlatformLog.get(TrustedProxies.class);

    /** The settings catalogue. */
    public static final String COMPONENT = "trusted-proxies";
    /** The proxies whose forwarding headers are believed: CIDR ranges or addresses, space- or comma-separated. */
    public static final String SETTING = "OIDF_TRUSTED_PROXIES";
    /** Which forwarding headers a trusted proxy writes: {@code x-forwarded} or {@code forwarded}. */
    public static final String HEADERS_SETTING = "OIDF_TRUSTED_PROXIES_HEADERS";

    /** The header family a trusted proxy writes. */
    public enum HeaderFamily {
        /** {@code X-Forwarded-For}, {@code -Proto}, {@code -Host} and {@code -Port}. */
        X_FORWARDED("x-forwarded"),
        /** RFC 7239's {@code Forwarded}. */
        FORWARDED("forwarded");

        private final String setting;

        HeaderFamily(String setting) {
            this.setting = setting;
        }

        /** The value of {@value #HEADERS_SETTING} that names it. */
        public String setting() {
            return this.setting;
        }

        /** The family a setting value names, in any case; {@code x-forwarded} for {@code null}. */
        public static HeaderFamily of(String value) {
            if (value == null) {
                return X_FORWARDED;
            }
            for (HeaderFamily family : values()) {
                if (family.setting.equalsIgnoreCase(value.trim())) {
                    return family;
                }
            }
            throw new IllegalArgumentException(HEADERS_SETTING + " is '" + value + "', not x-forwarded or forwarded");
        }
    }

    /** A request's headers: every value of the named header, in the order received; {@code null} or empty for none. */
    @FunctionalInterface
    public interface Headers {
        List<String> values(String name);
    }

    /**
     * What a trusted proxy says of the request it received: the scheme ({@code http} or {@code https}), the host (with
     * a port when the proxy wrote one into it) and the port ({@code X-Forwarded-Port} only). Each is {@code null} when
     * the proxy said nothing believable about it, and the request's own is used.
     */
    public record Origin(String scheme, String host, Integer port) {
        /** Nothing forwarded. */
        public static final Origin NONE = new Origin(null, null, null);
    }

    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9]([A-Za-z0-9.-]{0,252})?(:[0-9]{1,5})?");
    private static final Pattern BRACKETED_HOST = Pattern.compile("\\[[0-9A-Fa-f:.]{2,45}\\](:[0-9]{1,5})?");

    private static final TrustedProxies NONE = new TrustedProxies(List.of(), HeaderFamily.X_FORWARDED);

    /** The last configuration {@link #current()} read, with the values it was built from. */
    private static volatile Current current = new Current(null, null, NONE);

    /** The last problem {@link #current()} logged, so a bad value is logged once, not on every request. */
    private static volatile String lastProblem;

    private record Current(Set<String> proxies, String headers, TrustedProxies value) {
    }

    private final List<IpAddresses.Cidr> proxies;
    private final HeaderFamily family;

    private TrustedProxies(List<IpAddresses.Cidr> proxies, HeaderFamily family) {
        this.proxies = List.copyOf(proxies);
        this.family = family;
    }

    /** No trusted proxy: every request is taken at its word. */
    public static TrustedProxies none() {
        return NONE;
    }

    /**
     * Trusts the proxies in {@code cidrs} (each a CIDR range or one address), reading {@code family}'s headers.
     *
     * @throws IllegalArgumentException naming the first entry that is not an address or range
     */
    public static TrustedProxies of(Collection<String> cidrs, HeaderFamily family) {
        Objects.requireNonNull(family, "family");
        List<IpAddresses.Cidr> ranges = new ArrayList<>();
        if (cidrs != null) {
            for (String cidr : cidrs) {
                ranges.add(IpAddresses.cidr(cidr.trim()));
            }
        }
        return ranges.isEmpty() && family == HeaderFamily.X_FORWARDED ? NONE : new TrustedProxies(ranges, family);
    }

    /**
     * This process's rule, from the {@value #COMPONENT} catalogue: {@value #SETTING} and {@value #HEADERS_SETTING}.
     * Never throws: a value that cannot be read trusts no proxy, which ignores every forwarding header, and is logged at
     * ERROR; the surfaces that depend on it call {@link #check()} at start-up, so they do not start with it.
     */
    public static TrustedProxies current() {
        Settings settings = Holder.SETTINGS;
        try {
            return current(settings);
        } catch (RuntimeException e) {
            String problem = e.getMessage();
            if (!Objects.equals(problem, lastProblem)) {
                lastProblem = problem;
                LOG.error("Forwarding headers are ignored from every sender: " + problem, null);
            }
            return NONE;
        }
    }

    /**
     * This process's rule, as {@link #current()} reads it.
     *
     * @throws SettingRefused naming the setting, when either value cannot be read
     */
    public static TrustedProxies check() {
        return current(Holder.SETTINGS);
    }

    /** The rule {@code settings} give, built again only when their values change. */
    static TrustedProxies current(Settings settings) {
        // A value the catalogue refuses throws its own SettingRefused, which names the setting.
        Set<String> proxies = settings.words(SETTING);
        String headers = settings.choice(HEADERS_SETTING);
        Current seen = current;
        if (Objects.equals(seen.proxies, proxies) && Objects.equals(seen.headers, headers)) {
            return seen.value;
        }
        TrustedProxies value;
        try {
            value = of(proxies, HeaderFamily.of(headers));
        } catch (IllegalArgumentException e) {
            throw new SettingRefused(SETTING, SETTING + ": " + e.getMessage());
        }
        current = new Current(proxies, headers, value);
        if (value.trustsEveryone()) {
            LOG.warn(SETTING + " includes a /0 range: forwarding headers are believed from every sender");
        }
        return value;
    }

    /** Whether no proxy is trusted. */
    public boolean isEmpty() {
        return this.proxies.isEmpty();
    }

    /** The family of forwarding headers read from a trusted proxy. */
    public HeaderFamily family() {
        return this.family;
    }

    /** Whether a /0 range is listed, which believes every sender. */
    boolean trustsEveryone() {
        for (IpAddresses.Cidr cidr : this.proxies) {
            if (cidr.prefix() == 0) {
                return true;
            }
        }
        return false;
    }

    /** Whether {@code address} (a literal, optionally bracketed or with a port) is a listed proxy. */
    public boolean trusts(String address) {
        return this.trusts(IpAddresses.address(address));
    }

    private boolean trusts(byte[] address) {
        if (address == null) {
            return false;
        }
        for (IpAddresses.Cidr cidr : this.proxies) {
            if (cidr.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The client address of a request that arrived from {@code remoteAddress}: the right-most untrusted forwarding hop
     * when the sender is a listed proxy, else the sender. Canonical when it is an address; a remote address that is
     * not one (a mock, a Unix socket) comes back as given, and {@code null} as {@code null}.
     */
    public String clientAddress(String remoteAddress, Headers headers) {
        return this.walk(remoteAddress, headers).client;
    }

    /**
     * What a listed proxy says of the scheme, host and port the client used: {@link Origin#NONE} when the sender is not
     * a listed proxy. Each value is the one written by the proxy that received the request from the client address
     * ({@link #clientAddress}) when the header has a value per hop, else the right-most, which the nearest proxy wrote.
     */
    public Origin origin(String remoteAddress, Headers headers) {
        Walk walk = this.walk(remoteAddress, headers);
        if (!walk.trusted) {
            return Origin.NONE;
        }
        if (this.family == HeaderFamily.FORWARDED) {
            List<Forwarded.Element> elements = walk.elements;
            if (elements.isEmpty()) {
                return Origin.NONE;
            }
            Forwarded.Element element = elements.get(walk.index >= 0 ? walk.index : elements.size() - 1);
            return new Origin(scheme(element.get("proto")), host(element.get("host")), null);
        }
        String scheme = scheme(pick(list(headers, "X-Forwarded-Proto"), walk));
        String host = host(pick(list(headers, "X-Forwarded-Host"), walk));
        String portText = pick(list(headers, "X-Forwarded-Port"), walk);
        Integer port = portText == null ? null : IpAddresses.decimal(portText, 65535);
        return new Origin(scheme, host, port == null || port == 0 ? null : port);
    }

    /** The value at the client hop's index when the header has one value per hop, else the right-most, else null. */
    private static String pick(List<String> values, Walk walk) {
        if (values.isEmpty()) {
            return null;
        }
        if (walk.index >= 0 && values.size() == walk.hops) {
            return values.get(walk.index);
        }
        return values.get(values.size() - 1);
    }

    private static String scheme(String value) {
        if (value == null) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return "https".equals(lower) || "http".equals(lower) ? lower : null;
    }

    private static String host(String value) {
        if (value == null || value.length() > 261) {
            return null;
        }
        return HOST.matcher(value).matches() || BRACKETED_HOST.matcher(value).matches() ? value : null;
    }

    /** Where the walk ended: the client address, the index of its hop ({@code -1} for the sender), and the hop count. */
    private record Walk(String client, boolean trusted, int index, int hops, List<Forwarded.Element> elements) {
    }

    private Walk walk(String remoteAddress, Headers headers) {
        byte[] sender = IpAddresses.address(remoteAddress);
        String senderText = sender == null ? remoteAddress : IpAddresses.text(sender);
        if (!this.trusts(sender)) {
            return new Walk(senderText, false, -1, 0, List.of());
        }
        List<Forwarded.Element> elements = List.of();
        List<String> hops;
        if (this.family == HeaderFamily.FORWARDED) {
            elements = Forwarded.parse(list(headers, "Forwarded"));
            hops = new ArrayList<>(elements.size());
            for (Forwarded.Element element : elements) {
                hops.add(element.get("for"));
            }
        } else {
            hops = list(headers, "X-Forwarded-For");
        }
        String client = senderText;
        int index = -1;
        for (int i = hops.size() - 1; i >= 0; i--) {
            byte[] hop = IpAddresses.address(hops.get(i));
            if (hop == null) {
                break;
            }
            client = IpAddresses.text(hop);
            index = i;
            if (!this.trusts(hop)) {
                break;
            }
        }
        return new Walk(client, true, index, hops.size(), elements);
    }

    /**
     * Every value of a comma-separated header, over all its instances, trimmed, empty ones dropped. For
     * {@code Forwarded} the elements are split by {@link Forwarded}, which respects quoted strings; this is for the
     * {@code X-Forwarded-*} headers, whose values hold no commas.
     */
    static List<String> list(Headers headers, String name) {
        List<String> out = new ArrayList<>();
        List<String> values = headers == null ? null : headers.values(name);
        if (values == null) {
            return out;
        }
        for (String value : values) {
            if (value == null) {
                continue;
            }
            if (Forwarded.NAME.equals(name)) {
                out.add(value);
                continue;
            }
            for (String part : value.split(",", -1)) {
                String t = part.trim();
                if (!t.isEmpty()) {
                    out.add(t);
                }
            }
        }
        return out;
    }

    /** The catalogue, loaded once from this class's loader, read from this process's environment and properties. */
    private static final class Holder {
        static final Settings SETTINGS = Settings.load(TrustedProxies.class.getClassLoader(), COMPONENT);

        private Holder() {
        }
    }
}
