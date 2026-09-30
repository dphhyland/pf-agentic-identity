/*
 * IP address literals and CIDR ranges, parsed without the resolver.
 */
package com.pingidentity.ps.oidf.platform.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * IPv4 and IPv6 literals, and CIDR ranges of them, parsed here rather than by {@link InetAddress#getByName}, which asks
 * the resolver for anything it does not take for a literal and whose reading of an IPv4 literal with a leading zero
 * differs between JDK updates. An address comes back as its bytes: four for IPv4, sixteen for IPv6, and four for an
 * IPv4-mapped IPv6 address ({@code ::ffff:192.0.2.1}), so the two spellings of one IPv4 address are one address.
 */
final class IpAddresses {

    private IpAddresses() {
    }

    /** A CIDR range: the network's bytes and how many leading bits of an address must equal them. */
    record Cidr(byte[] network, int prefix) {

        /** Whether {@code address} (four or sixteen bytes) is in this range; an address of the other family never is. */
        boolean contains(byte[] address) {
            if (address.length != this.network.length) {
                return false;
            }
            int whole = this.prefix / 8;
            for (int i = 0; i < whole; i++) {
                if (address[i] != this.network[i]) {
                    return false;
                }
            }
            int rest = this.prefix % 8;
            if (rest == 0) {
                return true;
            }
            int mask = (0xff << (8 - rest)) & 0xff;
            return (address[whole] & mask) == (this.network[whole] & mask);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Cidr c && c.prefix == this.prefix && Arrays.equals(c.network, this.network);
        }

        @Override
        public int hashCode() {
            return 31 * Arrays.hashCode(this.network) + this.prefix;
        }

        @Override
        public String toString() {
            return text(this.network) + "/" + this.prefix;
        }
    }

    /**
     * A CIDR range, {@code 10.0.0.0/8} or {@code 2001:db8::/32}, or one address, which is the range of just it.
     * Bits of the address past the prefix are ignored, as a router reads them.
     *
     * @throws IllegalArgumentException naming the text, for anything else
     */
    static Cidr cidr(String text) {
        int slash = text.indexOf('/');
        String addressText = slash < 0 ? text : text.substring(0, slash);
        byte[] address = literal(addressText);
        if (address == null) {
            throw new IllegalArgumentException("'" + text + "' is not an IPv4 or IPv6 address or CIDR range");
        }
        if (address.length == 4 && addressText.indexOf(':') >= 0) {
            throw new IllegalArgumentException("'" + text + "' is an IPv4-mapped IPv6 address: write the IPv4 range in"
                    + " dotted form");
        }
        int bits = address.length * 8;
        if (slash < 0) {
            return new Cidr(address, bits);
        }
        String prefixText = text.substring(slash + 1);
        Integer prefix = decimal(prefixText, bits);
        if (prefix == null) {
            throw new IllegalArgumentException("'" + text + "' has a prefix length that is not a whole number from 0 to "
                    + bits);
        }
        return new Cidr(address, prefix);
    }

    /**
     * The address a header or the container names: a literal, IPv6 optionally in brackets, either optionally with a
     * {@code :port}; {@code null} for anything else - a host name, {@code unknown}, an RFC 7239 obfuscated identifier,
     * a zone id - and for {@code null}.
     */
    static byte[] address(String text) {
        if (text == null) {
            return null;
        }
        String t = text.trim();
        if (t.startsWith("[")) {
            int close = t.indexOf(']');
            if (close < 0 || !port(t.substring(close + 1))) {
                return null;
            }
            byte[] inner = ipv6(t.substring(1, close));
            return inner;
        }
        int firstColon = t.indexOf(':');
        if (firstColon >= 0 && firstColon == t.lastIndexOf(':')) {
            // One colon: an IPv4 address with a port, as some proxies write X-Forwarded-For.
            return port(t.substring(firstColon)) ? ipv4(t.substring(0, firstColon)) : null;
        }
        return literal(t);
    }

    /** An IPv4 or IPv6 literal with nothing around it, or {@code null}. */
    static byte[] literal(String text) {
        return text.indexOf(':') >= 0 ? ipv6(text) : ipv4(text);
    }

    /** The canonical text of an address: dotted IPv4, or IPv6 as {@link InetAddress#getHostAddress} writes it. */
    static String text(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException e) {
            // getByAddress throws only for a length other than 4 or 16, which nothing here makes.
            throw new IllegalStateException("an address of " + address.length + " bytes", e);
        }
    }

    /** {@code ""}, or {@code :} and a port number from 1 to 65535. */
    private static boolean port(String text) {
        return text.isEmpty() || text.charAt(0) == ':' && decimal(text.substring(1), 65535) != null
                && !"0".equals(text.substring(1));
    }

    /** Four dotted decimal octets, each 0 to 255 with no leading zero, or {@code null}. */
    static byte[] ipv4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            Integer octet = decimal(parts[i], 255);
            if (octet == null) {
                return null;
            }
            out[i] = (byte) (int) octet;
        }
        return out;
    }

    /**
     * An IPv6 literal (RFC 4291 section 2.2): eight groups of one to four hex digits, one {@code ::} standing for one or
     * more zero groups, and optionally a dotted IPv4 address as the last two groups; {@code null} for anything else, a
     * zone id included. An IPv4-mapped address comes back as its four IPv4 bytes.
     */
    static byte[] ipv6(String text) {
        if (text.isEmpty() || text.length() > 45) {
            return null;
        }
        int gap = text.indexOf("::");
        if (gap >= 0 && text.indexOf("::", gap + 1) >= 0) {
            return null;
        }
        byte[] out = new byte[16];
        int[] head = gap < 0 ? groups(text, out, 0) : groups(text.substring(0, gap), out, 0);
        if (head == null) {
            return null;
        }
        if (gap < 0) {
            if (head[0] != 16) {
                return null;
            }
        } else {
            byte[] tail = new byte[16];
            int[] rest = groups(text.substring(gap + 2), tail, 0);
            if (head[1] == 1 || rest == null || head[0] + rest[0] > 14) {
                return null;
            }
            System.arraycopy(tail, 0, out, 16 - rest[0], rest[0]);
        }
        if (isMappedIpv4(out)) {
            return Arrays.copyOfRange(out, 12, 16);
        }
        return out;
    }

    /**
     * Reads colon-separated groups into {@code out} from {@code start}: {@code [bytes written, 1 if the last group was a
     * dotted IPv4 address]}, or {@code null}. An empty text is no groups.
     */
    private static int[] groups(String text, byte[] out, int start) {
        if (text.isEmpty()) {
            return new int[] {0, 0};
        }
        String[] parts = text.split(":", -1);
        int at = start;
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (i == parts.length - 1 && part.indexOf('.') >= 0) {
                byte[] v4 = ipv4(part);
                if (v4 == null || at + 4 > out.length) {
                    return null;
                }
                System.arraycopy(v4, 0, out, at, 4);
                return new int[] {at + 4 - start, 1};
            }
            Integer group = hex(part);
            if (group == null || at + 2 > out.length) {
                return null;
            }
            out[at++] = (byte) (group >> 8);
            out[at++] = (byte) (int) group;
        }
        return new int[] {at - start, 0};
    }

    private static boolean isMappedIpv4(byte[] address) {
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return false;
            }
        }
        return address[10] == (byte) 0xff && address[11] == (byte) 0xff;
    }

    /** One to four hex digits, or {@code null}. */
    private static Integer hex(String text) {
        if (text.isEmpty() || text.length() > 4) {
            return null;
        }
        int value = 0;
        for (int i = 0; i < text.length(); i++) {
            int digit = Character.digit(text.charAt(i), 16);
            if (digit < 0) {
                return null;
            }
            value = value * 16 + digit;
        }
        return value;
    }

    /** A decimal whole number from 0 to {@code max}, ASCII digits only and no leading zero, or {@code null}. */
    static Integer decimal(String text, int max) {
        if (text.isEmpty() || text.length() > 5 || text.length() > 1 && text.charAt(0) == '0') {
            return null;
        }
        int value = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            value = value * 10 + (c - '0');
        }
        return value <= max ? value : null;
    }
}
