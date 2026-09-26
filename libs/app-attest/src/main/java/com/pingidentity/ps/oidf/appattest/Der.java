/*
 * Just enough DER to read the extensions Apple writes into an App Attest credential certificate.
 */
package com.pingidentity.ps.oidf.appattest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * One DER element: its tag and its content octets. Apple's App Attest extensions use context-specific
 * tags with high tag numbers ({@code [1400]}, {@code [1026]}), which the JDK has no public API for, so
 * this reads them directly. Every read is bounds-checked: malformed input fails with
 * {@link IllegalArgumentException}, never an index error.
 */
final class Der {

    static final int UNIVERSAL = 0;
    static final int CONTEXT = 2;

    static final int BOOLEAN = 1;
    static final int INTEGER = 2;
    static final int OCTET_STRING = 4;
    static final int UTF8_STRING = 12;
    static final int SEQUENCE = 16;

    private final int tagClass;
    private final boolean constructed;
    private final int tag;
    private final byte[] value;

    private Der(int tagClass, boolean constructed, int tag, byte[] value) {
        this.tagClass = tagClass;
        this.constructed = constructed;
        this.tag = tag;
        this.value = value;
    }

    /** Reads exactly one element; trailing bytes are an error. */
    static Der read(byte[] der) {
        if (der == null) {
            throw new IllegalArgumentException("no DER to read");
        }
        Reader reader = new Reader(der);
        Der element = reader.next();
        if (reader.hasMore()) {
            throw new IllegalArgumentException("trailing bytes after the DER element");
        }
        return element;
    }

    /** The elements inside a constructed element. */
    List<Der> children() {
        if (!this.constructed) {
            throw new IllegalArgumentException("a primitive element has no children");
        }
        Reader reader = new Reader(this.value);
        List<Der> out = new ArrayList<>();
        while (reader.hasMore()) {
            out.add(reader.next());
        }
        return out;
    }

    /** The only child of a constructed element, as an explicit tag wraps one value. */
    Der only() {
        List<Der> children = children();
        if (children.size() != 1) {
            throw new IllegalArgumentException("expected one element inside the tag, found " + children.size());
        }
        return children.get(0);
    }

    boolean is(int tagClass, int tag) {
        return this.tagClass == tagClass && this.tag == tag;
    }

    int tagClass() {
        return this.tagClass;
    }

    int tag() {
        return this.tag;
    }

    boolean constructed() {
        return this.constructed;
    }

    byte[] value() {
        return this.value.clone();
    }

    String text() {
        if (this.constructed) {
            throw new IllegalArgumentException("a constructed element is not text");
        }
        return new String(this.value, StandardCharsets.UTF_8);
    }

    long integer() {
        if (!is(UNIVERSAL, INTEGER) || this.value.length == 0 || this.value.length > 8) {
            throw new IllegalArgumentException("not a small INTEGER");
        }
        return new BigInteger(this.value).longValue();
    }

    boolean bool() {
        if (!is(UNIVERSAL, BOOLEAN) || this.value.length != 1) {
            throw new IllegalArgumentException("not a BOOLEAN");
        }
        return this.value[0] != 0;
    }

    private static final class Reader {
        private final byte[] bytes;
        private int pos;

        Reader(byte[] bytes) {
            this.bytes = bytes;
        }

        boolean hasMore() {
            return this.pos < this.bytes.length;
        }

        Der next() {
            int first = octet();
            int tagClass = first >>> 6;
            boolean constructed = (first & 0x20) != 0;
            int tag = first & 0x1f;
            if (tag == 0x1f) {
                // High tag number form: base-128, most significant group first, top bit means "more".
                tag = 0;
                int groups = 0;
                int octet;
                do {
                    octet = octet();
                    if (++groups > 4) {
                        throw new IllegalArgumentException("tag number too large");
                    }
                    tag = (tag << 7) | (octet & 0x7f);
                } while ((octet & 0x80) != 0);
            }
            int length = octet();
            if (length >= 0x80) {
                int count = length & 0x7f;
                if (count == 0 || count > 3) {
                    throw new IllegalArgumentException("unsupported DER length form");
                }
                length = 0;
                for (int i = 0; i < count; i++) {
                    length = (length << 8) | octet();
                }
            }
            if (length > this.bytes.length - this.pos) {
                throw new IllegalArgumentException("DER element runs past the end of its container");
            }
            byte[] value = Arrays.copyOfRange(this.bytes, this.pos, this.pos + length);
            this.pos += length;
            return new Der(tagClass, constructed, tag, value);
        }

        private int octet() {
            if (this.pos >= this.bytes.length) {
                throw new IllegalArgumentException("DER truncated");
            }
            return this.bytes[this.pos++] & 0xff;
        }
    }
}
