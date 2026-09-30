/*
 * Encrypts a push stream's authorization_header at rest (plan item H-SSF-7, finding F-0058).
 */
package com.pingidentity.ps.oidf.ssf;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The {@code authorization_header} a receiver gives a push stream (SSF 1.0 §8.1.1) is the credential the transmitter
 * presents to the receiver's endpoint, and until 0.6.0 the stores kept it in clear. With {@code OIDF_SSF_SECRET_KEY} set
 * (32 bytes, base64), the JDBC and {@code ldm} stores keep it as
 *
 * <pre>{@code ssfenc:v1:<kid>:<base64url(12-byte nonce || AES-256-GCM ciphertext and 16-byte tag)>}</pre>
 *
 * with the stream's id as the additional authenticated data, so a sealed value copied onto another stream does not
 * open. {@code kid} is the first 16 characters of the base64url SHA-256 of the key, so it names the key without
 * revealing it: during a rotation {@code OIDF_SSF_SECRET_KEY_PREVIOUS} holds the old key, values sealed under it still
 * open, and each is sealed under the new key on its stream's next write.
 *
 * <p>A value without the prefix is a clear header an earlier version stored: it is read as it is, and sealed on the
 * stream's next write. A sealed value neither key opens (the key it was sealed under is gone) is kept as it is - an
 * ERROR says so once per key id - so a write of the stream does not lose it; the receiver is then sent the sealed text
 * and refuses it, until the key is restored.
 *
 * <p>Without a key the production profile refuses to store a header ({@link KeyMissing}, naming the setting), and SSF
 * does not start while its store holds one ({@link #refuseStoredWithoutKey}); the development profile stores it in clear
 * with a WARN.
 */
public final class PushHeaderCipher {

    private static final Log LOGGER = LogFactory.getLog(PushHeaderCipher.class);

    /** The prefix of a sealed value. */
    static final String PREFIX = "ssfenc:v1:";
    /** The setting that holds the current key. */
    public static final String KEY_SETTING = "OIDF_SSF_SECRET_KEY";
    /** The setting that holds the previous key, during a rotation. */
    public static final String PREVIOUS_KEY_SETTING = "OIDF_SSF_SECRET_KEY_PREVIOUS";

    static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String AAD_PREFIX = "ssf-push-auth-header|";
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A cipher that stores clear, as every version before 0.6.0 did: for a store no deployment wiring reaches (tests). */
    public static final PushHeaderCipher CLEAR = new PushHeaderCipher(null, List.of(), false);

    private final Key current;
    private final Map<String, Key> byKid;
    private final boolean production;
    private final Set<String> reported = ConcurrentHashMap.newKeySet();
    private volatile boolean warnedClear;

    private record Key(String kid, SecretKeySpec spec) {
    }

    private PushHeaderCipher(Key current, List<Key> others, boolean production) {
        this.current = current;
        Map<String, Key> keys = new LinkedHashMap<>();
        if (current != null) {
            keys.put(current.kid(), current);
        }
        for (Key k : others) {
            keys.putIfAbsent(k.kid(), k);
        }
        this.byKid = Map.copyOf(keys);
        this.production = production;
    }

    /**
     * The cipher for these keys (each 32 bytes, base64 or base64url; null for none) under the production profile or
     * not.
     *
     * @throws IllegalArgumentException for a key that is not 32 bytes of base64, naming the setting
     */
    public static PushHeaderCipher of(String currentKey, String previousKey, boolean production) {
        Key current = currentKey == null ? null : key(KEY_SETTING, currentKey);
        List<Key> others = new ArrayList<>();
        if (previousKey != null) {
            others.add(key(PREVIOUS_KEY_SETTING, previousKey));
        }
        if (current == null && !others.isEmpty()) {
            throw new IllegalArgumentException(PREVIOUS_KEY_SETTING + " is set without " + KEY_SETTING
                    + ": the previous key only opens values while a current key seals new ones");
        }
        return new PushHeaderCipher(current, others, production);
    }

    /**
     * The key {@code value} holds, for {@code setting}.
     *
     * @throws IllegalArgumentException when it is not 32 bytes of base64 or base64url
     */
    static Key key(String setting, String value) {
        byte[] raw;
        try {
            // base64 or base64url: the URL alphabet's two letters mapped onto the standard one's
            raw = Base64.getDecoder().decode(value.trim().replace('-', '+').replace('_', '/'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(setting + " is not base64: generate one with `openssl rand -base64 32`");
        }
        if (raw.length != KEY_BYTES) {
            throw new IllegalArgumentException(setting + " is " + raw.length + " bytes; it must be " + KEY_BYTES
                    + " (AES-256): generate one with `openssl rand -base64 32`");
        }
        return new Key(kidOf(raw), new SecretKeySpec(raw, "AES"));
    }

    /** The first 16 characters of the key's base64url SHA-256: names it without revealing it. */
    static String kidOf(byte[] raw) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).substring(0, 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** Whether a key is set. */
    public boolean hasKey() {
        return this.current != null;
    }

    /** The current key's id, or null. */
    public String kid() {
        return this.current == null ? null : this.current.kid();
    }

    /**
     * What to store for stream {@code streamId}'s header: sealed under the current key; a value already sealed as it is;
     * null as null. Without a key: refused under production, clear with a WARN under development.
     *
     * @throws KeyMissing under production with no key
     */
    public String seal(String streamId, String header) {
        if (header == null || header.startsWith(PREFIX)) {
            return header;
        }
        if (this.current == null) {
            if (this.production) {
                throw new KeyMissing();
            }
            if (!this.warnedClear) {
                this.warnedClear = true;
                LOGGER.warn((Object) ("SSF: a push stream's authorization_header is stored in clear because " + KEY_SETTING
                        + " is unset; allowed only because the deployment profile is development, and production refuses"
                        + " it"));
            }
            return header;
        }
        return PREFIX + this.current.kid() + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                encrypt(this.current.spec(), aad(streamId), header.getBytes(StandardCharsets.UTF_8)));
    }

    /** A fresh 12-byte nonce, then AES-256-GCM's ciphertext and tag. */
    private static byte[] encrypt(SecretKeySpec key, byte[] aad, byte[] plain) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(aad);
            byte[] sealed = c.doFinal(plain);
            byte[] out = Arrays.copyOf(nonce, NONCE_BYTES + sealed.length);
            System.arraycopy(sealed, 0, out, NONCE_BYTES, sealed.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SSF: could not encrypt a push authorization_header: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * The header stream {@code streamId} stored: opened when sealed under a key this cipher holds; a clear value (an
     * earlier version's) as it is; a sealed value no key here opens, as it is, with an ERROR once per key id.
     */
    public String open(String streamId, String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            return stored;
        }
        String rest = stored.substring(PREFIX.length());
        int colon = rest.indexOf(':');
        String kid = colon < 0 ? "" : rest.substring(0, colon);
        Key key = this.byKid.get(kid);
        if (key == null) {
            report(kid, "was sealed under a key that neither " + KEY_SETTING + " nor " + PREVIOUS_KEY_SETTING + " holds");
            return stored;
        }
        try {
            byte[] in = Base64.getUrlDecoder().decode(rest.substring(colon + 1));
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key.spec(), new GCMParameterSpec(TAG_BITS, in, 0, NONCE_BYTES));
            c.updateAAD(aad(streamId));
            return new String(c.doFinal(in, NONCE_BYTES, in.length - NONCE_BYTES), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            report(kid, "did not open (" + e.getClass().getSimpleName() + "): altered, or copied from another stream");
            return stored;
        }
    }

    private void report(String kid, String what) {
        if (this.reported.add(kid)) {
            LOGGER.error((Object) ("SSF: a push stream's stored authorization_header (key id " + kid + ") " + what
                    + "; its pushes carry the sealed text, which the receiver refuses, until the key is restored"));
        }
    }

    private static byte[] aad(String streamId) {
        // Lower case: the ldm store reads its id back as PostgreSQL's canonical uuid text.
        return (AAD_PREFIX + (streamId == null ? "" : streamId.toLowerCase(java.util.Locale.ROOT))).getBytes(StandardCharsets.UTF_8);
    }

    /** Whether {@code stored} is a sealed value (for tests and the migration check). */
    static boolean isSealed(String stored) {
        return stored != null && stored.startsWith(PREFIX);
    }

    /**
     * Refuses to start over a store that holds a push header when this cipher has no key under production: an
     * earlier version's clear header, or one sealed under a key since removed. Called once the store is open.
     *
     * @throws KeyMissing naming {@value #KEY_SETTING}, which the start turns into {@code FAILED_CONFIG}
     */
    public void refuseStoredWithoutKey(SsfStore store) {
        if (this.current != null || !this.production) {
            return;
        }
        int held = 0;
        for (Stream s : store.listStreams()) {
            if (s.pushAuthorizationHeader() != null) {
                held++;
            }
        }
        if (held > 0) {
            throw new KeyMissing(held);
        }
    }

    /** The production profile refused to store a push header, or to start over stored ones, without the key. */
    public static final class KeyMissing extends RuntimeException {
        private static final long serialVersionUID = 1L;

        KeyMissing() {
            super(KEY_SETTING + " is not set: the production profile does not store a push stream's authorization_header"
                    + " in clear. Set it (32 bytes, base64: `openssl rand -base64 32`) and restart PingFederate");
        }

        KeyMissing(int held) {
            super(KEY_SETTING + " is not set and the SSF store holds " + held + " push stream(s) with an"
                    + " authorization_header: the production profile does not keep them in clear. Set it (32 bytes,"
                    + " base64: `openssl rand -base64 32`) and restart PingFederate; each is encrypted on its stream's next"
                    + " write");
        }
    }
}
