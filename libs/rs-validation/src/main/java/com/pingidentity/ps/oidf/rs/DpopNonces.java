/*
 * Resource-server DPoP nonces: an HMAC over a time window, so no node has to remember one.
 */
package com.pingidentity.ps.oidf.rs;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The {@code DPoP-Nonce} values a resource server hands out and then requires in proofs (RFC 9449 §9).
 *
 * <p>A nonce is the base64url HMAC-SHA256, under a secret the embedding application supplies, of the number of the
 * current time window. So it is unpredictable to anyone without the secret - RFC 9449 §8: "Nonce values MUST be
 * unpredictable." - and every node that shares the secret issues and accepts the same nonces without storing any.
 * A nonce is accepted in the window it was issued in and the one after, so it lives between one and two windows.
 *
 * <p>With nonces on, {@link DelegatedTokenValidator} refuses a proof that carries no nonce, or one this server did
 * not issue in the last two windows, with {@code use_dpop_nonce} and a fresh nonce in {@code DPoP-Nonce} - RFC 9449
 * §11.3: "A server MUST NOT accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided to
 * the client." A proof whose nonce is from the previous window is accepted, and the response carries the current
 * one so the client moves on before it expires (§8.2).
 */
public final class DpopNonces {
    /** The window {@link #DpopNonces(byte[])} uses. */
    public static final Duration DEFAULT_WINDOW = Duration.ofMinutes(1);
    /** The shortest secret accepted: 256 bits, the size of the HMAC's output. */
    public static final int MIN_SECRET_BYTES = 32;

    /** How a presented nonce stands. */
    public enum Check {
        /** Issued in the current window. */
        CURRENT,
        /** Issued in the previous window: accepted, and the response should carry the current nonce. */
        PREVIOUS,
        /** Not a nonce this server issued in the last two windows. */
        INVALID
    }

    private static final byte[] LABEL = "rs-validation DPoP-Nonce ".getBytes(StandardCharsets.US_ASCII);

    private final SecretKeySpec key;
    private final long windowMillis;
    private final Clock clock;

    public DpopNonces(byte[] secret) {
        this(secret, DEFAULT_WINDOW, Clock.systemUTC());
    }

    /**
     * @param secret at least {@value #MIN_SECRET_BYTES} random bytes, the same on every node that serves the
     *               resource; copied, so the caller may clear its array
     * @param window how long a nonce is current: at least a second
     */
    public DpopNonces(byte[] secret, Duration window, Clock clock) {
        Objects.requireNonNull(secret, "secret");
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("a DPoP nonce secret must be at least " + MIN_SECRET_BYTES
                    + " bytes, not " + secret.length);
        }
        if (window.compareTo(Duration.ofSeconds(1)) < 0) {
            throw new IllegalArgumentException("a DPoP nonce window must be at least a second, not " + window);
        }
        this.key = new SecretKeySpec(Arrays.copyOf(secret, secret.length), "HmacSHA256");
        this.windowMillis = window.toMillis();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The nonce for the current window. */
    public String current() {
        return this.nonceFor(this.clock.millis() / this.windowMillis);
    }

    /** Whether {@code nonce} is one this server issued in the current or the previous window. */
    public Check check(String nonce) {
        long window = this.clock.millis() / this.windowMillis;
        byte[] presented = nonce.getBytes(StandardCharsets.US_ASCII);
        if (MessageDigest.isEqual(presented, this.nonceFor(window).getBytes(StandardCharsets.US_ASCII))) {
            return Check.CURRENT;
        }
        if (MessageDigest.isEqual(presented, this.nonceFor(window - 1).getBytes(StandardCharsets.US_ASCII))) {
            return Check.PREVIOUS;
        }
        return Check.INVALID;
    }

    private String nonceFor(long window) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(this.key);
            mac.update(LABEL);
            byte[] digest = mac.doFinal(Long.toString(window).getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }
}
