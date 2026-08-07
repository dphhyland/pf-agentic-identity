/*
 * Generates the pseudonymous identifiers the registry hands out.
 */
package com.pingidentity.ps.oidf.device;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Mints opaque identifiers for instances and devices.
 *
 * <p>Instance identifiers are <strong>random, not derived</strong>. A derived identifier — an HMAC over
 * the user and device, say — would be recomputable, which sounds convenient until the inputs leak or
 * the key is compromised, at which point every identifier ever issued becomes linkable to a person
 * retroactively. A random identifier stored against the record has no such failure mode: the mapping
 * exists in exactly one place and can be destroyed.
 *
 * <p>256 bits from {@link SecureRandom}, base64url without padding — 43 characters, non-guessable, and
 * safe in a JWT claim, a URL and a database key without escaping.
 */
public final class InstanceIdentifiers {

    private static final int ENTROPY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private InstanceIdentifiers() {
    }

    /** A new instance identifier — becomes an attestation {@code sub} and a token's {@code act.sub}. */
    public static String newInstanceId() {
        return random();
    }

    /** A new device identifier. Registry-internal; never leaves the platform. */
    public static String newDeviceId() {
        return random();
    }

    /** A new owner-user identifier, keyed to but distinct from the PingOne subject. */
    public static String newOwnerUserId() {
        return random();
    }

    private static String random() {
        byte[] bytes = new byte[ENTROPY_BYTES];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
