/*
 * The boundary an OGNL issuance criterion runs behind: it answers true or false and never throws.
 */
package com.pingidentity.ps.oidf.platform.pf.ognl;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.util.function.BooleanSupplier;

/**
 * Runs the body of an OGNL issuance criterion so that nothing escapes it. PingFederate evaluates an issuance
 * criterion on the engine's classloader, and a criterion that throws denies the token with the criterion's
 * Error Result - {@code invalid_grant} on the client-credentials grant, verified on the rig with 13.1.3.0 on
 * 2026-09-26 (finding U-0015) - and server.log records the criterion as failed with an exception, which the
 * repository's existing criterion calls an opaque OGNL "Method failed" with no trace of the cause. Here any
 * throwable, an {@link Error} included (a {@link NoClassDefFoundError} is what a missing staged jar looks
 * like), is logged with the criterion's name and answered with {@code false}: the same denial, and one an
 * operator can read. {@code ClientAttestationUtils.validateClientAttestation} is the same boundary written out
 * by hand.
 *
 * <p>The body must be a separate method or lambda from the one OGNL calls, which is what this class makes
 * sure of: a linkage error surfaces where a class is first resolved, and inside the body it is caught here.
 */
public final class CriterionGuard {
    /** The longest criterion name or exception message the log line keeps, in characters. */
    static final int MAX_TEXT = 256;

    private static final PlatformLog LOG = PlatformLog.get(CriterionGuard.class);

    private CriterionGuard() {
    }

    /**
     * The criterion's answer, or {@code false} when it throws or has no body.
     *
     * @param criterion what the log calls it, such as {@code validateClientAttestation}
     * @param body      the criterion's own decision
     */
    public static boolean evaluate(String criterion, BooleanSupplier body) {
        String name = criterion == null ? "an unnamed criterion" : oneLine(criterion);
        if (body == null) {
            LOG.error("OGNL criterion " + name + " has no body; it denies", null);
            return false;
        }
        try {
            return body.getAsBoolean();
        } catch (Throwable t) {
            LOG.error("OGNL criterion " + name + " failed and denies: " + describe(t), t);
            return false;
        }
    }

    /**
     * A throwable as one short line: its class and its message, which can carry request-derived text (a client_id,
     * a header, a JWT member), cleaned by {@link #oneLine(String)}. The throwable itself still goes to the log call,
     * so the stack trace is kept.
     */
    static String describe(Throwable t) {
        String message = t.getMessage();
        return t.getClass().getName() + (message == null ? "" : ": " + oneLine(message));
    }

    /**
     * Text as one log line: control, format and separator characters (CR, LF, the bidi overrides) become {@code ?},
     * and it is cut at {@value #MAX_TEXT} characters, never through a surrogate pair.
     */
    static String oneLine(String text) {
        int end = Math.min(text.length(), MAX_TEXT);
        if (end < text.length() && Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        StringBuilder out = new StringBuilder(end);
        for (int i = 0; i < end; i++) {
            char c = text.charAt(i);
            int type = Character.getType(c);
            boolean hidden = type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR;
            out.append(hidden ? '?' : c);
        }
        return out.toString();
    }
}
