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
        String name = criterion == null ? "an unnamed criterion" : criterion;
        if (body == null) {
            LOG.error("OGNL criterion " + name + " has no body; it denies", null);
            return false;
        }
        try {
            return body.getAsBoolean();
        } catch (Throwable t) {
            LOG.error("OGNL criterion " + name + " failed and denies: " + t, t);
            return false;
        }
    }
}
