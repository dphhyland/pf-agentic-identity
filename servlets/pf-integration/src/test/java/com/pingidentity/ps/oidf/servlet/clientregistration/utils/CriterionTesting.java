package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import java.time.Clock;

/** What the criterion's tests hand it in place of PingFederate's client manager and signing keys. */
final class CriterionTesting {
    /** A client manager with no clients: every client has the server's policy. */
    static final AttestationPolicyResolver NO_CLIENTS = AttestationPolicyResolver.over(id -> null, Clock.systemUTC(), () -> false);
    /** Signing keys that are none: no subject token verifies. */
    static final SubjectTokenVerifier NO_SUBJECT_TOKENS = new SubjectTokenVerifier(() -> null);

    private CriterionTesting() {
    }
}
