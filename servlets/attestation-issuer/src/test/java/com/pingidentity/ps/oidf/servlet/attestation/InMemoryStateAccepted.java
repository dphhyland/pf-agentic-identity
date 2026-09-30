/*
 * A test that starts the attester's parts as a standalone node that has accepted keeping its state in memory.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import java.time.LocalDate;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A test run's environment names no profile, which is production, and no Redis URL, so the attester's stores are in
 * memory and its parts would be {@code REFUSED} (Phase 3 plan, decision 9). A test that starts a part to test something
 * else extends with this: before each test the {@code in-memory-state} risk is accepted, as
 * {@code OIDF_ACCEPTED_RISKS=in-memory-state} accepts it; after each, the risks go back to the process's and the
 * refusals made in code are forgotten, so none reaches the next test.
 */
public final class InMemoryStateAccepted implements BeforeEachCallback, AfterEachCallback {

    /** {@code OIDF_ACCEPTED_RISKS=in-memory-state}. */
    public static final AcceptedRisks IN_MEMORY = AcceptedRisks.parse("in-memory-state", LocalDate.of(2026, 9, 30));

    @Override
    public void beforeEach(ExtensionContext context) {
        ProfileRefusals.resetForTests();
        AttestationSupport.acceptedRisksForTests(IN_MEMORY);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        AttestationSupport.acceptedRisksForTests(null);
        ProfileRefusals.resetForTests();
    }
}
