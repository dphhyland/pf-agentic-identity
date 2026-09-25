package com.pingidentity.ps.oidf.federation.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Decisions kept a while, and the local policy before an external one. */
class CachingAndCompositePolicyDecisionPointTest {
    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final List<PolicyDecisionRequest> asked = new ArrayList<>();

    private static PolicyDecisionRequest request(String trackingId) {
        return new PolicyDecisionRequest(DecisionPoint.AUTOMATIC_REGISTRATION, "https://rp.example", null, "openid_provider", "https://pf.example",
                null, Map.of("request", Map.of("tracking_id", trackingId)), trackingId);
    }

    private FederationPolicyDecisionPoint answering(PolicyDecision decision) {
        return request -> {
            this.asked.add(request);
            return decision;
        };
    }

    @Test
    void aDecisionIsKeptForItsTimeWhateverTheRequestsOwnDetails() throws Exception {
        PolicyDecision permit = PolicyDecision.permit(NarrowingObligations.NONE);
        CachingPolicyDecisionPoint cached = new CachingPolicyDecisionPoint(this.answering(permit), Duration.ofSeconds(60), this.clock);

        assertSame(permit, cached.decide(request("t-1")));
        assertSame(permit, cached.decide(request("t-2")));
        assertEquals(1, this.asked.size(), "a second tracking id is the same question");

        this.clock.advance(Duration.ofSeconds(60));
        cached.decide(request("t-3"));
        assertEquals(2, this.asked.size(), "and asked again once its time is up");
    }

    @Test
    void aDenialIsKeptButNoDecisionNeverIs() throws Exception {
        CachingPolicyDecisionPoint denials = new CachingPolicyDecisionPoint(this.answering(PolicyDecision.deny("no", null)), Duration.ofSeconds(60),
                this.clock);
        denials.decide(request("t-1"));
        denials.decide(request("t-2"));
        assertEquals(1, this.asked.size());

        List<Integer> tries = new ArrayList<>();
        CachingPolicyDecisionPoint failing = new CachingPolicyDecisionPoint(request -> {
            tries.add(1);
            throw new PolicyDecisionException("down");
        }, Duration.ofSeconds(60), this.clock);
        assertThrows(PolicyDecisionException.class, () -> failing.decide(request("t-1")));
        assertThrows(PolicyDecisionException.class, () -> failing.decide(request("t-1")));
        assertEquals(2, tries.size(), "the next request asks again");
    }

    @Test
    void aLocalDenialIsFinalAndTheExternalDecisionPointIsNotAsked() throws Exception {
        CompositePolicyDecisionPoint composite = new CompositePolicyDecisionPoint(request -> PolicyDecision.deny("local", null),
                this.answering(PolicyDecision.permit(NarrowingObligations.NONE)));

        assertFalse(composite.decide(request("t-1")).permitted());
        assertEquals(List.of(), this.asked);
    }

    @Test
    void aPermitFromBothCarriesTheObligationsOfBoth() throws Exception {
        FederationPolicyDecisionPoint local = new LocalFederationPolicyDecisionPoint(Set.of("openid", "read"));
        PolicyDecision external = new PolicyDecision(true, new NarrowingObligations(Set.of("read", "write"), null, null, 600L, null), "ok", null,
                "pdp-1", 12L, Set.of("step_up"));

        PolicyDecision both = new CompositePolicyDecisionPoint(local, this.answering(external)).decide(request("t-1"));

        assertTrue(both.permitted());
        assertEquals(Set.of("read"), both.obligations().scopes());
        assertEquals(600L, both.obligations().maxTtlSeconds());
        assertEquals("pdp-1", both.pdpRequestId());
        assertEquals(12L, both.latencyMs());
        assertEquals(Set.of("step_up"), both.ignoredContextKeys());
        assertFalse(new CompositePolicyDecisionPoint(local, request -> PolicyDecision.deny("external", "nope")).decide(request("t-1")).permitted());
        assertEquals(NarrowingObligations.NONE, new LocalFederationPolicyDecisionPoint(null).decide(request("t-1")).obligations());
    }
}
