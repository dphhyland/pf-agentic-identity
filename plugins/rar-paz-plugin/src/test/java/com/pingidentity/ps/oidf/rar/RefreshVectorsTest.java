package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.rar.model.Vectors;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetails;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * The refresh runner: the fourth of the plan's four runners over one vector file (S-1, "One vector file (a
 * test-jar) run by four runners: library, AS, CAS and refresh"). Every {@code contains} case in
 * {@code libs/rar-model}'s vectors - the question {@code isEqualOrSubset} answers - goes through this plugin's
 * {@code isEqualOrSubset} the way PingFederate 13.1.3 asks it on a refresh, and the answer is held to the case's
 * {@code expect}: {@code true} and {@code false} as they are, and a refusal as {@code false} with the model's
 * reason when the plugin was the one asked.
 *
 * <p>The way PingFederate asks is transcribed from {@code javap -c} of the 13.1.3 jars (2026-09-27):
 * {@code RefreshTokenGrantProcessor.processGrant} parses the {@code authorization_details} parameter with
 * {@code new AuthorizationDetails(String)} (the SDK's Jackson; a parse failure is {@code invalid_authorization_details}),
 * enriches it, and calls {@code AuthorizationDetailProcessorAccessor.isEqualOrSubset(requested, grant's details,
 * context)}. {@code AuthorizationDetailsServiceImpl.isEqualOrSubset} answers {@code true} for no requested list and
 * otherwise requires every requested detail to pass {@code AuthorizationDetailsUtil.isEqualOrSubset}, which answers
 * {@code false} for no stored list and otherwise asks, for each stored detail whose {@code getType()} equals the
 * requested one's, that type's processor - with copies of both details, the context, and an empty parameter map -
 * and takes the first yes; an {@code AuthorizationDetailProcessingException} is a no. The stored details are read
 * here through the same parse: PingFederate wrote them with the same service.
 *
 * <p>So the cases pass through PingFederate's own JSON handling first, and a number that is not an integer reaches
 * the plugin as a {@code double}, a large integer as a {@code BigInteger}, and an entry that is not an object, or
 * whose {@code type} is not a string, is refused by the parse before any processor is asked.
 */
class RefreshVectorsTest {

    private static final ObjectMapper WRITER = new ObjectMapper();

    /**
     * Cases whose answer on the refresh path differs from the library's, each with the reason. The runner fails
     * when a case differs and is not here, and when a case here no longer differs, so the list cannot rot. None of
     * them issues more than the grant: three are the markers the plugin strips by design, one is PingFederate not
     * asking about an empty request, and two are numbers PingFederate's own parse turns into something else before
     * the plugin is asked - and what the plugin compares is what PingFederate then issues.
     */
    private static final Map<String, String> DIVERGENCES = new TreeMap<>(Map.of(
            "forbidden: _principal_sub in a candidate is refused",
            "the plugin strips the two bookkeeping markers before it asks the model, as the library's README says the "
                    + "wiring must; on a real refresh enrich has removed them before isEqualOrSubset is called",
            "forbidden: _agent_id in a candidate is refused",
            "as above: the attestation filter's marker is stripped, never compared",
            "forbidden: a forbidden field in the ceiling is refused",
            "as above, on the grant's side, which enrich stripped before PingFederate stored it",
            "lists: a malformed ceiling is refused even when the candidate is empty",
            "PingFederate asks no processor about an empty requested list (allMatch over nothing): the refresh is "
                    + "granted with no details at all, narrower than any grant",
            "numbers: 100e2147483647 is too large wherever it is",
            "PingFederate's parse reads the number as an infinite double, and its copy of the detail writes that back "
                    + "as the string \"Infinity\", under a field the grant does not constrain; the plugin compares, and "
                    + "PingFederate issues, that string",
            "numbers: 1e-999999999 is too large",
            "PingFederate's parse reads the number as the double 0.0, a limit the grant does not constrain; the plugin "
                    + "compares, and PingFederate issues, 0.0"));

    /** What the refresh path answered, and who answered it. */
    private record Answer(boolean contained, String by, RarModelException.Reason reason) { }

    @TestFactory
    @Requirement({"RFC9396 §6.1", "CAS §7(1)"})
    Stream<DynamicTest> everyContainsCaseAnswersTheSameOnARefresh() {
        return Vectors.load().stream()
                .filter(c -> "contains".equals(c.op()))
                .map(c -> DynamicTest.dynamicTest(c.name(), () -> {
                    String mismatch = mismatch(c);
                    String allowed = DIVERGENCES.get(c.name());
                    if (allowed == null && mismatch != null) {
                        fail(mismatch);
                    }
                    if (allowed != null && mismatch == null) {
                        fail("listed as a divergence (" + allowed + ") but the refresh path now agrees with the library");
                    }
                }));
    }

    @Test
    void theRunnerRunsEveryContainsCase() {
        long contains = Vectors.load().stream().filter(c -> "contains".equals(c.op())).count();
        assertTrue(contains >= 148, "the vector file had 148 contains cases on 2026-09-27; it has " + contains);
        assertEquals(DIVERGENCES.size(), DIVERGENCES.keySet().stream()
                .filter(name -> Vectors.load().stream().anyMatch(c -> c.name().equals(name))).count(),
                "every listed divergence names a case in the file");
    }

    /** The first way the refresh path's answer differs from the case's expectation, or {@code null}. */
    static String mismatch(Vectors.Case c) throws Exception {
        Answer answer = refresh(c);
        Object expect = c.expect();
        RarModelException.Reason refusal = c.expectedRefusal();
        if (refusal != null) {
            if (answer.contained()) {
                return "the library refuses (" + refusal + ") and the refresh path grants it";
            }
            if (answer.reason() != null && answer.reason() != refusal) {
                return "the library refuses as " + refusal + " and the plugin as " + answer.reason();
            }
            return null;
        }
        if (!(expect instanceof Boolean want)) {
            return "a contains case expecting " + Vectors.canonical(expect);
        }
        if (answer.contained() != want) {
            return "the library says " + want + " and the refresh path " + answer.contained() + " (" + answer.by()
                    + (answer.reason() == null ? "" : ", " + answer.reason()) + ")";
        }
        return null;
    }

    /** The case as a refresh: the candidate is what the refresh asks for, the ceiling what was granted. */
    static Answer refresh(Vectors.Case c) throws Exception {
        ModelGate gate;
        try {
            gate = ModelGate.of(c.models());
        } catch (RarModelException e) {
            gate = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, "{}{"));
        }
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(mock(PdpClient.class),
                GovernanceEngineConfig.builder().pdpUrl("https://pdp").build(), gate);
        AuthorizationDetails requested;
        AuthorizationDetails granted;
        try {
            requested = new AuthorizationDetails(WRITER.writeValueAsString(c.list("candidate")));
        } catch (IOException e) {
            return new Answer(false, "PingFederate's parse of the request", null);
        }
        try {
            granted = new AuthorizationDetails(WRITER.writeValueAsString(c.list("ceiling")));
        } catch (IOException e) {
            return new Answer(false, "PingFederate's parse of the grant, which it could not have stored", null);
        }
        // What PingFederate 13.1.3 passes on a refresh: the request, the client id and the scope, and no user key.
        AuthorizationDetailContext context = new AuthorizationDetailContext.Builder().withClientId("refresh-client").build();
        try {
            return asPingFederateDoes(processor, requested, granted, context);
        } catch (RuntimeException e) {
            // PingFederate's own code failing before it asks the plugin - getType() on a null entry, say - issues
            // no token.
            return new Answer(false, "PingFederate itself (" + e.getClass().getSimpleName() + ")", null);
        }
    }

    /**
     * {@code AuthorizationDetailsServiceImpl.isEqualOrSubset} and {@code AuthorizationDetailsUtil.isEqualOrSubset}
     * as {@code javap -c} shows them in 13.1.3, with the model's reason kept for a single asked pair.
     */
    private static Answer asPingFederateDoes(AttestationAwareRarProcessor processor, AuthorizationDetails requested,
                                             AuthorizationDetails granted, AuthorizationDetailContext context) {
        if (requested == null || requested.getDetails() == null) {
            return new Answer(true, "PingFederate, with no requested list", null);
        }
        List<RarModelException.Reason> reasons = new ArrayList<>();
        int asked = 0;
        boolean all = true;
        for (AuthorizationDetail d : requested.getDetails()) {
            if (granted == null || granted.getDetails() == null) {
                all = false;
                break;
            }
            boolean any = false;
            for (AuthorizationDetail a : granted.getDetails()) {
                if (!a.getType().equals(d.getType())) {
                    continue;
                }
                asked++;
                try {
                    // Through the SDK interface, as PingFederate calls it, where the exception is declared.
                    AuthorizationDetailProcessor asSdk = processor;
                    if (asSdk.isEqualOrSubset(new AuthorizationDetail(d), new AuthorizationDetail(a), context,
                            Collections.emptyMap())) {
                        any = true;
                        break;
                    }
                } catch (AuthorizationDetailProcessingException e) {
                    continue;
                }
                reasons.add(processor.refreshVerdict(new AuthorizationDetail(d), new AuthorizationDetail(a), context).reason());
            }
            if (!any) {
                all = false;
                break;
            }
        }
        RarModelException.Reason reason = asked == 1 && reasons.size() == 1 ? reasons.get(0) : null;
        return new Answer(all, asked == 0 ? "PingFederate, which asked no processor" : "the plugin", reason);
    }
}
