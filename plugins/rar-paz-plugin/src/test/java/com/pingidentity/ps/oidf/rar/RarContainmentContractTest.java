package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

/**
 * RFC 9396 containment is implemented twice in this repo, and the two copies must agree.
 *
 * <p>{@code RarEntitlement} in {@code libs/client-attestation} decides it at the token endpoint —
 * "is this request within the attested entitlement?" — and {@link RarContainment} decides it here for
 * refresh-time narrowing. This plugin cannot depend on that module (PingFederate loads it on a
 * per-plugin isolated classloader and it shades its own jackson), so the rule is written twice and
 * {@code RarContainment}'s own javadoc has carried a {@code TODO: consolidate} since it was written.
 *
 * <p>They had already drifted, in the direction that matters. {@code RarEntitlement.authorize} refuses a
 * requested detail with no {@code type} outright as {@code invalid_authorization_details};
 * {@code isSubset} used to skip the type comparison whenever <em>either</em> side lacked a type, so the
 * very same detail was a subset of anything at refresh. Nothing failed — the two paths simply answered
 * one question two ways, and the permissive answer was the one on the refresh path.
 *
 * <p>Two copies with no compiler relationship need a test that fails when they diverge again. This is
 * it: a shared table of cases whose expected verdicts are {@code RarEntitlement}'s, plus a source-level
 * check that the set-valued field lists are identical.
 */
class RarContainmentContractTest {

    /** Where the other implementation lives, relative to this module's basedir. */
    private static final Path ENTITLEMENT_SOURCE = Path.of(
            "../../libs/client-attestation/src/main/java/com/pingidentity/ps/oidf/clientattestation/RarEntitlement.java");

    private static final Pattern SET_FIELDS_DECL = Pattern.compile(
            "SET_FIELDS\\s*=\\s*\\{([^}]*)\\}");

    /**
     * One case: what is requested, what was accepted, and whether containment holds.
     *
     * <p>Every expectation here is {@code RarEntitlement}'s answer for the same pair — that is the point
     * of the table. If a case's verdict is changed, change it because the shared rule changed, and
     * change both implementations.
     */
    private record Case(String name, Map<String, Object> requested, Map<String, Object> accepted, boolean contained) { }

    private static final List<Case> CASES = List.of(
            new Case("identical details are contained",
                    Map.of("type", "payment", "actions", List.of("initiate")),
                    Map.of("type", "payment", "actions", List.of("initiate")), true),
            new Case("a narrower request is contained",
                    Map.of("type", "payment", "actions", List.of("initiate")),
                    Map.of("type", "payment", "actions", List.of("initiate", "cancel")), true),
            new Case("an action outside the accepted set is not",
                    Map.of("type", "payment", "actions", List.of("cancel")),
                    Map.of("type", "payment", "actions", List.of("initiate")), false),
            new Case("a field the accepted detail omits is unconstrained",
                    Map.of("type", "payment", "actions", List.of("initiate"), "locations", List.of("https://eu.example")),
                    Map.of("type", "payment", "actions", List.of("initiate")), true),
            // The shared rule: an omitted constrained field never widens the grant. RarEntitlement.authorize
            // cannot answer "contained, verbatim" here either - it grants the request WITH the accepted
            // detail's locations inherited. A boolean has no way to narrow, so its only non-widening
            // answer is no; a refresh that wants the same grant restates the field.
            new Case("a request that omits a field the accepted detail constrains is not contained as-is",
                    Map.of("type", "payment", "actions", List.of("initiate")),
                    Map.of("type", "payment", "actions", List.of("initiate"),
                            "locations", List.of("https://eu.example")), false),
            new Case("a different type is not contained",
                    Map.of("type", "accounts", "actions", List.of("read")),
                    Map.of("type", "payment", "actions", List.of("read")), false),
            // The drift. RarEntitlement.authorize throws invalid_authorization_details on a requested
            // entry with no type, so "contained" can never be the answer for one.
            new Case("a requested detail with no type is not contained",
                    Map.of("actions", List.of("initiate")),
                    Map.of("type", "payment", "actions", List.of("initiate")), false),
            new Case("a requested detail with a blank type is not contained",
                    Map.of("type", "   ", "actions", List.of("initiate")),
                    Map.of("type", "payment", "actions", List.of("initiate")), false),
            // RarEntitlement.findContaining requires type.equals(entitlement type); a typeless
            // entitlement entry matches nothing.
            new Case("an accepted detail with no type contains nothing",
                    Map.of("type", "payment", "actions", List.of("initiate")),
                    Map.of("actions", List.of("initiate")), false),
            new Case("multi-valued subsets across several fields hold",
                    Map.of("type", "payment", "actions", List.of("initiate"), "locations", List.of("https://eu.example")),
                    Map.of("type", "payment", "actions", List.of("initiate", "cancel"),
                            "locations", List.of("https://eu.example", "https://us.example")), true),
            new Case("one field inside and another outside is not contained",
                    Map.of("type", "payment", "actions", List.of("initiate"), "locations", List.of("https://af.example")),
                    Map.of("type", "payment", "actions", List.of("initiate"),
                            "locations", List.of("https://eu.example")), false));

    @Test
    @Requirement("RFC9396 §6.1")
    void containmentAgreesWithTheTokenEndpointsRuleOnEveryCase() {
        for (Case c : CASES) {
            assertEquals(c.contained(), RarContainment.isSubset(c.requested(), c.accepted()),
                    "case '" + c.name() + "': this is RarEntitlement's verdict at the token endpoint. "
                            + "Refresh-time containment must not answer it differently.");
        }
    }

    @Test
    void nothingRequestedIsWithinAnything() {
        // RarEntitlement.authorize says the same by returning an empty grant rather than denying.
        assertTrue(RarContainment.isSubset(null, Map.of("type", "payment")));
    }

    @Test
    void nothingAcceptedContainsNothing() {
        assertFalse(RarContainment.isSubset(Map.of("type", "payment"), null));
    }

    @Test
    void theSetValuedFieldListIsIdenticalInBothImplementations() throws IOException {
        assertTrue(Files.isRegularFile(ENTITLEMENT_SOURCE),
                "expected RarEntitlement at " + ENTITLEMENT_SOURCE.toAbsolutePath()
                        + ". If it moved, these two implementations still need to agree - update the path "
                        + "rather than deleting the check.");

        Matcher m = SET_FIELDS_DECL.matcher(Files.readString(ENTITLEMENT_SOURCE));
        assertTrue(m.find(), "could not find SET_FIELDS in RarEntitlement");

        List<String> theirs = Arrays.stream(m.group(1).split(","))
                .map(s -> s.replace("\"", "").trim())
                .filter(s -> !s.isEmpty())
                .toList();

        assertEquals(theirs, Arrays.asList(RarContainment.SET_FIELDS),
                "the two containment implementations compare different fields. Whichever list is shorter "
                        + "silently stops constraining a field the other one enforces.");
    }
}
