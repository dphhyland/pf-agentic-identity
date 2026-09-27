/*
 * Every vector case, as its own dynamic test.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Runs {@link Vectors#RESOURCE} through the library, one test per named case. The cases carry the
 * clause each pins in their {@code requirements}; the class-level tags below are the clauses the file
 * as a whole pins - CAS §7 rules 1 to 3 and §7.1 and RFC 9396 §2.2 and §6.1 - so the coverage report
 * sees them, since it reads annotations and not JSON.
 *
 * <p>CAS §7 rule 1: "The issued authorization_details MUST be a subset of the applicable ceiling.
 * Subset semantics are defined per authorization_details type, following [RFC9396]: for a candidate to
 * be within the ceiling there must be a ceiling object of the same type whose constraints it does not
 * exceed (arrays: subset; numeric limits: ≤; absent ceiling field: unconstrained)." Rule 2: "An empty
 * or absent authorization_details request means the instance asks for its full ceiling; the CAS
 * issues the ceiling of the matched binding." Rule 3: "A request exceeding the ceiling is handled per
 * the advertised narrowing_behavior: "reject" → access_denied; "narrow" → issue the intersection."
 * §7.1: the AS "MUST reject requests exceeding it with invalid_authorization_details". RFC 9396 §2.2:
 * "locations: An array of strings", "actions: An array of strings", "datatypes: An array of strings",
 * "identifier: A string identifier", "privileges: An array of strings". RFC 9396 §6.1: "there is no
 * standardized mechanism to compare two arbitrary authorization detail requests. An AS should not
 * rely on simple object comparison in most cases".
 */
@Requirement({"CAS §7(1)", "CAS §7(2)", "CAS §7(3)", "CAS §7.1", "RFC9396 §2.2", "RFC9396 §6.1"})
class RarModelVectorsTest {

    @TestFactory
    Stream<DynamicTest> vectors() {
        List<Vectors.Case> cases = Vectors.load();
        assertTrue(cases.size() > 100, "the vector file should carry every rule and shape; only " + cases.size());
        return cases.stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> assertNull(Vectors.mismatch(c), c.name())));
    }

    /** Every case names an op the runner knows and an expectation it can compare. */
    @Test
    void everyCaseIsRunnable() {
        for (Vectors.Case c : Vectors.load()) {
            assertTrue(List.of("contains", "authorize", "intersect", "validate", "details", "fullCeiling", "load", "fingerprint")
                    .contains(c.op()), c.name() + " op " + c.op());
            assertTrue(c.expect() != null, c.name() + " has no expectation");
        }
    }
}
