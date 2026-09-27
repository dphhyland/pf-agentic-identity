/*
 * Randomised properties of contains, authorize and intersect over the built-in types.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * The algebra the plan asks of the three operations, checked over random well-formed details of the
 * three built-in types. The repo has no property-testing library and this module has no dependencies,
 * so the generator is a seeded {@link Random}: every run sees the same cases, and a failure names the
 * iteration and the inputs so it can be turned into a vector.
 *
 * <p>What is checked: {@code contains} is reflexive; {@code intersect} is within both arguments, is
 * commutative, is the greatest such thing (anything within both is within the meet), is monotone in
 * each argument, idempotent and associative; and {@code authorize} agrees with {@code contains} under
 * STRICT, keeps the candidate's own values under INHERIT, and never grants outside the ceiling.
 */
@SuppressWarnings("unchecked")
class RarModelPropertyTest {

    private static final long SEED = 20260927L;
    private static final int ITERATIONS = 1500;

    private final RarModels models = RarModels.builtIn();
    private final Random random = new Random(SEED);

    @Test
    void containsIsReflexive() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            assertTrue(models.contains(a, a), "iteration " + i + ": " + Json.write(a));
        }
    }

    /** {@code intersect(a, b)} is within {@code a} and within {@code b}. */
    @Test
    @Requirement("CAS §7(3)")
    void meetIsWithinBothArguments() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            List<Map<String, Object>> b = list();
            List<Map<String, Object>> m = models.intersect(a, b);
            String where = "iteration " + i + ": a=" + Json.write(a) + " b=" + Json.write(b) + " meet=" + Json.write(m);
            assertTrue(models.contains(a, m), where);
            assertTrue(models.contains(b, m), where);
        }
    }

    @Test
    void meetIsCommutative() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            List<Map<String, Object>> b = list();
            assertEquals(Json.write(models.intersect(a, b)), Json.write(models.intersect(b, a)),
                    "iteration " + i + ": a=" + Json.write(a) + " b=" + Json.write(b));
        }
    }

    /**
     * Anything within both {@code a} and {@code b} is within their meet: the meet is the greatest lower
     * bound. {@code c} is random; {@code a} and {@code b} are widenings of it, so every iteration is a
     * witness, and random pairs are tried as well.
     */
    @Test
    void meetIsTheGreatestLowerBound() throws Exception {
        int witnessed = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> c = list();
            List<Map<String, Object>> a = i % 2 == 0 ? widen(c) : list();
            List<Map<String, Object>> b = widen(c);
            if (models.contains(a, c) && models.contains(b, c)) {
                witnessed++;
                assertTrue(models.contains(models.intersect(a, b), c), "iteration " + i + ": a=" + Json.write(a)
                        + " b=" + Json.write(b) + " c=" + Json.write(c) + " meet=" + Json.write(models.intersect(a, b)));
            }
        }
        assertTrue(witnessed > ITERATIONS / 2, "too few witnesses to mean anything: " + witnessed);
    }

    /** If {@code a2} is within {@code a}, then {@code intersect(a2, b)} is within {@code intersect(a, b)}. */
    @Test
    void meetIsMonotone() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            List<Map<String, Object>> b = list();
            List<Map<String, Object>> a2 = i % 2 == 0 ? narrow(a) : models.intersect(a, list());
            assertTrue(models.contains(a, a2), "iteration " + i + ": a=" + Json.write(a) + " a2=" + Json.write(a2));
            assertTrue(models.contains(models.intersect(a, b), models.intersect(a2, b)),
                    "iteration " + i + ": a=" + Json.write(a) + " a2=" + Json.write(a2) + " b=" + Json.write(b));
        }
    }

    @Test
    void meetIsIdempotent() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            List<Map<String, Object>> m = models.intersect(a, a);
            assertTrue(models.contains(a, m) && models.contains(m, a), "iteration " + i + ": " + Json.write(a));
        }
    }

    @Test
    void meetIsAssociative() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            List<Map<String, Object>> a = list();
            List<Map<String, Object>> b = list();
            List<Map<String, Object>> c = list();
            List<Map<String, Object>> left = models.intersect(a, models.intersect(b, c));
            List<Map<String, Object>> right = models.intersect(models.intersect(a, b), c);
            assertTrue(models.contains(left, right) && models.contains(right, left),
                    "iteration " + i + ": a=" + Json.write(a) + " b=" + Json.write(b) + " c=" + Json.write(c));
        }
    }

    /** STRICT authorize succeeds exactly when contains says yes, and what it grants is the candidate. */
    @Test
    @Requirement("CAS §7.1")
    void strictAuthorizeAgreesWithContains() throws Exception {
        int granted = 0;
        for (int i = 0; i < ITERATIONS * 2; i++) {
            List<Map<String, Object>> ceiling = list();
            List<Map<String, Object>> candidate = i % 2 == 0 ? narrow(ceiling) : list();
            boolean within = models.contains(ceiling, candidate);
            try {
                List<Map<String, Object>> g = models.authorize(candidate, ceiling, Omission.STRICT);
                assertTrue(within, "iteration " + i + ": granted but not contained");
                assertEquals(Json.write(candidate), Json.write(g));
                granted++;
            } catch (RarModelException e) {
                assertEquals(RarModelException.Reason.EXCEEDS_CEILING, e.reason(), "iteration " + i + ": " + e.getMessage());
                assertFalse(within, "iteration " + i + ": contained but refused");
            }
        }
        assertTrue(granted > ITERATIONS / 2, "too few grants to mean anything: " + granted);
    }

    /** INHERIT authorize never grants outside the ceiling and keeps every value the candidate sent. */
    @Test
    @Requirement({"PROFILE §7(2)", "CAS §7(1)"})
    void inheritAuthorizeStaysWithinTheCeilingAndKeepsTheCandidatesValues() throws Exception {
        int granted = 0;
        for (int i = 0; i < ITERATIONS * 2; i++) {
            List<Map<String, Object>> ceiling = list();
            List<Map<String, Object>> candidate = i % 2 == 0 ? narrow(ceiling) : list();
            List<Map<String, Object>> g;
            try {
                g = models.authorize(candidate, ceiling, Omission.INHERIT);
            } catch (RarModelException e) {
                assertEquals(RarModelException.Reason.EXCEEDS_CEILING, e.reason(), "iteration " + i + ": " + e.getMessage());
                continue;
            } catch (IllegalStateException e) {
                fail("iteration " + i + ": the post-condition fired: " + e.getMessage());
                return;
            }
            granted++;
            assertTrue(models.contains(ceiling, g), "iteration " + i + ": granted outside the ceiling");
            assertEquals(candidate.size(), g.size());
            for (int k = 0; k < candidate.size(); k++) {
                for (Map.Entry<String, Object> e : candidate.get(k).entrySet()) {
                    if (e.getValue() instanceof Map<?, ?>) {
                        continue; // an object may have gained inherited members; its own members are checked by contains
                    }
                    assertEquals(Json.write(e.getValue()), Json.write(g.get(k).get(e.getKey())),
                            "iteration " + i + ": field " + e.getKey() + " changed");
                }
            }
        }
        assertTrue(granted > ITERATIONS / 2, "too few grants to mean anything: " + granted);
    }

    // ---- generator ----

    private static final String[] ACTIONS = {"read", "write", "initiate", "cancel"};
    private static final String[] LOCATIONS = {"https://a.example", "https://b.example"};
    private static final String[] REGIONS = {"EMEA", "APAC", "AMER"};
    private static final Object[] LIMITS = {100, "500", "1000.00", 5000};
    private static final String[] CURRENCIES = {"EUR", "USD"};
    private static final Object[] ACCOUNTS = {Map.of("iban", "DE1"), Map.of("iban", "DE2"), "acc-3"};
    private static final String[] INSTANTS = {"2026-12-31", "2026-06-30T12:00:00Z", "2027-01-01T00:00:00+01:00"};
    private static final String[] NAMES = {"Merchant A", "Merchant B"};
    private static final String[] IDS = {"id-0", "id-1"};

    private List<Map<String, Object>> list() {
        int n = 1 + random.nextInt(3);
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(detail());
        }
        return out;
    }

    private Map<String, Object> detail() {
        Map<String, Object> d = new LinkedHashMap<>();
        switch (random.nextInt(3)) {
            case 0 -> {
                d.put("type", "sales_agent");
                common(d);
                maybe(d, "sales_regions", () -> subset(REGIONS));
                maybe(d, "max_txn_eur", () -> pick(LIMITS));
            }
            case 1 -> {
                d.put("type", "payment_initiation");
                common(d);
                maybe(d, "instructedAmount", this::amount);
                if (random.nextInt(4) == 0) {
                    d.put("amount", pick(LIMITS));
                    d.put("currency", pick(CURRENCIES));
                } else {
                    maybe(d, "currency", () -> pick(CURRENCIES));
                }
                maybe(d, "creditorName", () -> pick(NAMES));
                maybe(d, "creditorAccount", () -> pick(ACCOUNTS));
            }
            default -> {
                d.put("type", "account_information");
                common(d);
                maybe(d, "accounts", () -> subset(ACCOUNTS));
                maybe(d, "access", () -> {
                    Map<String, Object> access = new LinkedHashMap<>();
                    maybe(access, "accounts", () -> subset(ACCOUNTS));
                    maybe(access, "balances", () -> subset(ACCOUNTS));
                    return access;
                });
                maybe(d, "validUntil", () -> pick(INSTANTS));
                maybe(d, "recurringIndicator", () -> random.nextBoolean());
            }
        }
        return d;
    }

    private void common(Map<String, Object> d) {
        maybe(d, "actions", () -> subset(ACTIONS));
        maybe(d, "locations", () -> subset(LOCATIONS));
        maybe(d, "identifier", () -> pick(IDS));
    }

    /** A field is present about two times in five: dense enough to constrain, sparse enough to meet. */
    private void maybe(Map<String, Object> d, String field, java.util.function.Supplier<Object> value) {
        if (random.nextInt(5) < 2) {
            d.put(field, value.get());
        }
    }

    private Object pick(Object[] pool) {
        return pool[random.nextInt(pool.length)];
    }

    private List<Object> subset(Object[] pool) {
        return subset(java.util.Arrays.asList(pool));
    }

    private List<Object> subset(List<?> pool) {
        List<Object> out = new ArrayList<>();
        for (Object o : pool) {
            if (random.nextBoolean()) {
                out.add(o);
            }
        }
        if (out.isEmpty()) {
            out.add(pool.get(random.nextInt(pool.size())));
        }
        return out;
    }

    private Map<String, Object> amount() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("currency", pick(CURRENCIES));
        m.put("amount", pick(LIMITS));
        assertNotNull(m.get("amount"));
        return m;
    }

    /** Each detail narrowed by its own type's rules, so the result is within the original by construction. */
    private List<Map<String, Object>> narrow(List<Map<String, Object>> details) throws RarModelException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> d : details) {
            if (random.nextInt(4) == 0) {
                continue; // fewer details is narrower too
            }
            out.add(narrow(models.model((String) d.get("type")), d, true));
        }
        return out;
    }

    private Map<String, Object> narrow(TypeModel model, Map<String, Object> d, boolean top) throws RarModelException {
        Map<String, Object> out = new LinkedHashMap<>();
        if (top) {
            out.put("type", d.get("type"));
        }
        for (Map.Entry<String, FieldRule> e : model.fields().entrySet()) {
            String f = e.getKey();
            if (d.containsKey(f)) {
                out.put(f, narrowValue(e.getValue(), d.get(f)));
            } else if (e.getValue().rule() == Rule.SET && random.nextInt(3) == 0) {
                out.put(f, subset(ACTIONS)); // a field the ceiling omits is unconstrained
            }
        }
        return out;
    }

    private Object narrowValue(FieldRule rule, Object v) throws RarModelException {
        switch (rule.rule()) {
            case SET:
            case SET_OF_VALUES:
                return subset((List<?>) v);
            case LIMIT:
                return atMost(v, LIMITS);
            case AMOUNT: {
                Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) v);
                m.put("amount", atMost(m.get("amount"), LIMITS));
                return m;
            }
            case INSTANT_LIMIT: {
                List<Object> earlier = new ArrayList<>();
                for (String s : INSTANTS) {
                    if (!FieldRule.instant(s, "").isAfter(FieldRule.instant(v, ""))) {
                        earlier.add(s);
                    }
                }
                return earlier.get(random.nextInt(earlier.size()));
            }
            case OBJECT:
                return narrow(rule.nested(), (Map<String, Object>) v, false);
            default:
                return v;
        }
    }

    private Object atMost(Object v, Object[] pool) throws RarModelException {
        List<Object> smaller = new ArrayList<>();
        for (Object o : pool) {
            if (FieldRule.decimal(o, "").compareTo(FieldRule.decimal(v, "")) <= 0) {
                smaller.add(o);
            }
        }
        smaller.add(v);
        return smaller.get(random.nextInt(smaller.size()));
    }

    /** Each detail widened by its own type's rules, so the original is within the result by construction. */
    private List<Map<String, Object>> widen(List<Map<String, Object>> details) throws RarModelException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> d : details) {
            out.add(widen(models.model((String) d.get("type")), d, true));
        }
        if (random.nextInt(3) == 0) {
            out.add(detail()); // an unrelated entry widens the list
        }
        return out;
    }

    private Map<String, Object> widen(TypeModel model, Map<String, Object> d, boolean top) throws RarModelException {
        Map<String, Object> out = new LinkedHashMap<>();
        if (top) {
            out.put("type", d.get("type"));
        }
        for (Map.Entry<String, FieldRule> e : model.fields().entrySet()) {
            String f = e.getKey();
            if (!d.containsKey(f)) {
                continue;
            }
            boolean keepForPairing = f.equals("currency") && d.containsKey("amount");
            if (!keepForPairing && random.nextInt(3) == 0) {
                if (f.equals("amount")) {
                    continue; // dropping the amount leaves the currency, which is fine on its own
                }
                continue; // dropping a field removes its constraint
            }
            out.put(f, widenValue(e.getValue(), d.get(f)));
        }
        return out;
    }

    private Object widenValue(FieldRule rule, Object v) throws RarModelException {
        switch (rule.rule()) {
            case SET: {
                List<Object> out = new ArrayList<>((List<?>) v);
                for (Object o : ACTIONS) {
                    if (!out.contains(o) && random.nextBoolean()) {
                        out.add(o);
                    }
                }
                return out;
            }
            case SET_OF_VALUES: {
                List<Object> out = new ArrayList<>((List<?>) v);
                for (Object o : ACCOUNTS) {
                    if (!out.contains(o) && random.nextBoolean()) {
                        out.add(o);
                    }
                }
                return out;
            }
            case LIMIT:
                return atLeast(v, LIMITS);
            case AMOUNT: {
                Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) v);
                m.put("amount", atLeast(m.get("amount"), LIMITS));
                return m;
            }
            case INSTANT_LIMIT: {
                List<Object> later = new ArrayList<>();
                for (String s : INSTANTS) {
                    if (!FieldRule.instant(s, "").isBefore(FieldRule.instant(v, ""))) {
                        later.add(s);
                    }
                }
                return later.get(random.nextInt(later.size()));
            }
            case OBJECT:
                return widen(rule.nested(), (Map<String, Object>) v, false);
            default:
                return v;
        }
    }

    private Object atLeast(Object v, Object[] pool) throws RarModelException {
        List<Object> larger = new ArrayList<>();
        for (Object o : pool) {
            if (FieldRule.decimal(o, "").compareTo(FieldRule.decimal(v, "")) >= 0) {
                larger.add(o);
            }
        }
        larger.add(v);
        return larger.get(random.nextInt(larger.size()));
    }
}
