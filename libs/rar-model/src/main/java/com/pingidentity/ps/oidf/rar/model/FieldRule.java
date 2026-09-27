/*
 * One field's rule, with its options, and what the rule means.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A {@link Rule} and its options: the {@code unit_field} a {@link Rule#LIMIT} is paired with, or the
 * {@link TypeModel nested model} a {@link Rule#OBJECT} compares by. The three questions the model
 * asks of a field are answered here: is this value the shape the rule compares ({@link #check}), is
 * the candidate's value within the ceiling's ({@link #contains}), and what is the largest value within
 * both ({@link #meet}).
 *
 * <p>Well-formedness comes first and is never skipped: a value the rule cannot compare is refused
 * whether or not the ceiling constrains the field. {@code null}, an empty array, an empty object under
 * {@link Rule#EQUAL}, and a wrong JSON type are all malformed. Treating any of them as "no constraint"
 * or "nothing requested" is how an unexamined value gets granted.
 *
 * @param rule      the rule
 * @param unitField for {@link Rule#LIMIT} only: the field whose value must be present alongside this one
 *                  (a currency beside an amount), and whose own rule is {@link Rule#EQUAL}; {@code null}
 *                  when the unit is in the field's name ({@code max_txn_eur})
 * @param nested    for {@link Rule#OBJECT} only: the fields of the object
 */
public record FieldRule(Rule rule, String unitField, TypeModel nested) {

    /** A plain decimal: digits, an optional fraction, an optional leading minus. No exponent, no spaces. */
    private static final Pattern DECIMAL = Pattern.compile("-?[0-9]+(\\.[0-9]+)?");

    public FieldRule {
        if (rule == null) {
            throw new IllegalArgumentException("rule is required");
        }
        if (unitField != null && rule != Rule.LIMIT) {
            throw new IllegalArgumentException("unit_field applies to limit only");
        }
        if ((nested != null) != (rule == Rule.OBJECT)) {
            throw new IllegalArgumentException("object needs its fields, and only object has them");
        }
    }

    /** A rule with no options. Not for {@link Rule#OBJECT}, which needs {@link #object}. */
    public static FieldRule of(Rule rule) {
        return new FieldRule(rule, null, null);
    }

    /** A {@link Rule#LIMIT} paired with a unit field. */
    public static FieldRule limit(String unitField) {
        return new FieldRule(Rule.LIMIT, unitField, null);
    }

    /** A {@link Rule#OBJECT} with the given fields. */
    public static FieldRule object(TypeModel nested) {
        return new FieldRule(Rule.OBJECT, null, nested);
    }

    /**
     * Refuses a value this rule cannot compare.
     *
     * @param value the field's value, present in the detail
     * @param where the detail and field, for the message
     */
    void check(Object value, String where) throws RarModelException {
        switch (rule) {
            case SET -> {
                List<?> list = nonEmptyList(value, where);
                for (Object item : list) {
                    if (!(item instanceof String)) {
                        throw RarModelException.malformed(where + " must be an array of strings");
                    }
                }
            }
            case SET_OF_VALUES -> {
                List<?> list = nonEmptyList(value, where);
                for (Object item : list) {
                    if (item == null) {
                        throw RarModelException.malformed(where + " must not contain null");
                    }
                }
            }
            case LIMIT -> decimal(value, where);
            case AMOUNT -> {
                if (!(value instanceof Map<?, ?> m)) {
                    throw RarModelException.malformed(where + " must be an object with amount and currency");
                }
                if (m.size() != 2 || !m.containsKey("amount") || !m.containsKey("currency")) {
                    throw RarModelException.malformed(where + " must have exactly amount and currency");
                }
                decimal(m.get("amount"), where + ".amount");
                currency(m.get("currency"), where + ".currency");
            }
            case INSTANT_LIMIT -> instant(value, where);
            case EQUAL -> {
                if (value == null) {
                    throw RarModelException.malformed(where + " must not be null");
                }
                if (value instanceof List<?> l && l.isEmpty()) {
                    throw RarModelException.malformed(where + " must not be an empty array");
                }
                if (value instanceof Map<?, ?> m && m.isEmpty()) {
                    throw RarModelException.malformed(where + " must not be an empty object");
                }
                noNulls(value, where);
            }
            case OBJECT -> {
                if (!(value instanceof Map<?, ?>)) {
                    throw RarModelException.malformed(where + " must be an object");
                }
                nested.check(asMap(value), where);
            }
            // FORBIDDEN, as the default so the switch has no branch nothing can reach.
            default -> throw RarModelException.malformed(where + " is a forbidden field");
        }
    }

    /**
     * Whether the candidate's value is within the ceiling's. Both values have passed {@link #check}.
     */
    boolean contains(Object ceiling, Object candidate) {
        switch (rule) {
            case SET:
                return strings(ceiling).containsAll(strings(candidate));
            case SET_OF_VALUES:
                return canonicals(ceiling).containsAll(canonicals(candidate));
            case LIMIT:
                return decimalOf(candidate).compareTo(decimalOf(ceiling)) <= 0;
            case AMOUNT: {
                Map<String, Object> c = asMap(ceiling);
                Map<String, Object> d = asMap(candidate);
                return c.get("currency").equals(d.get("currency"))
                        && decimalOf(d.get("amount")).compareTo(decimalOf(c.get("amount"))) <= 0;
            }
            case INSTANT_LIMIT:
                return !instantOf(candidate).isAfter(instantOf(ceiling));
            case EQUAL:
                return Json.write(ceiling).equals(Json.write(candidate));
            case OBJECT:
                return nested.contains(asMap(ceiling), asMap(candidate));
            default:
                // FORBIDDEN: a forbidden field is never present, so there is nothing to contain.
                return false;
        }
    }

    /**
     * The largest value within both, or empty when there is none (disjoint sets, unequal values,
     * different currencies). Both values have passed {@link #check}. Symmetric: the result is the same
     * value whichever way round the arguments come, including its JSON spelling.
     */
    Optional<Object> meet(Object a, Object b) {
        switch (rule) {
            case SET: {
                Set<String> right = strings(b);
                List<String> out = new ArrayList<>();
                for (String s : strings(a)) {
                    if (right.contains(s)) {
                        out.add(s);
                    }
                }
                return out.isEmpty() ? Optional.empty() : Optional.of(sortedStrings(out));
            }
            case SET_OF_VALUES: {
                Set<String> right = canonicals(b);
                Map<String, Object> out = new LinkedHashMap<>();
                for (Object item : (List<?>) a) {
                    String key = Json.write(item);
                    if (right.contains(key)) {
                        out.put(key, item);
                    }
                }
                if (out.isEmpty()) {
                    return Optional.empty();
                }
                List<String> keys = new ArrayList<>(out.keySet());
                keys.sort(null);
                List<Object> values = new ArrayList<>(keys.size());
                for (String k : keys) {
                    values.add(Json.copy(out.get(k)));
                }
                return Optional.of(values);
            }
            case LIMIT:
                return Optional.of(smaller(a, b, decimalOf(a).compareTo(decimalOf(b))));
            case AMOUNT: {
                Map<String, Object> x = asMap(a);
                Map<String, Object> y = asMap(b);
                if (!x.get("currency").equals(y.get("currency"))) {
                    return Optional.empty();
                }
                return Optional.of(smaller(a, b, decimalOf(x.get("amount")).compareTo(decimalOf(y.get("amount")))));
            }
            case INSTANT_LIMIT:
                return Optional.of(smaller(a, b, instantOf(a).compareTo(instantOf(b))));
            case EQUAL:
                return Json.write(a).equals(Json.write(b)) ? Optional.of(Json.copy(a)) : Optional.empty();
            case OBJECT:
                return nested.meet(asMap(a), asMap(b)).map(m -> m);
            default:
                // FORBIDDEN: never present on either side.
                return Optional.empty();
        }
    }

    /**
     * The smaller by the comparison, and on a tie the one with the smaller canonical spelling, so the
     * meet of {@code 100} and {@code "100"} is the same value in either order.
     */
    private static Object smaller(Object a, Object b, int comparison) {
        if (comparison == 0) {
            comparison = Json.write(a).compareTo(Json.write(b));
        }
        return Json.copy(comparison <= 0 ? a : b);
    }

    /** The rule as the fingerprint sees it. */
    Object describe() {
        if (rule == Rule.LIMIT && unitField != null) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("rule", rule.json());
            out.put("unit_field", unitField);
            return out;
        }
        if (rule == Rule.OBJECT) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("rule", rule.json());
            out.put("fields", nested.describeFields());
            return out;
        }
        return rule.json();
    }

    // ---- value readers ----

    private static List<?> nonEmptyList(Object value, String where) throws RarModelException {
        if (!(value instanceof List<?> list)) {
            throw RarModelException.malformed(where + " must be an array");
        }
        if (list.isEmpty()) {
            throw RarModelException.malformed(where + " must not be an empty array");
        }
        return list;
    }

    private static void noNulls(Object value, String where) throws RarModelException {
        if (value instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (e.getValue() == null) {
                    throw RarModelException.malformed(where + " must not contain null");
                }
                noNulls(e.getValue(), where);
            }
        } else if (value instanceof List<?> l) {
            for (Object item : l) {
                if (item == null) {
                    throw RarModelException.malformed(where + " must not contain null");
                }
                noNulls(item, where);
            }
        }
    }

    /** A decimal as a number or a plain decimal string; anything else is malformed. */
    static BigDecimal decimal(Object value, String where) throws RarModelException {
        if (value instanceof Number n) {
            return Json.decimal(n);
        }
        if (value instanceof String s && DECIMAL.matcher(s).matches()) {
            return new BigDecimal(s);
        }
        throw RarModelException.malformed(where + " must be a number or a plain decimal string");
    }

    private static BigDecimal decimalOf(Object checked) {
        return checked instanceof Number n ? Json.decimal(n) : new BigDecimal((String) checked);
    }

    private static void currency(Object value, String where) throws RarModelException {
        if (!(value instanceof String s) || s.isBlank()) {
            throw RarModelException.malformed(where + " must be a non-empty string");
        }
    }

    /**
     * An RFC 3339 date-time with its offset, or a full date, which means the end of that day in UTC:
     * "valid until 2026-12-31" allows the whole of the 31st, so its instant is the start of the 1st.
     */
    static Instant instant(Object value, String where) throws RarModelException {
        if (!(value instanceof String s)) {
            throw RarModelException.malformed(where + " must be an RFC 3339 date-time or date string");
        }
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (DateTimeParseException notDateTime) {
            try {
                return LocalDate.parse(s).plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
            } catch (DateTimeParseException notDate) {
                throw RarModelException.malformed(where + " must be an RFC 3339 date-time or date string");
            }
        }
    }

    private static Instant instantOf(Object checked) {
        try {
            return instant(checked, "");
        } catch (RarModelException e) {
            throw new IllegalStateException("checked value failed to parse", e);
        }
    }

    private static Set<String> strings(Object list) {
        Set<String> out = new LinkedHashSet<>();
        for (Object item : (List<?>) list) {
            out.add((String) item);
        }
        return out;
    }

    private static List<Object> sortedStrings(List<String> strings) {
        List<String> sorted = new ArrayList<>(new LinkedHashSet<>(strings));
        sorted.sort(null);
        return new ArrayList<>(sorted);
    }

    private static Set<String> canonicals(Object list) {
        Set<String> out = new LinkedHashSet<>();
        for (Object item : (List<?>) list) {
            out.add(Json.write(item));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }
}
