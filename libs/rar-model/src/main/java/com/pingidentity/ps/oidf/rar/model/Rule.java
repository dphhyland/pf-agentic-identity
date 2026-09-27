/*
 * The eight ways a field can be compared.
 */
package com.pingidentity.ps.oidf.rar.model;

/**
 * How a field of an {@code authorization_details} type is compared between a ceiling and a candidate.
 * The JSON name is what a models file writes; {@link FieldRule} holds a rule with its options and
 * carries the semantics.
 */
public enum Rule {
    /** An array of strings; the candidate's values must all be among the ceiling's. */
    SET("set"),
    /** An array of any JSON values (an account object, say), compared as a set by structural equality. */
    SET_OF_VALUES("set_of_values"),
    /** A decimal, as a number or a plain decimal string; the candidate's is at most the ceiling's. */
    LIMIT("limit"),
    /** The RFC 9396 {@code instructedAmount} object: {@code currency} equal and {@code amount} at most. */
    AMOUNT("amount"),
    /** An RFC 3339 date-time, or a date meaning the end of that day; the candidate's is no later. */
    INSTANT_LIMIT("instant_limit"),
    /** Any JSON value, which must be structurally equal. */
    EQUAL("equal"),
    /** A JSON object with field rules of its own. */
    OBJECT("object"),
    /** A field that must not appear at all. */
    FORBIDDEN("forbidden");

    private final String json;

    Rule(String json) {
        this.json = json;
    }

    /** The name a models file uses. */
    public String json() {
        return json;
    }

    /** The rule a models file names, or {@link RarModelException.Reason#MODEL_INVALID}. */
    public static Rule fromJson(String name) throws RarModelException {
        for (Rule r : values()) {
            if (r.json.equals(name)) {
                return r;
            }
        }
        throw RarModelException.modelInvalid("unknown rule '" + name + "'");
    }
}
