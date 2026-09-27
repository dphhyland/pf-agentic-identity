/*
 * Why the model refused something, in terms a caller can map to its own error.
 */
package com.pingidentity.ps.oidf.rar.model;

/**
 * A refusal by the model. Every refusal carries a {@link Reason}; the message names the detail, the
 * field and what was wrong with it, and never repeats the value (a detail can carry an account number).
 *
 * <p>The library knows nothing of OAuth error codes: the reason is for the caller to map. As a guide,
 * {@link Reason#MALFORMED}, {@link Reason#TOO_LARGE}, {@link Reason#UNDECLARED_FIELD} and
 * {@link Reason#UNMODELLED_TYPE} describe a request the server cannot process and answer
 * {@code invalid_authorization_details} (RFC 9396 §5); {@link Reason#EXCEEDS_CEILING} is the case
 * CAS §7.1 says an authorization server answers with {@code invalid_authorization_details} too
 * (today's callers answer {@code access_denied}; which one they say is their decision, not this
 * library's); {@link Reason#MODEL_INVALID} is a configuration fault - the component should refuse to
 * start rather than serve with a model it could not load.
 */
public final class RarModelException extends Exception {

    /** What kind of refusal this is. */
    public enum Reason {
        /** A detail, a ceiling entry or a value in one is not the shape its rule compares. */
        MALFORMED,
        /** A size limit in {@link Limits} was exceeded. */
        TOO_LARGE,
        /** A detail carries a field its type's model does not declare. */
        UNDECLARED_FIELD,
        /** No model exists for the detail's type and the common-fields fallback is off. */
        UNMODELLED_TYPE,
        /** The candidate is not within any same-type entry of the ceiling. */
        EXCEEDS_CEILING,
        /** The model definition itself (built-in or loaded) could not be used. */
        MODEL_INVALID
    }

    private final Reason reason;

    public RarModelException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    static RarModelException malformed(String message) {
        return new RarModelException(Reason.MALFORMED, message);
    }

    static RarModelException tooLarge(String message) {
        return new RarModelException(Reason.TOO_LARGE, message);
    }

    static RarModelException undeclared(String message) {
        return new RarModelException(Reason.UNDECLARED_FIELD, message);
    }

    static RarModelException unmodelled(String message) {
        return new RarModelException(Reason.UNMODELLED_TYPE, message);
    }

    static RarModelException exceeds(String message) {
        return new RarModelException(Reason.EXCEEDS_CEILING, message);
    }

    static RarModelException modelInvalid(String message) {
        return new RarModelException(Reason.MODEL_INVALID, message);
    }

    /**
     * A name from a request as a message may carry it: quoted, cut at 64 characters so a 2048-character
     * name cannot fill a log line, and with every character written as a {@code \}{@code uXXXX} escape
     * that could start a line of its own, change what an operator reads or hide from them: the quote and
     * the backslash, C0 and C1 controls ({@code NEL} among them), the line and paragraph separators,
     * format characters (the bidirectional overrides, zero-width spaces), and each half of a surrogate
     * pair, so the cut never leaves half of one. {@code null}, which no parser produces, is shown as
     * {@code null}, unquoted.
     */
    static String quote(String name) {
        if (name == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder("'");
        int shown = Math.min(name.length(), 64);
        for (int i = 0; i < shown; i++) {
            char c = name.charAt(i);
            if (c == '\'' || c == '\\' || hidden(c)) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        if (name.length() > shown) {
            out.append("...");
        }
        return out.append('\'').toString();
    }

    /** Whether a character is one a log reader would not see as itself. */
    private static boolean hidden(char c) {
        int type = Character.getType(c);
        return type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR || type == Character.SURROGATE;
    }
}
