/*
 * The subset of the RFC 7644 filter language the SSF SCIM endpoint answers.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * A parsed {@code filter} query parameter (RFC 7644 §3.4.2.2), over the attributes the SSF SCIM endpoint keeps
 * (plan item H-SSF-4). Supported, and nothing else:
 *
 * <ul>
 *   <li>attributes, named with or without their schema URN, in any case ("Attribute names and attribute operators
 *       used in filters are case insensitive"): {@code id}, {@code userName}, {@code externalId}, {@code active},
 *       {@code emails.value} (and {@code emails}, read as its value), and the SSF extension's {@code streams}
 *       ({@value ScimSubjectService#SSF_EXT}{@code :streams});</li>
 *   <li>the operators {@code eq}, {@code ne}, {@code co}, {@code sw}, {@code ew} and {@code pr}; on {@code active}
 *       only {@code eq}, {@code ne} and {@code pr};</li>
 *   <li>{@code and}, {@code or}, {@code not ( ... )} and grouping with round brackets.</li>
 * </ul>
 *
 * <p>Anything else - {@code gt}, {@code ge}, {@code lt}, {@code le}, a value path such as
 * {@code emails[type eq "work"]}, another attribute, a value of the wrong type, a filter that does not parse - is
 * refused with 400 and {@code scimType} {@code invalidFilter}, which Table 9 defines as "The specified filter syntax was
 * invalid (does not comply with Figure 1), or the specified attribute and filter comparison combination is not
 * supported." String comparisons follow each attribute's {@code caseExact} in RFC 7643 - §3.1 for {@code id} and
 * {@code externalId} ("caseExact" as "true"), §4.1.1 for {@code userName} ("case insensitive"), §8.7.1 for
 * {@code emails.value} ({@code "caseExact" : false}) - and stream ids exactly.
 */
public final class ScimFilter {

    /** The attributes a filter may name. */
    public enum Attribute {
        ID(true, false),
        USER_NAME(false, false),
        EXTERNAL_ID(true, false),
        ACTIVE(true, true),
        EMAILS_VALUE(false, false),
        STREAMS(true, false);

        final boolean caseExact;
        final boolean bool;

        Attribute(boolean caseExact, boolean bool) {
            this.caseExact = caseExact;
            this.bool = bool;
        }
    }

    /** The longest filter parsed, and the deepest nesting: a bound on the work one query parameter can ask for. */
    static final int MAX_LENGTH = 2048;
    static final int MAX_DEPTH = 16;

    private static final String CORE = "urn:ietf:params:scim:schemas:core:2.0:user:";
    private static final String EXT = ScimSubjectService.SSF_EXT.toLowerCase(Locale.ROOT) + ":";
    private static final Map<String, Attribute> NAMES = Map.of(
            "id", Attribute.ID,
            "username", Attribute.USER_NAME,
            "externalid", Attribute.EXTERNAL_ID,
            "active", Attribute.ACTIVE,
            "emails", Attribute.EMAILS_VALUE,
            "emails.value", Attribute.EMAILS_VALUE);

    /** A resource as a filter reads it: each attribute's values, empty when it has none. */
    public interface Resource extends Function<Attribute, List<Object>> {
    }

    private interface Node {
        boolean test(Resource r);
    }

    private final Node root;

    private ScimFilter(Node root) {
        this.root = root;
    }

    /** Whether {@code resource} matches. */
    public boolean matches(Resource resource) {
        return this.root.test(resource);
    }

    /**
     * Parses {@code filter}.
     *
     * @throws ScimException 400 {@code invalidFilter} for a filter outside the supported subset
     */
    public static ScimFilter parse(String filter) {
        if (filter == null || filter.isBlank()) {
            throw invalid("the filter is empty");
        }
        if (filter.length() > MAX_LENGTH) {
            throw invalid("the filter is longer than " + MAX_LENGTH + " characters");
        }
        Parser p = new Parser(tokens(filter));
        Node n = p.or(0);
        if (p.pos < p.tokens.size()) {
            throw invalid("unexpected '" + p.tokens.get(p.pos).text + "'");
        }
        return new ScimFilter(n);
    }

    static ScimException invalid(String detail) {
        return ScimException.badRequest("invalidFilter", detail);
    }

    // ─────────────────────────────── tokens ───────────────────────────────

    private record Token(String text, boolean string) {
    }

    private static List<Token> tokens(String s) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t') {
                i++;
            } else if (c == '(' || c == ')') {
                out.add(new Token(String.valueOf(c), false));
                i++;
            } else if (c == '[' || c == ']') {
                throw invalid("value paths ('[...]') are not supported");
            } else if (c == '"') {
                StringBuilder v = new StringBuilder();
                i++;
                boolean closed = false;
                while (i < s.length()) {
                    char d = s.charAt(i++);
                    if (d == '"') {
                        closed = true;
                        break;
                    }
                    if (d == '\\') {
                        if (i >= s.length()) {
                            break;
                        }
                        char e = s.charAt(i++);
                        switch (e) {
                            case '"', '\\', '/' -> v.append(e);
                            case 'b' -> v.append('\b');
                            case 'f' -> v.append('\f');
                            case 'n' -> v.append('\n');
                            case 'r' -> v.append('\r');
                            case 't' -> v.append('\t');
                            case 'u' -> {
                                if (i + 4 > s.length()) {
                                    throw invalid("a \\u escape is cut short");
                                }
                                try {
                                    v.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                                } catch (NumberFormatException ex) {
                                    throw invalid("a \\u escape is not hexadecimal");
                                }
                                i += 4;
                            }
                            default -> throw invalid("unknown escape \\" + e);
                        }
                    } else {
                        v.append(d);
                    }
                }
                if (!closed) {
                    throw invalid("a string is not closed");
                }
                out.add(new Token(v.toString(), true));
            } else {
                int start = i;
                while (i < s.length() && " \t()[]\"".indexOf(s.charAt(i)) < 0) {
                    i++;
                }
                out.add(new Token(s.substring(start, i), false));
            }
        }
        return out;
    }

    // ─────────────────────────────── grammar ───────────────────────────────

    private static final class Parser {
        private final List<Token> tokens;
        private int pos;

        Parser(List<Token> tokens) {
            this.tokens = tokens;
        }

        private boolean keyword(String k) {
            if (this.pos < this.tokens.size() && !this.tokens.get(this.pos).string
                    && this.tokens.get(this.pos).text.equalsIgnoreCase(k)) {
                this.pos++;
                return true;
            }
            return false;
        }

        private Token next(String expected) {
            if (this.pos >= this.tokens.size()) {
                throw invalid("the filter ends where " + expected + " was expected");
            }
            return this.tokens.get(this.pos++);
        }

        Node or(int depth) {
            if (depth > MAX_DEPTH) {
                throw invalid("the filter nests deeper than " + MAX_DEPTH);
            }
            Node left = and(depth);
            while (keyword("or")) {
                Node l = left;
                Node r = and(depth);
                left = res -> l.test(res) || r.test(res);
            }
            return left;
        }

        Node and(int depth) {
            Node left = unary(depth);
            while (keyword("and")) {
                Node l = left;
                Node r = unary(depth);
                left = res -> l.test(res) && r.test(res);
            }
            return left;
        }

        Node unary(int depth) {
            if (keyword("not")) {
                Node inner = group(depth);
                return res -> !inner.test(res);
            }
            if (this.pos < this.tokens.size() && !this.tokens.get(this.pos).string && "(".equals(this.tokens.get(this.pos).text)) {
                return group(depth);
            }
            return comparison();
        }

        Node group(int depth) {
            Token open = next("'('");
            if (open.string || !"(".equals(open.text)) {
                throw invalid("expected '(' but found '" + open.text + "'");
            }
            Node inner = or(depth + 1);
            Token close = next("')'");
            if (close.string || !")".equals(close.text)) {
                throw invalid("expected ')' but found '" + close.text + "'");
            }
            return inner;
        }

        Node comparison() {
            Token name = next("an attribute");
            if (name.string || "(".equals(name.text) || ")".equals(name.text)) {
                throw invalid("expected an attribute but found '" + name.text + "'");
            }
            Attribute attr = attribute(name.text);
            Token op = next("an operator");
            String operator = op.string ? "" : op.text.toLowerCase(Locale.ROOT);
            if ("pr".equals(operator)) {
                return res -> !res.apply(attr).isEmpty();
            }
            if (!List.of("eq", "ne", "co", "sw", "ew").contains(operator)) {
                throw invalid("the operator '" + op.text + "' is not supported; this endpoint takes eq, ne, co, sw, ew and pr");
            }
            Token value = next("a value");
            if (attr.bool) {
                if (value.string || !("true".equalsIgnoreCase(value.text) || "false".equalsIgnoreCase(value.text))
                        || !("eq".equals(operator) || "ne".equals(operator))) {
                    throw invalid("active is compared only with eq or ne, to true or false");
                }
                Boolean wanted = Boolean.valueOf(value.text.toLowerCase(Locale.ROOT));
                boolean eq = "eq".equals(operator);
                return res -> res.apply(attr).contains(wanted) == eq;
            }
            if (!value.string) {
                if ("null".equalsIgnoreCase(value.text) && ("eq".equals(operator) || "ne".equals(operator))) {
                    boolean eq = "eq".equals(operator);
                    return res -> res.apply(attr).isEmpty() == eq;
                }
                throw invalid(name.text + " is a string, and is compared with a quoted string");
            }
            String wanted = attr.caseExact ? value.text : value.text.toLowerCase(Locale.ROOT);
            return res -> {
                boolean any = false;
                for (Object v : res.apply(attr)) {
                    String have = attr.caseExact ? String.valueOf(v) : String.valueOf(v).toLowerCase(Locale.ROOT);
                    boolean hit = switch (operator) {
                        case "eq", "ne" -> have.equals(wanted);
                        case "co" -> have.contains(wanted);
                        case "sw" -> have.startsWith(wanted);
                        default -> have.endsWith(wanted);
                    };
                    any |= hit;
                }
                return "ne".equals(operator) ? !any : any;
            };
        }

        private static Attribute attribute(String raw) {
            String name = raw.toLowerCase(Locale.ROOT);
            if (name.startsWith(EXT)) {
                if ("streams".equals(name.substring(EXT.length()))) {
                    return Attribute.STREAMS;
                }
                throw invalid("the SSF extension's only filterable attribute is streams");
            }
            if (name.startsWith(CORE)) {
                name = name.substring(CORE.length());
            }
            Attribute a = NAMES.get(name);
            if (a == null) {
                throw invalid("filtering on '" + raw + "' is not supported; this endpoint filters on id, userName,"
                        + " externalId, active, emails.value and " + ScimSubjectService.SSF_EXT + ":streams");
            }
            return a;
        }
    }
}
