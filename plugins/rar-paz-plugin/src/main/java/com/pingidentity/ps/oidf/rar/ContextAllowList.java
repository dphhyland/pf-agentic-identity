/*
 * Which members of an AuthZEN decision's context may reach a detail, per type (plan item H-RAR-1).
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * The processor's "{@value #FIELD}" field: for each detail type, the members of an AuthZEN decision's {@code context}
 * that may be merged into the granted detail.
 *
 * <p>Until 0.6.0 every member of {@code context} but {@code id}, {@code reason_admin} and {@code reason_user} became a
 * statement merged into the detail (finding F-0065), so a PDP - or anything able to shape its answer - could write any
 * member into what PingFederate grants, held back only by the model's check that the grant stays within the request.
 * Now a member reaches the detail only when this list names it for the detail's type; any other is dropped, counted in
 * {@value #DROPPED} and logged by name, and never merged. A member on the list that would widen the detail is still
 * refused by the model's {@code within}, as before. The symmetric form, {@code context.statements: [{name, payload}]},
 * is held to the same list: a statement's member is the first dot-separated part of its name, the detail member it
 * writes into.
 *
 * <p>The field is {@code type: member, member} entries separated by {@code ;} or new lines; an entry splits at its last
 * colon, so a URI type ({@code urn:example:transfer: amount}) is named as it is. {@value #MODEL} stands for
 * every member the type's model declares (the two markers excluded), {@code -} for none; a type the field does not name
 * merges nothing. Blank is the default, {@value #DEFAULT}: {@code payment_initiation} merges nothing, and the other two
 * built-in types what their models declare. A single {@code -} for the whole field merges nothing for any type.
 */
final class ContextAllowList {

    /** The field's name, as PingFederate stores it. */
    static final String FIELD = "AuthZEN context members merged into details";

    /** Every member the type's model declares. */
    static final String MODEL = "@model";

    /** What a blank field means. */
    static final String DEFAULT = "sales_agent: " + MODEL + "; account_information: " + MODEL;

    static final String DROPPED = "oidf_rar_context_dropped_total";
    static final String FORM_MEMBER = "member";
    static final String FORM_STATEMENT = "statement";

    /**
     * A detail type: a built-in or extra type's name, or a URI type such as {@code urn:example:transfer} (RFC 9396 allows
     * either). An entry splits at its last colon, which a member name cannot hold, so a URI type keeps its own colons.
     */
    private static final Pattern TYPE = Pattern.compile("[A-Za-z_][^\\s,;]{0,254}");
    /** A member name: a top-level detail member, never a path. */
    private static final Pattern MEMBER = Pattern.compile("[A-Za-z_][A-Za-z0-9_-]{0,63}");
    /** The most distinct (type, member) pairs whose drop is logged; later ones are only counted. */
    static final int MAX_WARNED = 64;

    private static final Logger LOG = Logger.getLogger(ContextAllowList.class.getName());
    private static final Counter DROPS = Metrics.counter(DROPPED,
            "AuthZEN context members the RAR plugin dropped because its allow-list does not name them for the detail's type",
            Label.oneOf("form", FORM_MEMBER, FORM_STATEMENT));
    private static final Set<String> WARNED = Collections.synchronizedSet(new LinkedHashSet<>());

    /** Each named type's members, {@link #MODEL} still unexpanded. */
    private final Map<String, Set<String>> members;
    /** The model's declared members for a type, for {@link #MODEL}. */
    private final Function<String, Set<String>> model;

    private ContextAllowList(Map<String, Set<String>> members, Function<String, Set<String>> model) {
        this.members = members;
        this.model = model;
    }

    /**
     * The list a field holds.
     *
     * @param model each type's declared members, for {@link #MODEL}
     * @throws IllegalStateException naming the field and what is wrong with it
     */
    static ContextAllowList of(String field, Function<String, Set<String>> model) {
        Map<String, Set<String>> parsed = new LinkedHashMap<>();
        String problem = parse(field, parsed);
        if (problem != null) {
            throw new IllegalStateException(problem);
        }
        return new ContextAllowList(Collections.unmodifiableMap(parsed), model);
    }

    /** What is wrong with a field's value, or {@code null}. */
    static String problem(String field) {
        return parse(field, new LinkedHashMap<>());
    }

    /** Reads {@code field} into {@code into}; answers what is wrong with it, or {@code null}. */
    private static String parse(String field, Map<String, Set<String>> into) {
        String text = field == null || field.isBlank() ? DEFAULT : field.trim();
        if ("-".equals(text)) {
            return null;
        }
        for (String entry : text.split("[;\\n]")) {
            if (entry.isBlank()) {
                continue;
            }
            int colon = entry.lastIndexOf(':');
            if (colon < 0) {
                return FIELD + ": '" + entry.trim() + "' is not 'type: member, member'";
            }
            String type = entry.substring(0, colon).trim();
            if (!TYPE.matcher(type).matches()) {
                return FIELD + ": '" + type + "' is not a detail type";
            }
            if (into.containsKey(type)) {
                return FIELD + " names " + type + " twice";
            }
            Set<String> names = new LinkedHashSet<>();
            for (String name : entry.substring(colon + 1).split("[,\\s]+")) {
                String member = name.trim();
                if (member.isEmpty() || "-".equals(member)) {
                    continue;
                }
                if (!MODEL.equals(member) && !MEMBER.matcher(member).matches()) {
                    return FIELD + ": " + type + "'s '" + member + "' is not a member name (a top-level detail member,"
                            + " no dots)";
                }
                if ("type".equals(member) || ModelGate.PRINCIPAL_MARKER.equals(member) || ModelGate.AGENT_MARKER.equals(member)) {
                    return FIELD + ": " + type + " may not list '" + member + "', which no PDP may write";
                }
                names.add(member);
            }
            into.put(type, Collections.unmodifiableSet(names));
        }
        return null;
    }

    /** The members a PDP may merge into a detail of {@code type}, {@link #MODEL} expanded. */
    Set<String> allowed(String type) {
        Set<String> named = members.get(type);
        if (named == null || named.isEmpty()) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String member : named) {
            if (MODEL.equals(member)) {
                out.addAll(model.apply(type));
            } else {
                out.add(member);
            }
        }
        return out;
    }

    /**
     * The statements an AuthZEN answer may apply to a detail of {@code type}: those whose member the list names. Each one
     * dropped is counted under its form and logged by name (the first {@value #MAX_WARNED} distinct pairs), never its
     * payload.
     */
    List<DecisionResponse.Statement> filter(String type, List<DecisionResponse.Statement> statements, String form) {
        Set<String> allowed = allowed(type);
        List<DecisionResponse.Statement> kept = new ArrayList<>(statements.size());
        for (DecisionResponse.Statement statement : statements) {
            String member = memberOf(statement.getName());
            if (member == null) {
                continue; // no name: the applier would skip it anyway
            }
            if (allowed.contains(member)) {
                kept.add(statement);
                continue;
            }
            DROPS.inc(form);
            String name = printable(member);
            if (WARNED.size() < MAX_WARNED && WARNED.add(type + "\n" + name)) {
                LOG.warning("RAR AuthZEN: dropped the context " + form + " '" + name + "' for type '" + printable(type)
                        + "': \"" + FIELD + "\" does not name it for that type, so it is never merged into the detail."
                        + " List it there if the PDP's policy means to narrow the detail through it");
            }
        }
        return kept;
    }

    /** The detail member a statement writes into: the first dot-separated part of its name, or null for none. */
    static String memberOf(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        int dot = name.indexOf('.');
        return dot < 0 ? name : name.substring(0, dot);
    }

    /** A name for a log line: itself when it is a plain member name, otherwise a placeholder, never the PDP's text. */
    static String printable(String name) {
        return name != null && MEMBER.matcher(name).matches() ? name : "(not a member name)";
    }

    /** How many members of {@code form} have been dropped in this copy of the plugin. */
    static long dropped(String form) {
        return DROPS.get(form);
    }

    /** The admin-console half: the field's syntax, on save. */
    static final class Validator implements ConfigurationValidator {

        @Override
        public void validate(Configuration configuration) throws ValidationException {
            String problem = problem(configuration.getFieldValue(FIELD));
            if (problem != null) {
                throw new ValidationException(problem);
            }
        }
    }
}
