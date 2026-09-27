/*
 * The risks a deployment accepts, read from OIDF_ACCEPTED_RISKS.
 */
package com.pingidentity.ps.oidf.platform.profile;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * What {@value #SETTING} accepts: a comma-separated list of {@link AcceptedRisk} ids, each alone ({@code pkce-off})
 * or with the last day it holds ({@code expiry-log-mode@2026-12-31}). The date is a calendar date in UTC and the
 * acceptance holds through the end of it. Whitespace around an entry is ignored.
 *
 * <p>An entry is refused, and its risk not accepted, when it is empty, names an id not in the registry, carries
 * something other than a {@code YYYY-MM-DD} date that exists, has expired, leaves out the date a
 * {@linkplain AcceptedRisk#dated() dated} risk needs, or names a risk a second time (both entries go: which of two
 * expiries was meant is a guess). Each refusal is a message naming the entry. Parsing never throws: nothing stops
 * a deployment over this list until PR-5 (Phase 3) - PLAN.md decision 7 - and until then the start-up audit (F-2)
 * reports {@link #refusals()}.
 */
public final class AcceptedRisks {
    /** The environment variable that lists the accepted risks. */
    public static final String SETTING = "OIDF_ACCEPTED_RISKS";

    private static final Pattern DATE = Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}");
    private static final AcceptedRisks NONE = new AcceptedRisks(new EnumMap<>(AcceptedRisk.class), List.of());

    private final Map<AcceptedRisk, Optional<LocalDate>> accepted;
    private final List<String> refusals;

    private AcceptedRisks(Map<AcceptedRisk, Optional<LocalDate>> accepted, List<String> refusals) {
        this.accepted = Collections.unmodifiableMap(accepted);
        this.refusals = List.copyOf(refusals);
    }

    /** Nothing accepted. */
    public static AcceptedRisks none() {
        return NONE;
    }

    /** This process's list, from its environment, judged against today's date in UTC. */
    public static AcceptedRisks current() {
        return of(System::getenv, LocalDate.now(ZoneOffset.UTC));
    }

    /** The list an environment names, judged against {@code today}. */
    public static AcceptedRisks of(Function<String, String> env, LocalDate today) {
        return parse(env.apply(SETTING), today);
    }

    /** A value of {@value #SETTING}, judged against {@code today}; null or blank accepts nothing. */
    public static AcceptedRisks parse(String value, LocalDate today) {
        if (value == null || value.isBlank()) {
            return NONE;
        }
        Map<AcceptedRisk, Optional<LocalDate>> accepted = new EnumMap<>(AcceptedRisk.class);
        Set<AcceptedRisk> seen = EnumSet.noneOf(AcceptedRisk.class);
        Set<AcceptedRisk> twice = EnumSet.noneOf(AcceptedRisk.class);
        List<String> refusals = new ArrayList<>();
        for (String raw : value.split(",", -1)) {
            String entry = raw.trim();
            if (entry.isEmpty()) {
                refusals.add(SETTING + " has an empty entry; separate ids with single commas");
                continue;
            }
            int at = entry.indexOf('@');
            String id = at < 0 ? entry : entry.substring(0, at);
            AcceptedRisk risk = AcceptedRisk.byId(id);
            if (risk == null) {
                refusals.add(SETTING + " names '" + id + "', which is not a risk this release knows; the ids are " + ids());
                continue;
            }
            if (!seen.add(risk)) {
                if (twice.add(risk)) {
                    accepted.remove(risk);
                    refusals.add(SETTING + " names '" + id + "' more than once; name it once");
                }
                continue;
            }
            Optional<LocalDate> expiry;
            if (at < 0) {
                if (risk.dated()) {
                    refusals.add(SETTING + " accepts '" + id + "' without an expiry; this risk is accepted only with one, as "
                            + id + "@YYYY-MM-DD");
                    continue;
                }
                expiry = Optional.empty();
            } else {
                LocalDate date = date(entry.substring(at + 1));
                if (date == null) {
                    refusals.add(SETTING + " entry '" + entry + "' does not end in a date that exists, written YYYY-MM-DD");
                    continue;
                }
                if (date.isBefore(today)) {
                    refusals.add(SETTING + " accepted '" + id + "' until " + date + ", and that has passed");
                    continue;
                }
                expiry = Optional.of(date);
            }
            accepted.put(risk, expiry);
        }
        return new AcceptedRisks(accepted, refusals);
    }

    /** A {@code YYYY-MM-DD} date that exists, or null. */
    static LocalDate date(String text) {
        if (!DATE.matcher(text).matches()) {
            return null;
        }
        try {
            return LocalDate.parse(text);
        } catch (DateTimeException e) {
            return null;
        }
    }

    /** Every registered id, comma-separated, in registry order. */
    static String ids() {
        StringBuilder out = new StringBuilder();
        for (AcceptedRisk risk : AcceptedRisk.values()) {
            out.append(out.length() == 0 ? "" : ", ").append(risk.id());
        }
        return out.toString();
    }

    /** Whether {@code risk} is accepted: listed once, known, and not expired. */
    public boolean accepts(AcceptedRisk risk) {
        return this.accepted.containsKey(risk);
    }

    /** The accepted risks with the last day each holds, empty for an acceptance with no expiry. */
    public Map<AcceptedRisk, Optional<LocalDate>> accepted() {
        return this.accepted;
    }

    /** One message per refused entry, naming it, in the order the list gives them. */
    public List<String> refusals() {
        return this.refusals;
    }
}
