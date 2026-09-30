/*
 * What the production profile refuses in this loader: the start-up sweep's violations and the refusals made in code.
 */
package com.pingidentity.ps.oidf.platform.profile;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.settings.Catalogues;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;

/**
 * The components the production profile refuses (plan item PR-5), for this loaded copy of platform. Two things feed
 * it:
 *
 * <ul>
 *   <li>The start-up sweep ({@link ProfileAudit#evaluate}): platform-pf's lifecycle listener evaluates it once, in
 *       {@code contextInitialized}, before any filter's or servlet's {@code init}, and {@link #publish}es it here. A copy
 *       nothing publishes to - the engine's, where the OGNL criteria run - evaluates it itself on first use, from the
 *       same process-wide sources (the environment and the system properties) and the catalogues its own loader sees,
 *       so both copies give one answer.</li>
 *   <li>Refusals in code, for a condition that is not a setting ({@link #refuse}): an in-memory store under production
 *       without the {@code in-memory-state} risk (Phase 3 plan, decisions 9 and 15), a database that is not PostgreSQL.
 *       The package that owns the store calls it from its part's start function.</li>
 * </ul>
 *
 * <p>{@code platform.health.Startup.begin} asks {@link #reason} for each part it registers, and a part of a refused
 * component is {@code REFUSED} before its start function runs, so its {@code init} configures nothing. {@link #reason}
 * reads the published sweep only: the webapp's copy always has one before its first {@code init}, and a copy nothing
 * published to - a unit test's, or a war that does not register the listener, which no war this repository ships is -
 * refuses nothing for a setting, whatever its process happens to hold at that moment. {@link #refused} and
 * {@link #current} are the engine copy's way in, and evaluate. Under the development profile nothing is refused: the
 * sweep's violations are warnings, and {@link #refuse} logs a WARN and returns.
 *
 * <p>A {@code required-in-production} setting left unset refuses its component only when the component's switch
 * says {@code true}. Unswitched, a component in production is inferred only while none of its settings is set, so its
 * start finds it unconfigured and disables it; refusing it for a setting it will never read would take readiness
 * down for a feature nobody runs. Every other violation refuses an enabled or an inferred component alike.
 */
public final class ProfileRefusals {

    private static final PlatformLog LOG = PlatformLog.get(ProfileRefusals.class);
    private static final Object LOCK = new Object();

    private static ProfileAudit.Result published;
    private static ProfileAudit.Result result;
    private static Supplier<ProfileAudit.Result> evaluation = ProfileRefusals::evaluateProcess;
    private static final List<ProfileAudit.Violation> CODE = new ArrayList<>();
    private static final Set<String> WARNED = new LinkedHashSet<>();

    private ProfileRefusals() {
    }

    /** The sweep of this process as this copy sees it: {@link Sources#process()} and its own loader's catalogues. */
    static ProfileAudit.Result evaluateProcess() {
        ClassLoader loader = ProfileRefusals.class.getClassLoader();
        return ProfileAudit.evaluate(Sources.process(), Catalogues.onClassPath(loader == null ? ClassLoader.getSystemClassLoader()
                : loader), DeploymentProfile.current(), AcceptedRisks.current());
    }

    /** Publishes the sweep's result, as the lifecycle listener does before any {@code init}; a later publish replaces it. */
    public static void publish(ProfileAudit.Result sweep) {
        synchronized (LOCK) {
            published = Objects.requireNonNull(sweep, "sweep");
            result = sweep;
        }
    }

    /** The sweep's result: the published one, or this copy's own evaluation, made once on first use. */
    public static ProfileAudit.Result current() {
        synchronized (LOCK) {
            if (result == null) {
                result = evaluation.get();
            }
            return result;
        }
    }

    /**
     * Why {@code component} is refused, as one line for its state's reason, or null when nothing refuses it: nothing
     * under development, and under production the sweep's violations that name it - {@code required-in-production}
     * ones only when {@code switchedOn} - and the refusals made in code for it.
     */
    public static String reason(String component, boolean switchedOn) {
        ProfileAudit.Result sweep;
        synchronized (LOCK) {
            sweep = published;
        }
        List<ProfileAudit.Violation> refusing = refusing(component, switchedOn, sweep);
        if (refusing.isEmpty()) {
            return null;
        }
        String first = "refused by the production profile: " + refusing.get(0).message();
        return refusing.size() == 1 ? first : first + " (and " + (refusing.size() - 1) + " more, listed in server.log and the"
                + " start-up audit)";
    }

    /** Whether {@code component} is refused, for a caller that has no part to ask - an OGNL criterion. */
    public static boolean refused(String component, boolean switchedOn) {
        return !refusing(component, switchedOn, current()).isEmpty();
    }

    /**
     * Whether {@code v} refuses anything under production, given which components are switched on: every violation
     * does, but a {@code required-in-production} setting left unset refuses only a component switched on.
     */
    public static boolean refuses(ProfileAudit.Violation v, Predicate<String> switchedOn) {
        return v.kind() != ProfileAudit.Kind.REQUIRED || v.components().stream().anyMatch(switchedOn);
    }

    /**
     * The components {@code v} refuses under production, given each one's switch - the rule
     * {@code platform.health.Startup.begin} applies to each part it registers: none switched off (switching a component
     * off is never a violation), and for a {@code required-in-production} setting only those switched on. The start-up
     * log, the banner and {@code Preflight} all judge a violation by it, so they say what the server does.
     */
    public static List<String> refusedBy(ProfileAudit.Violation v, Predicate<String> switchedOn, Predicate<String> switchedOff) {
        List<String> out = new ArrayList<>();
        for (String component : v.components()) {
            if (!switchedOff.test(component) && (v.kind() != ProfileAudit.Kind.REQUIRED || switchedOn.test(component))) {
                out.add(component);
            }
        }
        return out;
    }

    /**
     * How the start-up log, the banner and {@code Preflight} label a violation: {@code REFUSED: } when it refuses a
     * component ({@link #refusedBy}); otherwise {@code not refused (development): } under development,
     * {@code not refused (not switched on): } for a required setting, {@code not refused (names no component): } for one
     * that names none, and {@code not refused (switched off): } for one whose components are all switched off.
     */
    public static String label(ProfileAudit.Violation v, DeploymentProfile profile, boolean refusing) {
        if (refusing) {
            return "REFUSED: ";
        }
        if (profile.isDevelopment()) {
            return "not refused (development): ";
        }
        if (v.kind() == ProfileAudit.Kind.REQUIRED) {
            return "not refused (not switched on): ";
        }
        return v.components().isEmpty() ? "not refused (names no component): " : "not refused (switched off): ";
    }

    /**
     * The violations of {@code sweep} that refuse {@code component}, and the refusals made in code for it; nothing
     * from the sweep when there is none, and nothing at all under development.
     */
    static List<ProfileAudit.Violation> refusing(String component, boolean switchedOn, ProfileAudit.Result sweep) {
        List<ProfileAudit.Violation> out = new ArrayList<>();
        if (sweep != null && sweep.profile().isDevelopment()) {
            return out;
        }
        for (ProfileAudit.Violation v : sweep == null ? List.<ProfileAudit.Violation>of() : sweep.of(component)) {
            if (refuses(v, c -> switchedOn)) {
                out.add(v);
            }
        }
        synchronized (LOCK) {
            for (ProfileAudit.Violation v : CODE) {
                if (v.components().contains(component)) {
                    out.add(v);
                }
            }
        }
        return out;
    }

    /**
     * Refuses {@code component} for a condition that is not a setting (Phase 3 plan, decision 15). Under the
     * production profile it records the refusal - the start-up audit lists it beside the sweep's, and every part of
     * the component that registers after it is {@code REFUSED} - logs it at ERROR once, and throws it, so a start
     * function that calls it leaves its part {@code REFUSED}. Under development it logs a WARN once and returns.
     *
     * @param component the component, by S-9's name
     * @param reason    what is refused and how to fix it: the risk id to accept, or the setting that fixes it
     * @throws ProfileRefused under the production profile
     */
    public static void refuse(String component, String reason) {
        Objects.requireNonNull(component, "component");
        Objects.requireNonNull(reason, "reason");
        ProfileAudit.Violation violation = new ProfileAudit.Violation(ProfileAudit.Kind.CODE, component, reason,
                "The start-up audit lists it", List.of(component));
        boolean production = profile().isProduction();
        boolean first;
        synchronized (LOCK) {
            first = WARNED.add(component + " " + reason);
            if (production && first) {
                CODE.add(violation);
            }
        }
        if (first && production) {
            LOG.error("Production profile: " + component + " refused - " + reason, null);
        } else if (first) {
            LOG.warn("Development profile: " + component + " would be refused under production - " + reason);
        }
        if (production) {
            throw new ProfileRefused(violation);
        }
    }

    /**
     * {@link #refuse}s {@code component} under production unless {@code risk} is accepted: for a store that keeps its
     * state in memory, {@code requireRisk(SSF, AcceptedRisk.IN_MEMORY_STATE, "the SSF stream store is in memory because
     * OIDF_SSF_DATA_STORE_ID is unset")}.
     *
     * @throws ProfileRefused under production, the risk not accepted
     */
    public static void requireRisk(String component, AcceptedRisk risk, String what) {
        requireRisk(component, risk, what, AcceptedRisks.current());
    }

    /** {@link #requireRisk(String, AcceptedRisk, String)} against {@code risks} rather than this process's. */
    static void requireRisk(String component, AcceptedRisk risk, String what, AcceptedRisks risks) {
        Objects.requireNonNull(risk, "risk");
        if (risks.accepts(risk)) {
            return;
        }
        refuse(component, what + ", which the production profile allows only with the risk '" + risk.id() + "' accepted ("
                + risk.description() + "): add " + risk.id() + (risk.dated() ? "@YYYY-MM-DD" : "") + " to "
                + AcceptedRisks.SETTING);
    }

    /** The profile a refusal in code is judged under: the published sweep's, or this process's environment's. */
    static DeploymentProfile profile() {
        synchronized (LOCK) {
            return published != null ? published.profile() : DeploymentProfile.current();
        }
    }

    /** The refusals made in code so far, in the order they were made. */
    public static List<ProfileAudit.Violation> codeRefusals() {
        synchronized (LOCK) {
            return List.copyOf(CODE);
        }
    }

    /** Tests only: forget what was published and refused, and evaluate with {@code with} on the next use. */
    static void reset(Supplier<ProfileAudit.Result> with) {
        synchronized (LOCK) {
            published = null;
            result = null;
            evaluation = Objects.requireNonNull(with, "with");
            CODE.clear();
            WARNED.clear();
        }
    }

    /** Tests only: as {@link #reset(Supplier)}, back to evaluating this process. */
    public static void resetForTests() {
        reset(ProfileRefusals::evaluateProcess);
    }
}
