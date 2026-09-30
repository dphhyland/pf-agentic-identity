/*
 * The first statement of every OGNL entry point: whether the criterion's component serves in this classloader.
 */
package com.pingidentity.ps.oidf.platform.pf.component;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * S-9's rule for the OGNL criteria (S9b): a criterion answers {@code false} - never a throw - while its component is
 * not serving. PingFederate denies the token then, as it does for any criterion that answers {@code false} or throws:
 * 400 {@code invalid_grant} with the criterion's Error Result (seen on the rig with 13.1.3.0 on 2026-09-30).
 *
 * <p>A criterion runs on PingFederate's engine classloader, whose copy of platform is not the webapp's: statics are
 * per loader (docs/development/classloaders.md), so the engine's component registry is empty - nothing there runs a
 * servlet's or filter's {@code init} - and it cannot see the webapp's parts. So the answer comes from what the engine's
 * copy can read for itself, lazily, on the first call for each component, and is kept:
 *
 * <ol>
 *   <li>When this loader's registry does have the component - a war in which the criterion's classes and the
 *       component's filters share a loader - it answers: serving while {@code READY} or {@code DEGRADED}.</li>
 *   <li>Otherwise the enable switch ({@link ComponentSwitches}): switched off, or a switch that is not {@code true} or
 *       {@code false} (or unset in production beside the component's settings), is not serving.</li>
 *   <li>Then the deployment profile ({@link ProfileRefusals#refused}, which the engine's copy evaluates for itself, from
 *       the same process-wide environment and system properties the webapp's sweep read): a refused component is not
 *       serving.</li>
 *   <li>Otherwise it serves, and the criterion's own lazily built state decides the rest - the trust anchors, the
 *       containment models, the attesters - each of which already refuses the token when it cannot be built.</li>
 * </ol>
 *
 * <p>The engine's copy cannot learn {@code FAILED_DEPENDENCY}: nothing tells it that the webapp's copy of a part failed
 * on a dependency, and it has no supervisor (only the webapp's copy retries). It answers from its own state instead, and
 * a dependency the criterion itself needs and cannot reach fails that criterion's own call, which answers {@code false}.
 */
public final class CriterionGate {

    private static final PlatformLog LOG = PlatformLog.get(CriterionGate.class);

    /** The engine-side answer per component, made once: the switches and the profile do not change while the JVM runs. */
    private static final Map<String, Answer> ANSWERS = new ConcurrentHashMap<>();
    /** The components whose "not serving" has been logged at WARN, so a denied token logs it once per component. */
    private static final Map<String, Boolean> WARNED = new ConcurrentHashMap<>();

    private static volatile Supplier<ComponentSwitches> switches = ComponentSwitches::process;
    private static volatile Function<String, Optional<ComponentStatus>> registry = Components::status;

    /** Whether a component serves here, and why not when it does not. */
    record Answer(boolean serving, String why) {
    }

    private CriterionGate() {
    }

    /**
     * An OGNL entry point's first statement: whether {@code component} serves, so the criterion may run.
     *
     * @param component S-9's name for the criterion's component ({@code ATTESTATION_AUTH}, {@code FEDERATION})
     * @param criterion what the log calls the criterion
     * @return {@code true} to run the criterion; {@code false} to answer {@code false} (or the entry point's empty value)
     */
    public static boolean serves(String component, String criterion) {
        Answer answer;
        try {
            answer = answer(component);
        } catch (RuntimeException | LinkageError e) {
            // Nothing escapes a criterion's first statement: what cannot be decided is not serving.
            answer = new Answer(false, "its state could not be read (" + e.getClass().getSimpleName() + ")");
        }
        if (!answer.serving()) {
            String line = "OGNL criterion " + criterion + " answers false: " + component + " " + answer.why();
            if (WARNED.putIfAbsent(component, Boolean.TRUE) == null) {
                LOG.warn(line + " (logged once per component; later refusals at DEBUG)");
            } else {
                LOG.debug(line);
            }
        }
        return answer.serving();
    }

    static Answer answer(String component) {
        Optional<ComponentStatus> own = registry.apply(component);
        if (own.isPresent()) {
            ComponentState state = own.get().state();
            boolean serving = state == ComponentState.READY || state == ComponentState.DEGRADED;
            return new Answer(serving, "is " + state + (own.get().reason().isEmpty() ? "" : ": " + own.get().reason()));
        }
        return ANSWERS.computeIfAbsent(component, CriterionGate::engine);
    }

    /** The engine copy's answer: the switch, then the profile. */
    static Answer engine(String component) {
        ComponentSwitches.Verdict verdict = switches.get().verdict(component);
        switch (verdict.kind()) {
            case DISABLED:
                return new Answer(false, "is DISABLED (" + verdict.note() + ")");
            case FAILED_CONFIG:
                return new Answer(false, "is FAILED_CONFIG (" + verdict.note() + ")");
            default:
                break;
        }
        if (ProfileRefusals.refused(component, verdict.kind() == ComponentSwitches.Kind.ENABLED)) {
            return new Answer(false, "is REFUSED by the production profile (the start-up audit in server.log lists why)");
        }
        return new Answer(true, "");
    }

    /** Test seam: the switches and the registry to ask, and the kept answers forgotten; null puts the process's back. */
    static void useForTests(Supplier<ComponentSwitches> newSwitches, Function<String, Optional<ComponentStatus>> newRegistry) {
        switches = newSwitches == null ? ComponentSwitches::process : newSwitches;
        registry = newRegistry == null ? Components::status : newRegistry;
        ANSWERS.clear();
        WARNED.clear();
    }
}
