/*
 * The parts a component is made of - a servlet, a filter - and the one state the component's registry shows for them.
 */
package com.pingidentity.ps.oidf.platform.health;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Supervisor;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * One S-9 component can be served by more than one class: automatic registration by a filter at the token
 * endpoint and another at the authorization and PAR endpoints. {@link ComponentRegistry} holds one state per
 * component, and registering a name again retires the earlier handle, so the classes cannot each register the
 * component themselves. Each registers a <em>part</em> here instead, from its {@code init}, and this class
 * publishes the component's state to the registry: the worst state among its enabled parts, and
 * {@link ComponentState#DISABLED} when none is enabled.
 *
 * <p>A part starts {@link ComponentState#STARTING}. Its {@code init} hands its start function to
 * {@link Part#start(Start)}, which never throws (plan item S-9): it applies the component's enable switch
 * ({@link ComponentSwitches}) - a component switched off is {@link ComponentState#DISABLED} and its start function
 * never runs, one refused by its switch is {@link ComponentState#FAILED_CONFIG} - then runs the function, records
 * what it threw as {@link Part#failed(Throwable)} does, and makes a part still starting ready. Inside, the function
 * says what it found: {@link Part#notConfigured(String)} where the settings it needs are absent (disabled, or
 * {@code FAILED_CONFIG} when its switch is {@code true}), {@link Part#failedConfig(String)} or
 * {@link Part#degraded(String)} where it refuses or limits the part. A part that ends in
 * {@link ComponentState#FAILED_DEPENDENCY} is handed to the {@link Supervisor}, which runs the same start function
 * again with backoff until the part is ready or fails in a way a retry does not fix. A disabled part stays
 * disabled. Registering a part again - a servlet initialised a second time - starts it afresh and retires the
 * earlier handle, and the supervisor stops retrying the retired one.
 *
 * <p>Parts that do not start through {@link Part#start(Start)} (the SSF servlets until ST-5 moves them) report as
 * before: {@link Part#failed(Throwable)} on what their {@code init} throws, {@link Part#finish()} at the end. The
 * pull probe stays for them: a part that failed on a dependency another thread keeps retrying - the SSF
 * transmitter's boot retry - can pass a check that {@link #refresh()}, called by health before it reads the
 * states, runs; the part is ready once the check returns.
 */
public final class ComponentParts {

    /** How many causes {@link #stateFor} and {@link #reasonOf} follow before they stop. */
    static final int MAX_CAUSES = 16;

    private static final Pattern PART = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]{0,63}");

    /** The order a component's parts are compared in: the first is the worst. */
    private static final List<ComponentState> WORST_FIRST = List.of(ComponentState.FAILED_CONFIG, ComponentState.REFUSED,
            ComponentState.FAILED_DEPENDENCY, ComponentState.STARTING, ComponentState.DEGRADED, ComponentState.READY);

    private static final PlatformLog LOG = PlatformLog.get(ComponentParts.class);

    /** A part's start function: what its {@code init} did before S-9, run once at deploy and again by each retry. */
    @FunctionalInterface
    public interface Start {
        void start() throws Exception;
    }

    /** A check that returns when a dependency is back, and throws while it is not. */
    @FunctionalInterface
    public interface Probe {
        void check() throws Exception;
    }

    private final ComponentRegistry registry;
    private final Clock clock;
    private final Function<String, ComponentSwitches.Verdict> switches;
    private final Supervisor supervisor;
    private final Map<String, Map<String, Entry>> components = new LinkedHashMap<>();
    private final Map<String, Published> published = new LinkedHashMap<>();
    /** Each component's note: how its switch was read, shown beside a state that needs no reason. */
    private final Map<String, String> notes = new LinkedHashMap<>();
    private long generations;

    private static final class Entry {
        final long generation;
        ComponentState state = ComponentState.STARTING;
        String reason = "";
        Instant since;
        Probe probe;

        Entry(long generation, Instant since) {
            this.generation = generation;
            this.since = since;
        }
    }

    private record Published(ComponentRegistry.Component handle, boolean enabled) {
    }

    /** Parts with no switches (every component inferred) and no supervisor (nothing retried). */
    public ComponentParts(ComponentRegistry registry, Clock clock) {
        this(registry, clock, component -> new ComponentSwitches.Verdict(component, "", ComponentSwitches.Kind.INFERRED, ""), null);
    }

    /**
     * @param switches   each component's switch verdict, asked when a part starts
     * @param supervisor what retries a part that failed on a dependency, or null for nothing
     */
    public ComponentParts(ComponentRegistry registry, Clock clock, Function<String, ComponentSwitches.Verdict> switches,
            Supervisor supervisor) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.switches = Objects.requireNonNull(switches, "switches");
        this.supervisor = supervisor;
    }

    /**
     * {@code component}'s switch verdict, asked of the switches these parts were built with; {@code FAILED_CONFIG} when
     * they cannot be read (the catalogue is missing or broken: a packaging fault, refused rather than guessed at).
     */
    public ComponentSwitches.Verdict verdict(String component) {
        try {
            return this.switches.apply(component);
        } catch (RuntimeException e) {
            return new ComponentSwitches.Verdict(component, "", ComponentSwitches.Kind.FAILED_CONFIG,
                    "the enable switches could not be read: " + reasonOf(e));
        }
    }

    /** The component's state as this parts' registry holds it; empty when no part of it has registered. */
    public java.util.Optional<ComponentStatus> component(String component) {
        return this.registry.status(component);
    }

    /**
     * Registers {@code part} of {@code component}, starting.
     *
     * @param component S-9's name for the component, as {@link ComponentRegistry#register} takes it
     * @param part      the class that serves it, by its simple name: a letter, then up to 63 letters, digits,
     *                  {@code _}, {@code .} and {@code -}
     * @throws IllegalArgumentException for a bad name of either - constants in the caller's code
     */
    public Part begin(String component, String part) {
        if (part == null || !PART.matcher(part).matches()) {
            throw new IllegalArgumentException("a part is named by its class's simple name: 1-64 of A-Z, a-z, 0-9, '_', '.' and '-', starting with a letter");
        }
        long generation;
        synchronized (this) {
            generation = ++this.generations;
            Map<String, Entry> parts = this.components.computeIfAbsent(component, c -> new LinkedHashMap<>());
            parts.put(part, new Entry(generation, this.clock.instant()));
            try {
                this.publish(component);
            } catch (IllegalArgumentException e) {
                // The registry refused the component's name. That can only happen the first time a component is
                // seen - a name it has accepted once it accepts again - so the component is new and goes again whole.
                this.components.remove(component);
                throw e;
            }
        }
        return new Part(component, part, generation);
    }

    /** Every registered part, ordered by component and then part. */
    public synchronized List<PartStatus> parts() {
        List<PartStatus> out = new ArrayList<>();
        for (Map.Entry<String, Map<String, Entry>> c : this.components.entrySet()) {
            for (Map.Entry<String, Entry> p : c.getValue().entrySet()) {
                Entry e = p.getValue();
                out.add(new PartStatus(c.getKey(), p.getKey(), e.state, e.reason, e.since));
            }
        }
        out.sort(Comparator.comparing(PartStatus::component).thenComparing(PartStatus::part));
        return List.copyOf(out);
    }

    /**
     * Runs the probe of every part that failed on a dependency and has one, and makes each whose probe returns
     * ready. A probe that throws - anything, an {@code Error} included - leaves its part as it was.
     */
    public void refresh() {
        Map<Entry, String[]> due = new IdentityHashMap<>();
        synchronized (this) {
            for (Map.Entry<String, Map<String, Entry>> c : this.components.entrySet()) {
                for (Map.Entry<String, Entry> p : c.getValue().entrySet()) {
                    if (p.getValue().probe != null) {
                        due.put(p.getValue(), new String[] {c.getKey(), p.getKey()});
                    }
                }
            }
        }
        for (Map.Entry<Entry, String[]> d : due.entrySet()) {
            if (passes(d.getKey().probe)) {
                this.move(d.getValue()[0], d.getValue()[1], d.getKey().generation, ComponentState.READY, null, null);
            }
        }
    }

    static boolean passes(Probe probe) {
        try {
            probe.check();
            return true;
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    /**
     * Moves a part. Nothing happens, and the answer is {@code false}, when the handle is from an earlier
     * registration or the part is disabled.
     */
    boolean move(String component, String part, long generation, ComponentState to, String reason, Probe probe) {
        synchronized (this) {
            // Never null: a handle exists only for a registered part, and nothing removes one.
            Entry e = this.components.get(component).get(part);
            if (e.generation != generation || e.state == ComponentState.DISABLED) {
                return false;
            }
            String why = to.needsReason() ? clean(reason) : "";
            if (e.state != to || !e.reason.equals(why)) {
                e.since = this.clock.instant();
            }
            e.state = to;
            e.reason = why;
            e.probe = to == ComponentState.FAILED_DEPENDENCY ? probe : null;
            this.publish(component);
            return true;
        }
    }

    /** Tells the registry the component's state: the worst of its enabled parts. Called holding this lock. */
    private void publish(String component) {
        Map<String, Entry> parts = this.components.get(component);
        ComponentState worst = worst(parts);
        boolean enabled = worst != ComponentState.DISABLED;
        Published was = this.published.get(component);
        String note = this.notes.getOrDefault(component, "");
        ComponentRegistry.Component handle = was == null || was.enabled() != enabled
                ? this.registry.register(component, enabled, note) : was.handle();
        this.published.put(component, new Published(handle, enabled));
        if (!enabled) {
            return;
        }
        String reason = reasons(parts, worst);
        switch (worst) {
            case READY -> handle.ready(note);
            case DEGRADED -> handle.degraded(reason);
            case FAILED_CONFIG -> handle.failedConfig(reason);
            case FAILED_DEPENDENCY -> handle.failedDependency(reason);
            case REFUSED -> handle.refused(reason);
            default -> handle.starting(note);
        }
    }

    /** The worst state among the enabled parts, by {@link #WORST_FIRST}; {@code DISABLED} when none is enabled. */
    static ComponentState worst(Map<String, Entry> parts) {
        ComponentState worst = ComponentState.DISABLED;
        for (Entry e : parts.values()) {
            if (e.state != ComponentState.DISABLED
                    && (worst == ComponentState.DISABLED || WORST_FIRST.indexOf(e.state) < WORST_FIRST.indexOf(worst))) {
                worst = e.state;
            }
        }
        return worst;
    }

    /** Each part in {@code state}, as {@code part: reason}, joined with {@code ; }. */
    static String reasons(Map<String, Entry> parts, ComponentState state) {
        StringJoiner out = new StringJoiner("; ");
        for (Map.Entry<String, Entry> p : parts.entrySet()) {
            if (p.getValue().state == state && !p.getValue().reason.isEmpty()) {
                out.add(p.getKey() + ": " + p.getValue().reason);
            }
        }
        return out.toString();
    }

    /**
     * What an exception out of {@code init} says about the part: {@link ComponentState#REFUSED} when it, or one of its
     * causes, is the production profile's {@link ProfileRefused} (PR-5); {@link ComponentState#FAILED_DEPENDENCY} when it,
     * or one of its causes, is an I/O, SQL or timeout failure, or a class that would not link (a jar missing where
     * it runs); {@link ComponentState#FAILED_CONFIG} for anything else - a setting refused, a key that does not
     * parse, a required value missing.
     */
    static ComponentState stateFor(Throwable thrown) {
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable t = thrown;
        while (t != null && seen.size() < MAX_CAUSES && seen.add(t)) {
            if (t instanceof ProfileRefused) {
                return ComponentState.REFUSED;
            }
            if (t instanceof IOException || t instanceof UncheckedIOException || t instanceof SQLException
                    || t instanceof TimeoutException || t instanceof LinkageError) {
                return ComponentState.FAILED_DEPENDENCY;
            }
            t = t.getCause();
        }
        return ComponentState.FAILED_CONFIG;
    }

    /**
     * An exception as an operator's reason: its message - or its class's name when it has none - and, when its
     * deepest cause says something the message does not, that cause as {@code (Class: message)}. The registry
     * cleans and cuts it.
     */
    static String reasonOf(Throwable thrown) {
        String text = describe(thrown);
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable root = thrown;
        seen.add(root);
        while (root.getCause() != null && seen.size() < MAX_CAUSES && seen.add(root.getCause())) {
            root = root.getCause();
        }
        String message = root.getMessage();
        if (root != thrown && (message == null || !text.contains(message))) {
            text = text + " (" + root.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message) + ")";
        }
        return text;
    }

    private static String describe(Throwable t) {
        String message = t.getMessage();
        return message == null || message.isBlank() ? t.getClass().getSimpleName() : message;
    }

    /**
     * A reason as one short line, by the registry's rule (ComponentRegistry's {@code clean}, which is not visible
     * here): control, format and separator characters become {@code ?}, and it is cut at
     * {@link ComponentRegistry#MAX_REASON} characters without splitting a surrogate pair.
     */
    static String clean(String reason) {
        if (reason == null || reason.isBlank()) {
            return "no reason given";
        }
        String text = reason.strip();
        int end = Math.min(text.length(), ComponentRegistry.MAX_REASON);
        if (end < text.length() && Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        StringBuilder out = new StringBuilder(end);
        for (int i = 0; i < end; i++) {
            char c = text.charAt(i);
            int type = Character.getType(c);
            boolean hidden = type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR;
            out.append(hidden ? '?' : c);
        }
        return out.toString();
    }

    /** What a part's {@code init} holds to report its state. */
    public final class Part {
        private final String component;
        private final String part;
        private final long generation;

        private Part(String component, String part, long generation) {
            this.component = component;
            this.part = part;
            this.generation = generation;
        }

        public String component() {
            return this.component;
        }

        public String part() {
            return this.part;
        }

        /** Its state now. */
        public PartStatus status() {
            synchronized (ComponentParts.this) {
                Entry e = ComponentParts.this.components.get(this.component).get(this.part);
                return new PartStatus(this.component, this.part, e.state, e.reason, e.since);
            }
        }

        /**
         * Starts the part: applies its component's switch, runs {@code start}, records the outcome, and hands a part
         * that failed on a dependency to the supervisor, which runs {@code start} again with backoff. Never throws:
         * what {@code start} throws is recorded ({@link ComponentParts#stateFor}, with its message as the reason)
         * and logged with its stack, and nothing reaches the container.
         *
         * @return the part's state once this first attempt is recorded
         */
        public ComponentState start(Start start) {
            Objects.requireNonNull(start, "start");
            ComponentSwitches.Verdict verdict = this.verdict();
            synchronized (ComponentParts.this) {
                ComponentParts.this.notes.put(this.component, verdict.note());
            }
            if (verdict.kind() == ComponentSwitches.Kind.DISABLED) {
                this.disabled();
                return this.status().state();
            }
            if (verdict.kind() == ComponentSwitches.Kind.FAILED_CONFIG) {
                LOG.warn("Component " + this.component + ": " + this.part + " not started - " + verdict.note());
                this.failedConfig(verdict.note());
                return this.status().state();
            }
            if (this.status().state() == ComponentState.REFUSED) {
                // The production profile refused the component when the part registered (Startup.begin): its start
                // function configures nothing, and the part stays refused until the deployment changes and it starts again.
                LOG.warn("Component " + this.component + ": " + this.part + " not started - " + this.status().reason());
                return ComponentState.REFUSED;
            }
            this.attempt(start);
            ComponentState now = this.status().state();
            if (now == ComponentState.FAILED_DEPENDENCY && ComponentParts.this.supervisor != null && !this.hasProbe()) {
                boolean scheduled = ComponentParts.this.supervisor.retry(this.component, () -> this.retry(start));
                if (!scheduled) {
                    LOG.warn("Component " + this.component + ": " + this.part + " failed on a dependency and nothing will retry it in"
                            + " this copy; it stays FAILED_DEPENDENCY until it starts again");
                }
            }
            return now;
        }

        /** One retry: starting again, the start function, the outcome. Answers whether the supervisor should stop. */
        boolean retry(Start start) {
            if (!move(this.component, this.part, this.generation, ComponentState.STARTING, null, null)) {
                return true;
            }
            this.attempt(start);
            PartStatus now = this.status();
            return now.state() != ComponentState.FAILED_DEPENDENCY || !this.current();
        }

        private void attempt(Start start) {
            try {
                start.start();
            } catch (Throwable thrown) {
                if (thrown instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                ComponentState state = stateFor(thrown);
                LOG.warn("Component " + this.component + ": " + this.part + " did not start (" + state + ")", thrown);
                this.failed(thrown);
                return;
            }
            this.finish();
        }

        private boolean hasProbe() {
            synchronized (ComponentParts.this) {
                return ComponentParts.this.components.get(this.component).get(this.part).probe != null;
            }
        }

        /** Whether this handle is the part's current registration. */
        private boolean current() {
            synchronized (ComponentParts.this) {
                return ComponentParts.this.components.get(this.component).get(this.part).generation == this.generation;
            }
        }

        /** The component's switch verdict, asked of the switches this parts was built with. */
        public ComponentSwitches.Verdict verdict() {
            return ComponentParts.this.verdict(this.component);
        }

        /**
         * The settings the part needs are absent: {@code FAILED_CONFIG} when its switch is {@code true} (the reason says
         * the switch and what is missing), disabled otherwise - the inferred answer, as before the switches existed.
         */
        public boolean notConfigured(String missing) {
            ComponentSwitches.Verdict verdict = this.verdict();
            if (verdict.kind() == ComponentSwitches.Kind.ENABLED) {
                return this.failedConfig(verdict.name() + "=true but " + missing);
            }
            return this.disabled();
        }

        /** The component's state now, as the registry holds it: the worst of its enabled parts. */
        public ComponentState componentState() {
            return ComponentParts.this.registry.status(this.component).map(ComponentStatus::state).orElse(ComponentState.STARTING);
        }

        /**
         * Whether any part of this part's component is {@code REFUSED}: a violation of the deployment profile refuses the
         * whole component (the programme's decision 4), so a surface's gate asks this beside its own part's state.
         */
        public boolean componentRefused() {
            synchronized (ComponentParts.this) {
                return ComponentParts.this.components.get(this.component).values().stream()
                        .anyMatch(e -> e.state == ComponentState.REFUSED);
            }
        }

        /** Today's configuration switches this part off; it stays off. */
        public boolean disabled() {
            return move(this.component, this.part, this.generation, ComponentState.DISABLED, null, null);
        }

        public boolean ready() {
            return move(this.component, this.part, this.generation, ComponentState.READY, null, null);
        }

        public boolean degraded(String reason) {
            return move(this.component, this.part, this.generation, ComponentState.DEGRADED, reason, null);
        }

        public boolean failedConfig(String reason) {
            return move(this.component, this.part, this.generation, ComponentState.FAILED_CONFIG, reason, null);
        }

        public boolean failedDependency(String reason) {
            return this.failedDependency(reason, null);
        }

        /** The deployment profile forbids how the part is configured (S-9's profile checks, Phase 3). */
        public boolean refused(String reason) {
            return move(this.component, this.part, this.generation, ComponentState.REFUSED, reason, null);
        }

        /** Failed on a dependency something else retries; ready once {@code probe} returns (see {@link #refresh()}). */
        public boolean failedDependency(String reason, Probe probe) {
            return move(this.component, this.part, this.generation, ComponentState.FAILED_DEPENDENCY, reason, probe);
        }

        /**
         * Records what {@code thrown} says about this part ({@link ComponentParts#stateFor}, with
         * {@link ComponentParts#reasonOf} as the reason); {@code init} then rethrows it unchanged. A disabled part
         * stays disabled.
         */
        public boolean failed(Throwable thrown) {
            return move(this.component, this.part, this.generation, stateFor(thrown), reasonOf(thrown), null);
        }

        /** The end of {@code init}: a part still starting is ready; one that said otherwise keeps what it said. */
        public boolean finish() {
            synchronized (ComponentParts.this) {
                Entry e = ComponentParts.this.components.get(this.component).get(this.part);
                if (e.generation != this.generation || e.state != ComponentState.STARTING) {
                    return false;
                }
            }
            return this.ready();
        }
    }
}
