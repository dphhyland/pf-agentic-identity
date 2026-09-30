/*
 * The components one loaded copy of platform knows about, and the state each is in.
 */
package com.pingidentity.ps.oidf.platform.component;

import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Components and their {@link ComponentState}s. A component registers once at initialisation, enabled or not,
 * and reports its state through the {@link Component} handle it gets back; health (plan item O-4) reads
 * {@link #snapshot()}. Retrying is not done here: {@link Supervisor} starts a part again, and the part's
 * {@code ComponentParts} reports the outcome through this registry.
 *
 * <p>A disabled component stays {@link ComponentState#DISABLED}: its handle's transitions do nothing. Registering
 * a name again - a servlet initialised a second time - starts it afresh, and the handle from the earlier
 * registration stops having any effect, so a destroyed instance's late report cannot overwrite the new one's.
 *
 * <p>A reason is operator text and is kept to one short line: control, format and separator characters become
 * {@code ?} and it is cut at {@value #MAX_REASON} characters. A state that needs a reason and is given none says
 * "no reason given". A state that needs none may still carry a note - how its enable switch was read - which
 * the start-up banner and the health detail show beside it.
 */
public final class ComponentRegistry {

    /** The longest reason kept, in characters. */
    public static final int MAX_REASON = 256;

    private static final PlatformLog LOG = PlatformLog.get(ComponentRegistry.class);
    private static final Pattern NAME = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    private final Clock clock;
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private long generations;

    private static final class Entry {
        final long generation;
        final boolean enabled;
        ComponentStatus status;

        Entry(long generation, boolean enabled, ComponentStatus status) {
            this.generation = generation;
            this.enabled = enabled;
            this.status = status;
        }
    }

    public ComponentRegistry() {
        this(Clock.systemUTC());
    }

    /** platform's event catalogue, and the code of a state change in it. */
    static final String EVENTS = "platform";
    static final String CHANGED = "platform.component.changed";

    ComponentRegistry(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Registers a component, {@link ComponentState#STARTING} when enabled and {@link ComponentState#DISABLED}
     * when not.
     *
     * @param name S-9's spelling, the part of its {@code OIDF_<NAME>_ENABLED} switch between the prefix and the
     *             suffix ({@code FEDERATION}, {@code SSF_RECEIVER}): an upper case letter, then upper case letters,
     *             digits and {@code _}, at most 64 characters
     * @throws IllegalArgumentException for any other name - a constant in the caller's code, so a bad one is a
     *                                  bug to find in its tests, not at run time
     */
    public Component register(String name, boolean enabled) {
        return this.register(name, enabled, "");
    }

    /** As {@link #register(String, boolean)}, with a note shown beside the state (how its switch was read). */
    public Component register(String name, boolean enabled, String note) {
        checkName(name);
        String why = note(note);
        ComponentState initial = enabled ? ComponentState.STARTING : ComponentState.DISABLED;
        long generation;
        synchronized (this) {
            generation = ++this.generations;
            this.entries.put(name, new Entry(generation, enabled, new ComponentStatus(name, enabled, initial, why, this.clock.instant())));
        }
        LOG.info("Component " + name + ": registered " + initial);
        return new Component(name, generation);
    }

    /** One component's state, if it is registered. */
    public synchronized Optional<ComponentStatus> status(String name) {
        Entry e = this.entries.get(name);
        return e == null ? Optional.empty() : Optional.of(e.status);
    }

    /** Every registered component's state, ordered by name. */
    public synchronized List<ComponentStatus> snapshot() {
        List<ComponentStatus> out = new ArrayList<>();
        for (Entry e : this.entries.values()) {
            out.add(e.status);
        }
        out.sort(Comparator.comparing(ComponentStatus::name));
        return List.copyOf(out);
    }

    /**
     * Moves a component to a state. Nothing happens, and the answer is {@code false}, when the handle is from an
     * earlier registration or the component is disabled. A move to the state it is already in with the same
     * reason keeps the time it entered it.
     */
    boolean move(String name, long generation, ComponentState to, String reason) {
        String why = to.needsReason() ? clean(reason) : note(reason);
        ComponentState from;
        synchronized (this) {
            // Never null: a handle exists only for a registered name, and nothing removes one.
            Entry e = this.entries.get(name);
            if (e.generation != generation || !e.enabled) {
                return false;
            }
            from = e.status.state();
            if (from == to && e.status.reason().equals(why)) {
                return true;
            }
            e.status = new ComponentStatus(name, true, to, why, this.clock.instant());
        }
        String line = "Component " + name + ": " + from + " -> " + to + (why.isEmpty() ? "" : " (" + why + ")");
        if (to.needsReason()) {
            LOG.warn(line);
        } else {
            LOG.info(line);
        }
        changed(name, from, to);
        return true;
    }

    /** The one event of a state change (PR-5, O-2's platform family): counted, never audited; it never throws. */
    static void changed(String name, ComponentState from, ComponentState to) {
        try {
            Events.event(EVENTS, CHANGED).field("component", name).field("from", from.name()).field("to", to.name()).emit();
        } catch (RuntimeException | LinkageError e) {
            // An event is a count: a catalogue that cannot be read never fails a component's move.
        }
    }

    static void checkName(String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("a component name is 1-64 of A-Z, 0-9 and '_', starting with a letter, as S-9 spells it (SSF_RECEIVER)");
        }
    }

    /** A note on a state that needs no reason: empty when none is given, else cleaned as a reason is. */
    static String note(String note) {
        return note == null || note.isBlank() ? "" : clean(note);
    }

    /** A reason as one short line an operator can read. */
    static String clean(String reason) {
        if (reason == null || reason.isBlank()) {
            return "no reason given";
        }
        String text = reason.strip();
        int end = Math.min(text.length(), MAX_REASON);
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

    /** What a component holds to report its state. */
    public final class Component {
        private final String name;
        private final long generation;

        private Component(String name, long generation) {
            this.name = name;
            this.generation = generation;
        }

        public String name() {
            return this.name;
        }

        /** Its state now, as the registry holds it. */
        public ComponentStatus status() {
            return ComponentRegistry.this.status(this.name).orElseThrow();
        }

        /** Starting again, after a failure: what the {@link Supervisor}'s attempt records before it retries. */
        public boolean starting() {
            return move(this.name, this.generation, ComponentState.STARTING, null);
        }

        public boolean ready() {
            return move(this.name, this.generation, ComponentState.READY, null);
        }

        /** Ready, with a note shown beside the state. */
        public boolean ready(String note) {
            return move(this.name, this.generation, ComponentState.READY, note);
        }

        /** Starting, with a note shown beside the state. */
        public boolean starting(String note) {
            return move(this.name, this.generation, ComponentState.STARTING, note);
        }

        public boolean degraded(String reason) {
            return move(this.name, this.generation, ComponentState.DEGRADED, reason);
        }

        public boolean failedConfig(String reason) {
            return move(this.name, this.generation, ComponentState.FAILED_CONFIG, reason);
        }

        public boolean failedDependency(String reason) {
            return move(this.name, this.generation, ComponentState.FAILED_DEPENDENCY, reason);
        }

        public boolean refused(String reason) {
            return move(this.name, this.generation, ComponentState.REFUSED, reason);
        }
    }
}
