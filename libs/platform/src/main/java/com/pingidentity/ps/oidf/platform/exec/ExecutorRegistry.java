/*
 * One loaded copy's managed executors, and the rules for whether it may start one.
 */
package com.pingidentity.ps.oidf.platform.exec;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.BiPredicate;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * The executors one copy of platform runs, by name, and the three checks made before it starts one:
 *
 * <ol>
 * <li><b>Not in a relocated copy.</b> A plugin shades and relocates platform (classloaders rule 5), and a
 * plugin's loader has nothing to stop a thread it started (rule 2), so a relocated copy starts none.</li>
 * <li><b>Not after this copy's lifecycle has shut down.</b> The executor would be closed as soon as it was
 * registered.</li>
 * <li><b>One per name in the JVM.</b> The name is claimed in the JVM-wide System property
 * {@code oidf.exec.owner.<name>} under a lock on {@code System.class}, as the registration sweeper's owner is
 * (rule 4), and given back when the executor closes. So a second start of the same job - a servlet initialised
 * twice, or the same servlet in another loader - finds it running and starts nothing.</li>
 * </ol>
 *
 * <p>Which loader is the webapp's is not visible from inside a copy until F-2's listener marks it
 * ({@code Lifecycle.markWebapp()}); until then the engine's copy is told apart only by nothing in it calling a
 * start - every start is in a servlet's or filter's {@code init}, which only the webapp's loader runs.
 */
final class ExecutorRegistry {

    /** The JVM-wide claim on a name: {@code oidf.exec.owner.<name>}, holding the owning copy's id. */
    static final String OWNER_PREFIX = "oidf.exec.owner.";

    /** A name: lower case letters, digits and single hyphens, starting with a letter, at most 40 characters. */
    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9]*(-[a-z0-9]+)*");
    static final int MAX_NAME_LENGTH = 40;

    private static final PlatformLog LOG = PlatformLog.get(ExecutorRegistry.class);

    private final String copyId;
    private final String ownPackage;
    private final BooleanSupplier shutDown;
    private final BiPredicate<String, AutoCloseable> register;
    private final ManagedExecutor.RunRecorder recorder;
    private final Map<String, ManagedExecutor> live = new TreeMap<>();

    /**
     * @param copyId     what this copy writes into a claim
     * @param ownPackage the package this copy's classes are in, relocated or not
     * @param shutDown   whether this copy's lifecycle has shut down
     * @param register   this copy's lifecycle's register; answers {@code false} when it has shut down (and has
     *                   closed what it was given)
     * @param recorder   where runs are counted
     */
    ExecutorRegistry(String copyId, String ownPackage, BooleanSupplier shutDown, BiPredicate<String, AutoCloseable> register,
                     ManagedExecutor.RunRecorder recorder) {
        this.copyId = copyId;
        this.ownPackage = ownPackage;
        this.shutDown = shutDown;
        this.register = register;
        this.recorder = recorder;
    }

    /**
     * The package this code is in when it is not relocated. Written in parts so that a shading relocation, which
     * rewrites string constants that look like the package it moves, leaves it alone and the comparison still
     * sees the move.
     */
    static String unrelocatedPackage() {
        return String.join(".", "com", "pingidentity", "ps", "oidf", "platform", "exec");
    }

    /** Whether a copy whose classes are in {@code packageName} is a plugin's relocated copy. */
    static boolean relocated(String packageName) {
        return !unrelocatedPackage().equals(packageName);
    }

    /** Refuses a name that is not one: names are constants, so a bad one is a bug for the caller's tests to find. */
    static String checkName(String name) {
        if (name == null || name.length() > MAX_NAME_LENGTH || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("an executor name is 1-" + MAX_NAME_LENGTH
                    + " lower case letters, digits and single hyphens, starting with a letter: " + name);
        }
        return name;
    }

    /**
     * A new executor named {@code name}, or none when this copy may not start it - each refusal logged with its
     * reason.
     */
    Optional<ManagedExecutor> create(String name) {
        checkName(name);
        if (relocated(this.ownPackage)) {
            LOG.warn("Managed executor " + name + " not started: this is a relocated copy of platform (" + this.ownPackage
                    + "), and a plugin's copy starts no threads");
            return Optional.empty();
        }
        if (this.shutDown.getAsBoolean()) {
            LOG.warn("Managed executor " + name + " not started: this copy of platform has shut down");
            return Optional.empty();
        }
        ManagedExecutor executor;
        synchronized (this) {
            if (!claim(name, this.copyId)) {
                LOG.info("Managed executor " + name + " not started: it already runs in this JVM (" + OWNER_PREFIX + name
                        + "=" + System.getProperty(OWNER_PREFIX + name) + ")");
                return Optional.empty();
            }
            executor = new ManagedExecutor(name, this.recorder, () -> this.closed(name));
            this.live.put(name, executor);
        }
        if (!this.register.test("executor " + name, executor)) {
            return Optional.empty();
        }
        return Optional.of(executor);
    }

    /** An executor has closed: the name is free again, in this copy and in the JVM. */
    private void closed(String name) {
        synchronized (this) {
            this.live.remove(name);
        }
        release(name, this.copyId);
    }

    /** Claims {@code name} for {@code owner} JVM-wide; {@code false} when any copy holds it already. */
    static boolean claim(String name, String owner) {
        synchronized (System.class) {
            if (System.getProperty(OWNER_PREFIX + name) != null) {
                return false;
            }
            System.setProperty(OWNER_PREFIX + name, owner);
            return true;
        }
    }

    /** Gives {@code name} back, only if {@code owner} holds it. */
    static void release(String name, String owner) {
        synchronized (System.class) {
            if (owner.equals(System.getProperty(OWNER_PREFIX + name))) {
                System.clearProperty(OWNER_PREFIX + name);
            }
        }
    }

    synchronized Optional<ManagedExecutor> live(String name) {
        return Optional.ofNullable(this.live.get(name));
    }

    synchronized List<ManagedExecutor.Status> snapshot() {
        List<ManagedExecutor.Status> statuses = new ArrayList<>(this.live.size());
        for (ManagedExecutor executor : this.live.values()) {
            statuses.add(executor.status());
        }
        return List.copyOf(statuses);
    }
}
