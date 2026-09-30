/*
 * When a copy may start an executor, and how a name is held and given back.
 */
package com.pingidentity.ps.oidf.platform.exec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ExecutorRegistryTest {

    private static final String OWN = ManagedExecutors.class.getPackageName();

    private final AtomicBoolean shutDown = new AtomicBoolean();
    private final List<String> registered = new CopyOnWriteArrayList<>();
    private final List<ManagedExecutor> made = new CopyOnWriteArrayList<>();

    private ExecutorRegistry registry(String copyId, String ownPackage, boolean registerAccepts) {
        return new ExecutorRegistry(copyId, ownPackage, this.shutDown::get, (name, resource) -> {
            this.registered.add(name);
            if (!registerAccepts) {
                try {
                    resource.close();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            return registerAccepts;
        }, (name, nanos, failed) -> { });
    }

    private Optional<ManagedExecutor> create(ExecutorRegistry registry, String name) {
        Optional<ManagedExecutor> executor = registry.create(name);
        executor.ifPresent(this.made::add);
        return executor;
    }

    @AfterEach
    void tearDown() {
        this.made.forEach(e -> e.close(Duration.ofSeconds(5)));
        for (String name : List.of("reg-a", "reg-b", "reg-c", "reg-d")) {
            System.clearProperty(ExecutorRegistry.OWNER_PREFIX + name);
        }
    }

    @Test
    void anExecutorIsRegisteredWithTheLifecycleAndListedUntilItCloses() {
        ExecutorRegistry registry = registry("copy-1", OWN, true);
        ManagedExecutor executor = create(registry, "reg-a").orElseThrow();
        assertEquals(List.of("executor reg-a"), this.registered);
        assertEquals("copy-1", System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-a"), "claimed JVM-wide");
        assertEquals(Optional.of(executor), registry.live("reg-a"));
        assertEquals(List.of(new ManagedExecutor.Status("reg-a", false, 0, 0)), registry.snapshot());

        executor.close();
        assertEquals(Optional.empty(), registry.live("reg-a"));
        assertEquals(List.of(), registry.snapshot());
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-a"), "and given back");
        assertTrue(create(registry, "reg-a").isPresent(), "so it can start again");
    }

    @Test
    void aNameRunsOnceInTheJvmWhicheverCopyAsks() {
        ExecutorRegistry first = registry("copy-1", OWN, true);
        ExecutorRegistry second = registry("copy-2", OWN, true);
        ManagedExecutor running = create(first, "reg-b").orElseThrow();
        assertEquals(Optional.empty(), create(first, "reg-b"), "the same copy again: a servlet initialised twice");
        assertEquals(Optional.empty(), create(second, "reg-b"), "another copy: the same job in another loader");
        assertEquals(List.of("executor reg-b"), this.registered);

        running.close();
        assertTrue(create(second, "reg-b").isPresent(), "once it is closed, another copy may run it");
    }

    @Test
    void aReleaseByACopyThatDoesNotHoldTheNameLeavesItHeld() {
        assertTrue(ExecutorRegistry.claim("reg-c", "copy-1"));
        ExecutorRegistry.release("reg-c", "copy-2");
        assertEquals("copy-1", System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-c"));
        ExecutorRegistry.release("reg-c", "copy-1");
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-c"));
    }

    @Test
    void aRelocatedCopyStartsNothing() {
        ExecutorRegistry plugin = registry("copy-1", "com.pingidentity.ps.oidf.rar.shaded.platform.exec", true);
        assertEquals(Optional.empty(), create(plugin, "reg-a"));
        assertEquals(List.of(), this.registered);
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-a"), "and claims nothing");
    }

    @Test
    void theUnrelocatedPackageIsThisOne() {
        assertEquals(OWN, ExecutorRegistry.unrelocatedPackage());
        assertFalse(ExecutorRegistry.relocated(OWN));
        assertTrue(ExecutorRegistry.relocated("com.pingidentity.ps.oidf.cibasim.shaded.platform.exec"));
    }

    @Test
    void aCopyThatHasShutDownStartsNothing() {
        this.shutDown.set(true);
        assertEquals(Optional.empty(), create(registry("copy-1", OWN, true), "reg-a"));
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-a"));
    }

    @Test
    void aLifecycleThatShutsDownDuringTheStartClosesItAndGivesTheNameBack() {
        ExecutorRegistry registry = registry("copy-1", OWN, false);
        assertEquals(Optional.empty(), create(registry, "reg-d"));
        assertEquals(List.of("executor reg-d"), this.registered);
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "reg-d"));
        assertEquals(List.of(), registry.snapshot());
    }

    @Test
    void namesAreConstantsAndABadOneIsABug() {
        for (String good : List.of("a", "registration-sweeper", "ssf-push-delivery", "x1-2", "a".repeat(40))) {
            assertEquals(good, ExecutorRegistry.checkName(good));
        }
        for (String bad : new String[] {null, "", "A", "1a", "-a", "a-", "a--b", "a_b", "a b", "a".repeat(41), "oidf.x"}) {
            assertThrows(IllegalArgumentException.class, () -> ExecutorRegistry.checkName(bad), String.valueOf(bad));
        }
    }
}
