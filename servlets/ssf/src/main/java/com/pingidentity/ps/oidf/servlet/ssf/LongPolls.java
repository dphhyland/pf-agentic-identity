/*
 * RFC 8936 long polls held off the request thread: an async request and one managed executor that checks them.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The long polls the poll endpoint is holding (plan item H-SSF-2). RFC 8936 §2.5: "If no SETs are available at the
 * time of the request, the SET Transmitter SHALL delay responding until a SET is available or the timeout interval
 * has elapsed unless the poll request parameter "returnImmediately" is present with the value "true"", and §2.2 leaves
 * the timeout to "the configuration between the participants" - here {@code OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS}.
 *
 * <p>No request thread waits. The servlet puts its request into async mode and hands it here; one managed executor
 * ({@value #EXECUTOR_NAME}) checks every held poll each {@link #TICK}: a SET waiting for its stream (a cheap one-row
 * read of the store) answers it with a fresh poll, and the wait running out answers it with the empty set. The store
 * is read rather than told, so a SET queued by another node releases a poll held here as surely as one queued here.
 */
final class LongPolls {

    private static final Log LOG = LogFactory.getLog(LongPolls.class);

    /** The executor's name; its thread is {@code oidf-ssf-long-poll-1}. */
    static final String EXECUTOR_NAME = "ssf-long-poll";
    /** How often the held polls are checked. */
    static final Duration TICK = Duration.ofMillis(250);

    /** One held poll. */
    private record Held(long deadlineMillis, BooleanSupplier ready, Supplier<Map<String, Object>> poll,
            Consumer<Map<String, Object>> answer, Map<String, Object> empty, AtomicBoolean done) {

        /** Answers once, whichever of the tick, the container's timeout or a failure gets here first. */
        void finish(Map<String, Object> body) {
            if (this.done.compareAndSet(false, true)) {
                this.answer.accept(body);
            }
        }
    }

    private static final ConcurrentLinkedQueue<Held> HELD = new ConcurrentLinkedQueue<>();
    private static final Object LOCK = new Object();
    private static volatile ManagedExecutor executor;
    private static volatile Clock clock = Clock.systemUTC();

    private LongPolls() {
    }

    /**
     * Holds a poll until {@code ready} says a SET is waiting - then {@code answer} gets {@code poll}'s body - or until
     * {@code wait} has passed - then it gets {@code empty}. Returns the handle that ends it early ({@link #finish}), or
     * empty when this copy may not start the executor, and the caller answers at once.
     */
    static Optional<Runnable> hold(Duration wait, BooleanSupplier ready, Supplier<Map<String, Object>> poll,
            Consumer<Map<String, Object>> answer, Map<String, Object> empty) {
        if (!started()) {
            return Optional.empty();
        }
        Held held = new Held(clock.millis() + wait.toMillis(), ready, poll, answer, empty, new AtomicBoolean());
        HELD.add(held);
        return Optional.of(() -> {
            HELD.remove(held);
            held.finish(empty);
        });
    }

    private static boolean started() {
        synchronized (LOCK) {
            if (executor == null) {
                executor = ManagedExecutors.every(EXECUTOR_NAME, TICK, LongPolls::tick).orElse(null);
                if (executor == null) {
                    LOG.warn((Object) "SSF long polling is unavailable in this copy (its executor did not start);"
                            + " polls are answered at once");
                }
            }
            return executor != null;
        }
    }

    /** One check of every held poll. */
    static void tick() {
        long now = clock.millis();
        for (Iterator<Held> it = HELD.iterator(); it.hasNext(); ) {
            Held held = it.next();
            if (held.done().get()) {
                it.remove();
                continue;
            }
            try {
                if (held.ready().getAsBoolean()) {
                    Map<String, Object> body = held.poll().get();
                    if (!isEmpty(body) || now >= held.deadlineMillis()) {
                        it.remove();
                        held.finish(body);
                    }
                } else if (now >= held.deadlineMillis()) {
                    it.remove();
                    held.finish(held.empty());
                }
            } catch (RuntimeException e) {
                LOG.warn((Object) ("SSF long poll failed; answered with no SETs: " + e));
                it.remove();
                held.finish(held.empty());
            }
        }
    }

    private static boolean isEmpty(Map<String, Object> body) {
        Object sets = body.get("sets");
        return !(sets instanceof Map) || ((Map<?, ?>) sets).isEmpty();
    }

    /** How many polls are held now. */
    static int held() {
        return HELD.size();
    }

    /** Test hook: answer nothing more, stop the executor and use {@code newClock}. */
    static void resetForTests(Clock newClock) {
        synchronized (LOCK) {
            HELD.clear();
            if (executor != null) {
                executor.close();
            }
            executor = null;
            clock = newClock;
        }
    }
}
