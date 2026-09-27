/*
 * The poll loop on its managed executor: its thread, its tick, a tick that throws, and one loop in the JVM.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PollReceiverLoopTest {

    private final SsfReceiverService receiver = new SsfReceiverService(new SetVerifier("https://tx.example.com", null,
            refresh -> List.of()));

    @AfterEach
    void tearDown() {
        ManagedExecutors.live(PollReceiverClient.EXECUTOR_NAME).ifPresent(ManagedExecutor::close);
    }

    @Test
    void theLoopPollsEveryTickOnANamedExecutorAndATransportFailureIsNoFailureOfTheLoop() throws Exception {
        AtomicInteger polls = new AtomicInteger();
        PollReceiverClient client = new PollReceiverClient(this.receiver, body -> {
            if (polls.incrementAndGet() == 1) {
                throw new java.io.IOException("transmitter down");
            }
            return "{\"sets\":{}}";
        }, 10);
        client.start(1);
        client.start(1);
        try {
            ManagedExecutor executor = ManagedExecutors.live(PollReceiverClient.EXECUTOR_NAME).orElseThrow();
            assertEquals("oidf-ssf-poll-receiver", executor.threadNamePrefix());
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (executor.runs() < 2) {
                assertTrue(System.nanoTime() < deadline, "timed out");
                Thread.sleep(20);
            }
            assertTrue(polls.get() >= 2, "polled again after the failure");
            assertEquals(0, executor.failures());
        } finally {
            client.stop();
            client.stop();
        }
        assertEquals(Optional.empty(), ManagedExecutors.live(PollReceiverClient.EXECUTOR_NAME));
    }

    @Test
    void aSecondClientStartsNoSecondLoop() {
        PollReceiverClient first = new PollReceiverClient(this.receiver, body -> "{}", 10);
        PollReceiverClient second = new PollReceiverClient(this.receiver, body -> {
            throw new AssertionError("must not poll");
        }, 10);
        first.start(3600);
        try {
            ManagedExecutor running = ManagedExecutors.live(PollReceiverClient.EXECUTOR_NAME).orElseThrow();
            second.start(3600);
            assertEquals(running, ManagedExecutors.live(PollReceiverClient.EXECUTOR_NAME).orElseThrow());
            second.stop();
            assertTrue(!running.isClosed(), "stopping the client that started nothing stops nothing");
        } finally {
            first.stop();
        }
    }
}
