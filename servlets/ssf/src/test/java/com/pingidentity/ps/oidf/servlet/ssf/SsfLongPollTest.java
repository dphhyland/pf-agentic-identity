/*
 * H-SSF-2: a poll with returnImmediately false is held off the request thread until a SET arrives or the wait runs out.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.DeliveryMethod;
import com.pingidentity.ps.oidf.ssf.InMemorySsfStore;
import com.pingidentity.ps.oidf.ssf.PendingSet;
import com.pingidentity.ps.oidf.ssf.SetPublisher;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfLongPollTest {

    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));

    /** One poll: its request, response, async context and what was written. */
    private static final class Exchange {
        final HttpServletRequest req = mock(HttpServletRequest.class);
        final HttpServletResponse resp = mock(HttpServletResponse.class);
        final AsyncContext async = mock(AsyncContext.class);
        final ByteArrayOutputStream sink = new ByteArrayOutputStream();
        final CountDownLatch completed = new CountDownLatch(1);
        final AtomicReference<AsyncListener> listener = new AtomicReference<>();

        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(this.sink.toString(StandardCharsets.UTF_8));
        }
    }

    private InMemorySsfStore store;
    private StreamManagementService svc;
    private String id;

    @BeforeEach
    void fresh() throws Exception {
        LongPolls.resetForTests(Clock.systemUTC());
        service(1);
    }

    @AfterEach
    void stop() {
        LongPolls.resetForTests(Clock.systemUTC());
    }

    private void service(int waitSeconds) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        java.security.KeyPair pair = g.generateKeyPair();
        SigningKeyProvider keys = new SigningKeyProvider() {
            @Override
            public String keyId() {
                return "k";
            }

            @Override
            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) pair.getPrivate();
            }

            @Override
            public RSAPublicKey publicKey() {
                return (RSAPublicKey) pair.getPublic();
            }
        };
        store = new InMemorySsfStore();
        svc = new StreamManagementService(store, new SetMinter("RS256", keys), new SsfConfiguration.Builder()
                .issuer("https://op.example.com").pollLongPollWaitSeconds(waitSeconds).build(), SetPublisher.NOOP,
                OutboundUrlPolicy.from(Map.<String, String>of()::get));
        id = (String) svc.createStream(Map.of("delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED)), RECEIVER).get("stream_id");
    }

    private Exchange poll(String body, boolean async) throws Exception {
        Exchange x = new Exchange();
        when(x.req.getParameter("stream_id")).thenReturn(id);
        when(x.req.getRequestURI()).thenReturn("/ssf/poll");
        ByteArrayInputStream in = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        when(x.req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override
            public int read() {
                return in.read();
            }

            @Override
            public boolean isFinished() {
                return in.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener l) {
                throw new UnsupportedOperationException();
            }
        });
        when(x.req.isAsyncSupported()).thenReturn(async);
        when(x.req.startAsync()).thenReturn(x.async);
        when(x.async.getResponse()).thenReturn(x.resp);
        doAnswer(inv -> {
            x.completed.countDown();
            return null;
        }).when(x.async).complete();
        doAnswer(inv -> {
            x.listener.set(inv.getArgument(0));
            return null;
        }).when(x.async).addListener(any());
        when(x.resp.getWriter()).thenReturn(new PrintWriter(x.sink, true));
        SsfPollServlet.handle(x.req, x.resp, svc, RECEIVER);
        return x;
    }

    private void enqueue(String jti) {
        long now = SetMinter.nowSeconds();
        store.enqueue(PendingSet.fresh(jti, id, null, SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + jti, now, 0));
    }

    /**
     * RFC 8936 §2.5: "the SET Transmitter SHALL delay responding until a SET is available or the timeout interval has
     * elapsed"; §2.2: returnImmediately's "default value is "false"".
     */
    @Test
    @Requirement("RFC8936 §2.5")
    void aLongPollIsReleasedByANewSet() throws Exception {
        service(20);
        Exchange x = poll("{}", true);
        verify(x.req).startAsync();
        verify(x.async).setTimeout(25_000L);
        assertEquals(1, LongPolls.held());
        assertFalse(x.completed.await(300, TimeUnit.MILLISECONDS), "held: nothing to return yet");
        enqueue("j-new");
        assertTrue(x.completed.await(5, TimeUnit.SECONDS), "released by the SET");
        assertEquals(Map.of("j-new", "jws-j-new"), x.json().get("sets"));
        assertEquals(0, LongPolls.held());
    }

    @Test
    @Requirement("RFC8936 §2.5")
    void aLongPollIsReleasedByTheWaitWithNoSets() throws Exception {
        long started = System.nanoTime();
        Exchange x = poll("{\"returnImmediately\":false}", true);
        assertTrue(x.completed.await(5, TimeUnit.SECONDS));
        assertTrue(System.nanoTime() - started >= Duration.ofMillis(900).toNanos(), "held for the wait");
        assertEquals(Map.of(), x.json().get("sets"));
        assertEquals(false, x.json().get("moreAvailable"));
    }

    @Test
    void aPollThatAsksForAnImmediateAnswerOrHasSetsIsNotHeld() throws Exception {
        Exchange now = poll("{\"returnImmediately\":true}", true);
        verify(now.req, never()).startAsync();
        verify(now.resp).setStatus(200);
        enqueue("j-1");
        Exchange sets = poll("{}", true);
        verify(sets.req, never()).startAsync();
        assertEquals(Map.of("j-1", "jws-j-1"), sets.json().get("sets"));
    }

    /** PingFederate's runtime filters declare no async-supported: the poll is answered at once, as a wait of 0. */
    @Test
    void aChainThatCannotGoAsyncIsAnsweredAtOnce() throws Exception {
        for (int i = 0; i < 2; i++) {
            Exchange x = poll("{}", false);
            verify(x.req, never()).startAsync();
            assertEquals(Map.of(), x.json().get("sets"));
        }
    }

    @Test
    void theContainersTimeoutOrAnErrorAnswersAHeldPollOnce() throws Exception {
        service(20);
        Exchange x = poll("{}", true);
        AsyncListener l = x.listener.get();
        AsyncEvent event = new AsyncEvent(x.async);
        l.onStartAsync(event);
        l.onTimeout(event);
        assertTrue(x.completed.await(1, TimeUnit.SECONDS));
        assertEquals(Map.of(), x.json().get("sets"));
        l.onError(event);
        l.onComplete(event);
        verify(x.async).complete();
        assertEquals(0, LongPolls.held());
    }

    @Test
    void aPollThatFailsWhileHeldIsAnsweredWithNoSets() throws Exception {
        AtomicReference<Map<String, Object>> answered = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);
        Optional<Runnable> held = LongPolls.hold(Duration.ofSeconds(20), () -> true, () -> {
            throw new IllegalStateException("store down");
        }, body -> {
            answered.set(body);
            done.countDown();
        }, Map.of("sets", Map.of()));
        assertTrue(held.isPresent());
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(Map.of("sets", Map.of()), answered.get());
        held.get().run();
    }

    @Test
    void aHeldPollWhoseAnswerIsStillEmptyWaitsOn() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        int[] polls = {0};
        LongPolls.hold(Duration.ofMillis(700), () -> true, () -> {
            polls[0]++;
            return Map.of("sets", Map.of());
        }, body -> done.countDown(), Map.of("sets", Map.of()));
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertTrue(polls[0] >= 2, "polled again each tick until the wait ran out: " + polls[0]);
        Map<String, Object> noSets = Map.of();
        LongPolls.hold(Duration.ZERO, () -> true, () -> noSets, body -> { }, Map.of()).get().run();
    }

    /** Where this copy may not start the executor, a held poll is answered at once. */
    @Test
    void withoutItsExecutorAPollIsAnsweredAtOnce() throws Exception {
        Optional<ManagedExecutor> squatter = ManagedExecutors.every(LongPolls.EXECUTOR_NAME, Duration.ofHours(1), () -> { });
        try {
            service(20);
            Exchange x = poll("{}", true);
            assertTrue(x.completed.await(1, TimeUnit.SECONDS));
            assertEquals(Map.of(), x.json().get("sets"));
        } finally {
            squatter.ifPresent(ManagedExecutor::close);
        }
    }

    @Test
    void anAnswerThatCannotBeWrittenStillCompletes() throws Exception {
        AsyncContext async = mock(AsyncContext.class);
        when(async.getResponse()).thenThrow(new IllegalStateException("gone"));
        SsfPollServlet.answer(async, Map.of());
        verify(async).complete();
    }

    /** RFC 8936 §2.5.1: an invalid poll request is a 400. */
    @Test
    @Requirement("RFC8936 §2.5.1")
    void setErrsThatAreNotObjectsAreA400() throws Exception {
        verify(poll("{\"setErrs\":[\"j\"],\"returnImmediately\":true}", true).resp).setStatus(400);
        verify(poll("{\"setErrs\":{\"j\":\"bad\"},\"returnImmediately\":true}", true).resp).setStatus(400);
        enqueue("j-err");
        Exchange ok = poll("{\"setErrs\":{\"j-err\":{\"err\":\"invalid_key\",\"description\":\"d\"}},\"returnImmediately\":true}",
                true);
        verify(ok.resp).setStatus(200);
        assertEquals(Map.of(), ok.json().get("sets"), "released as the receiver reported it");
    }
}
