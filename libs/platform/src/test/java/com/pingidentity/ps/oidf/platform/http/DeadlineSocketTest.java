package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.io.InputStream;
import java.net.InetAddress;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.Test;

/** Every way of reading the socket is bounded, and failures are named by the phase they happened in. */
class DeadlineSocketTest {

    @Test
    void aJvmWideProxyIsNeverAskedSoThePinnedAddressIsDialledDirectly() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        ProxySelector previous = ProxySelector.getDefault();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             ServerSocket deadProxy = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            InetSocketAddress proxyAddress = (InetSocketAddress) deadProxy.getLocalSocketAddress();
            deadProxy.close();
            // What a socksProxyHost set for the JVM amounts to: a selector that sends every socket through SOCKS.
            ProxySelector.setDefault(new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    asked.incrementAndGet();
                    return List.of(new Proxy(Proxy.Type.SOCKS, proxyAddress));
                }

                @Override
                public void connectFailed(URI uri, SocketAddress address, IOException e) {
                    asked.incrementAndGet();
                }
            });
            try (DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(5)))) {
                socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
                try (Socket peer = server.accept()) {
                    assertEquals(socket.getLocalPort(), peer.getPort());
                }
            }
        } finally {
            ProxySelector.setDefault(previous);
        }
        assertEquals(0, asked.get());
    }

    @Test
    void singleByteReadsAndSkipsAreBoundedToo() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(5)))) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
            try (Socket peer = server.accept()) {
                peer.getOutputStream().write("abcdef".getBytes(StandardCharsets.US_ASCII));
                peer.getOutputStream().flush();
                InputStream in = socket.getInputStream();
                assertSame(in, socket.getInputStream());
                assertEquals('a', in.read());
                assertEquals(0L, in.skip(0));
                assertEquals(0L, in.skip(-3));
                assertEquals(2L, in.skip(2));
                assertEquals('d', in.read());
                socket.readBy(Deadline.after(Duration.ofMillis(200)), DeadlineSocket.Phase.BODY);
                assertEquals(DeadlineSocket.Phase.BODY, socket.phase());
                assertEquals(2, in.read(new byte[8], 0, 8));
                assertThrows(SocketTimeoutException.class, in::read);
                assertTrue(socket.timedOut());
                socket.readBy(Deadline.after(Duration.ZERO), DeadlineSocket.Phase.BODY);
                assertThrows(SocketTimeoutException.class, () -> in.read(new byte[1], 0, 1));
            }
        }
    }

    @Test
    void aSingleByteReadThatWaitsTooLongIsATimeout() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofMillis(150)))) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
            try (Socket peer = server.accept()) {
                assertThrows(SocketTimeoutException.class, () -> socket.getInputStream().read(new byte[4], 0, 4));
                assertTrue(socket.timedOut());
            }
        }
    }

    @Test
    void aTlsFailureAfterTheHandshakeIsAnIoFailure() throws Exception {
        AddressPolicy.Target target = new AddressPolicy.Target(URI.create("https://h/"), true, "h", 443, List.of());
        DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(1)));
        Deadline total = Deadline.after(Duration.ofSeconds(1));
        assertEquals(Reason.TLS, OutboundHttp.failure(new SSLException("bad"), socket, total, target).reason());
        socket.readBy(total, DeadlineSocket.Phase.HEADERS);
        assertEquals(Reason.IO, OutboundHttp.failure(new SSLException("bad record"), socket, total, target).reason());
        assertEquals(Reason.MALFORMED_RESPONSE, OutboundHttp.failure(new IllegalStateException("x"), socket, total, target).reason());
        socket.close();
    }

    @Test
    void aReadOutlastsItsSlicesUntilTheDeadline() throws Exception {
        // A peer silent for three slices, well inside the deadline: the read waits across the slices and returns.
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(5)))) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
            try (Socket peer = server.accept()) {
                CompletableFuture<Void> late = CompletableFuture.runAsync(() -> {
                    try {
                        Thread.sleep(3L * DeadlineSocket.SLICE_MILLIS);
                        peer.getOutputStream().write('z');
                        peer.getOutputStream().flush();
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
                assertEquals('z', socket.getInputStream().read());
                assertFalse(socket.timedOut());
                late.get(5, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void anInterruptEndsAReadOnASilentPeerAndIsKept() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(30)))) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
            try (Socket peer = server.accept()) {
                AtomicReference<Object> outcome = new AtomicReference<>();
                CountDownLatch reading = new CountDownLatch(1);
                CountDownLatch done = new CountDownLatch(1);
                Thread reader = new Thread(() -> {
                    try {
                        reading.countDown();
                        socket.getInputStream().read(new byte[4], 0, 4);
                        outcome.set("read");
                    } catch (IOException e) {
                        outcome.set(e);
                    }
                    outcome.compareAndSet(null, "none");
                    if (Thread.currentThread().isInterrupted()) {
                        done.countDown();
                    }
                });
                reader.start();
                assertTrue(reading.await(5, TimeUnit.SECONDS));
                Thread.sleep(DeadlineSocket.SLICE_MILLIS);
                long interrupted = System.nanoTime();
                reader.interrupt();
                assertTrue(done.await(5, TimeUnit.SECONDS), "the read ended and the thread kept its interrupt");
                long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - interrupted);
                assertTrue(took < 4L * DeadlineSocket.SLICE_MILLIS, "ended within about a slice, " + took + " ms");
                IOException e = assertInstanceOf(IOException.class, outcome.get());
                assertInstanceOf(InterruptedIOException.class, e);
                assertFalse(e instanceof SocketTimeoutException, "an interrupt is not a timeout");
                assertFalse(socket.timedOut());
            }
        }
    }

    @Test
    void anAlreadyInterruptedThreadReadsNothing() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
             DeadlineSocket socket = new DeadlineSocket(Deadline.after(Duration.ofSeconds(5)))) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.getLocalPort()), 1000);
            try (Socket peer = server.accept()) {
                peer.getOutputStream().write('a');
                peer.getOutputStream().flush();
                Thread.currentThread().interrupt();
                try {
                    assertThrows(InterruptedIOException.class, () -> socket.getInputStream().read());
                    assertTrue(Thread.currentThread().isInterrupted());
                } finally {
                    Thread.interrupted();
                }
                assertEquals('a', socket.getInputStream().read(), "the byte is still there for a thread not interrupted");
            }
        }
    }

    @Test
    void anInterruptedExchangeIsAnIoFailureAndKeepsTheInterrupt() throws Exception {
        // What a managed executor's close does to a fetch stuck on a peer that accepted and never answered.
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            OutboundHttp http = OutboundHttp.builder(AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build()).build();
            String url = "http://127.0.0.1:" + silent.getLocalPort() + "/";
            AtomicReference<Object> outcome = new AtomicReference<>();
            CountDownLatch done = new CountDownLatch(1);
            Thread fetcher = new Thread(() -> {
                try {
                    outcome.set(http.get(url, "*/*", Deadline.after(Duration.ofSeconds(30))));
                } catch (OutboundHttpException e) {
                    outcome.set(e.reason() + " interrupted=" + Thread.currentThread().isInterrupted());
                }
                done.countDown();
            });
            fetcher.start();
            try (Socket accepted = silent.accept()) {
                Thread.sleep(DeadlineSocket.SLICE_MILLIS);
                fetcher.interrupt();
                assertTrue(done.await(5, TimeUnit.SECONDS));
                assertEquals("IO interrupted=true", outcome.get());
            }
        }
    }
}
