package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.io.InputStream;
import java.net.InetAddress;
import java.io.IOException;
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
import java.util.concurrent.atomic.AtomicInteger;
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
}
