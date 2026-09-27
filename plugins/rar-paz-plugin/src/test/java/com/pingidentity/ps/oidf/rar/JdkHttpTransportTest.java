package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;

/**
 * Which failures of the JDK client read as "the PDP was not reached" - the one class fail-open grants
 * through - and which stay refusals. A TLS failure is a refusal even though it happens before any byte of
 * the request is sent: something answered on that port and could not prove it was the PDP.
 */
class JdkHttpTransportTest {

    @Test
    void connectResetAndDeadlineAreUnreachable() {
        for (IOException e : List.of(
                new ConnectException("Connection refused"),
                new HttpConnectTimeoutException("connect timed out"),
                new HttpTimeoutException("request timed out"),
                new SocketTimeoutException("Read timed out"),
                new UnknownHostException("pdp.internal"),
                new SocketException("Connection reset"),
                new EOFException("EOF reached while reading"),
                new ClosedChannelException(),
                new IOException("connection reset by peer"),
                new IOException("wrapped", new ConnectException("Connection refused")))) {
            IOException classified = JdkHttpTransport.classify(e);
            assertInstanceOf(PdpUnavailableException.class, classified, e.toString());
            assertSame(e, classified.getCause(), e.toString());
        }
    }

    @Test
    void tlsFailuresAndUnknownFailuresAreRefusals() {
        for (IOException e : List.of(
                new SSLHandshakeException("PKIX path building failed"),
                new IOException("handshake", new SSLHandshakeException("No subject alternative DNS name")),
                new SSLHandshakeException("wrapping a reset underneath is still TLS"),
                new IOException("something else"),
                new IOException(),
                new IOException(new IllegalStateException("not an IOException underneath")))) {
            IOException classified = JdkHttpTransport.classify(e);
            assertSame(e, classified, e.toString());
            assertFalse(classified instanceof PdpUnavailableException, e.toString());
        }
        // TLS anywhere in the chain wins over a transport cause beneath it.
        SSLHandshakeException badCert = new SSLHandshakeException("bad cert");
        badCert.initCause(new SocketException("reset"));
        IOException tlsOverReset = new IOException("io", badCert);
        assertSame(tlsOverReset, JdkHttpTransport.classify(tlsOverReset));
        // A cyclic cause chain (initCause forbids only a direct self-cause) does not loop.
        IOException a = new IOException("a");
        IOException b = new IOException("b");
        a.initCause(b);
        b.initCause(a);
        assertSame(a, JdkHttpTransport.classify(a));
        IOException resetDeep = new IOException("a");
        IOException resetDeepB = new IOException("b", new SocketException("reset"));
        resetDeep.initCause(resetDeepB);
        assertInstanceOf(PdpUnavailableException.class, JdkHttpTransport.classify(resetDeep));
    }

    @Test
    void anAlreadyClassifiedFailurePassesThrough() {
        PdpUnavailableException down = new PdpUnavailableException("down");
        assertSame(down, JdkHttpTransport.classify(down));
    }

    /** Against a closed port on loopback: the real client throws, and the transport says "unreachable". */
    @Test
    void aConnectionRefusedOnTheWireIsUnavailable() throws Exception {
        int closedPort;
        try (java.net.ServerSocket probe = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            closedPort = probe.getLocalPort();
        }
        JdkHttpTransport transport = new JdkHttpTransport(false, 2_000);
        assertThrows(PdpUnavailableException.class,
                () -> transport.post("http://127.0.0.1:" + closedPort + "/decide", "{}", Map.of("Content-Type", "application/json")));
        assertTrue(new JdkHttpTransport(true, 0) != null, "the insecure context builds");
    }
}
