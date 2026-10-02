package com.pingidentity.ps.oidf.rar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * A loopback server that answers every request with the same bytes, verbatim: for the answers a real HTTP
 * server will not send, such as a status line or a header name the client cannot parse. It reads each request
 * whole and waits for the client to close before closing its side, so the client never sees a reset that the
 * answer did not cause.
 */
final class RawHttpServer implements AutoCloseable {

    private final ServerSocket socket;

    RawHttpServer(String response) throws IOException {
        this.socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        byte[] bytes = response.getBytes(StandardCharsets.ISO_8859_1);
        Thread acceptor = new Thread(() -> {
            while (!socket.isClosed()) {
                try (Socket connection = socket.accept()) {
                    connection.setSoTimeout(5_000);
                    readRequest(connection.getInputStream());
                    OutputStream out = connection.getOutputStream();
                    out.write(bytes);
                    out.flush();
                    connection.shutdownOutput();
                    while (connection.getInputStream().read() != -1) {
                        // until the client closes
                    }
                } catch (IOException ignored) {
                    // the server closed under accept, or the client went away first
                }
            }
        }, "raw-http-server");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** A plain-HTTP URL on this server. */
    String url(String path) {
        return "http://127.0.0.1:" + socket.getLocalPort() + path;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    /** The head up to its blank line, then as many body bytes as its Content-Length names. */
    private static void readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int last4 = 0;
        int b;
        while ((b = in.read()) != -1) {
            head.write(b);
            last4 = (last4 << 8) | b;
            if (last4 == 0x0d0a0d0a) {
                break;
            }
        }
        int length = 0;
        for (String line : head.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                length = Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        in.readNBytes(length);
    }
}
