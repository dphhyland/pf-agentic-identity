package com.pingidentity.ps.oidf.platform.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * A one-connection-at-a-time HTTP (or HTTPS) server on 127.0.0.1 for these tests. It reads each request's head and
 * Content-Length body, records them with the server name TLS asked for, and hands the socket to a handler that writes
 * whatever bytes the test wants - well-formed or not, all at once or one a second.
 */
final class TestServer implements AutoCloseable {

    /** Writes the response to one request. */
    @FunctionalInterface
    interface Handler {
        void handle(Recorded request, OutputStream out) throws Exception;
    }

    /** What arrived: the request head as text, the body, and the SNI host name (null for none or plain HTTP). */
    record Recorded(String head, byte[] body, String sni) {
        String requestLine() {
            return head.substring(0, head.indexOf("\r\n"));
        }

        String header(String name) {
            for (String line : head.split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                    return line.substring(colon + 1).trim();
                }
            }
            return null;
        }
    }

    private final ServerSocket server;
    private final SSLContext tls;
    private volatile Handler handler;
    private final Thread thread;
    final BlockingQueue<Recorded> requests = new LinkedBlockingQueue<>();
    final AtomicInteger accepted = new AtomicInteger();

    private TestServer(SSLContext tls, Handler handler) throws IOException {
        this.tls = tls;
        this.handler = handler;
        this.server = new ServerSocket();
        this.server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 50);
        this.thread = new Thread(this::serve, "s5a-test-server");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    static TestServer plain(Handler handler) throws IOException {
        return new TestServer(null, handler);
    }

    static TestServer tls(SSLContext context, Handler handler) throws IOException {
        return new TestServer(context, handler);
    }

    void handler(Handler next) {
        this.handler = next;
    }

    int port() {
        return this.server.getLocalPort();
    }

    Recorded take() throws InterruptedException {
        Recorded recorded = this.requests.poll(10, TimeUnit.SECONDS);
        if (recorded == null) {
            throw new AssertionError("no request arrived");
        }
        return recorded;
    }

    private void serve() {
        while (!this.server.isClosed()) {
            Socket socket;
            try {
                socket = this.server.accept();
            } catch (IOException e) {
                return;
            }
            this.accepted.incrementAndGet();
            try (Socket plain = socket) {
                plain.setSoTimeout(10_000);
                Socket conversation = plain;
                String sni = null;
                if (this.tls != null) {
                    SSLSocket ssl = (SSLSocket) this.tls.getSocketFactory().createSocket(plain, null, plain.getPort(), false);
                    ssl.setUseClientMode(false);
                    ssl.startHandshake();
                    List<SNIServerName> names = ((ExtendedSSLSession) ssl.getSession()).getRequestedServerNames();
                    sni = names.isEmpty() ? null : ((SNIHostName) names.get(0)).getAsciiName();
                    conversation = ssl;
                }
                InputStream in = conversation.getInputStream();
                String head = readHead(in);
                if (head == null) {
                    continue;
                }
                byte[] body = new byte[0];
                String length = new Recorded(head, body, sni).header("Content-Length");
                if (length != null) {
                    body = in.readNBytes(Integer.parseInt(length));
                }
                Recorded recorded = new Recorded(head, body, sni);
                this.requests.add(recorded);
                OutputStream out = conversation.getOutputStream();
                this.handler.handle(recorded, out);
                out.flush();
            } catch (Exception e) {
                // The client gave up, refused the handshake, or the handler wrote past a closed socket: next.
            }
        }
    }

    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        byte[] end = {'\r', '\n', '\r', '\n'};
        while (matched < 4) {
            int b = in.read();
            if (b == -1) {
                return null;
            }
            head.write(b);
            matched = b == end[matched] ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        return head.toString(StandardCharsets.ISO_8859_1);
    }

    static void write(OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    /** A 200 with a Content-Length body. */
    static Handler ok(String body) {
        return (request, out) -> write(out, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body);
    }

    /** Echoes the request line, and the body when there is one, as a 200. */
    static Handler echo() {
        return (request, out) -> {
            String text = request.requestLine() + "\n" + new String(request.body(), StandardCharsets.UTF_8);
            write(out, "HTTP/1.1 200 OK\r\nContent-Length: " + text.getBytes(StandardCharsets.UTF_8).length
                    + "\r\nX-Method: " + request.requestLine().split(" ")[0].toLowerCase(Locale.ROOT) + "\r\n\r\n" + text);
        };
    }

    /** Writes {@code raw} exactly, then closes. */
    static Handler raw(String raw) {
        return (request, out) -> write(out, raw);
    }

    /** Writes {@code raw} exactly, then closes. */
    static Handler raw(byte[] raw) {
        return (request, out) -> {
            out.write(raw);
            out.flush();
        };
    }

    @Override
    public void close() throws Exception {
        this.server.close();
        this.thread.join(10_000);
    }
}
