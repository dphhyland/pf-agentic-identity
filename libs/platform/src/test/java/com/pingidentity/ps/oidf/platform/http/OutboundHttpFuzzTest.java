package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.EnumSet;
import java.util.EnumMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * A randomised test of the response path, which faces federation peers and so is attacker-facing: well-formed
 * responses are mutated - bytes flipped, protocol tokens spliced in, ranges dropped, doubled or cut off - and some are
 * pure noise, and each is served to the client once. Whatever arrives, the client must return a response within the
 * cap or throw an {@link OutboundHttpException} with a reason a peer can cause, and must do it by the deadline: no
 * other exception, no hang, no body over the cap.
 *
 * <p>The seed is fixed so a failure repeats; {@code -Ds5a.fuzz.seed=N} and {@code -Ds5a.fuzz.cases=N} run others.
 */
class OutboundHttpFuzzTest {

    private static final long CAP = 4096;
    private static final Set<Reason> PEER_CAUSED = EnumSet.of(Reason.MALFORMED_RESPONSE, Reason.BODY_TOO_LARGE,
            Reason.HEADER_TIMEOUT, Reason.DEADLINE, Reason.IO);

    private static final String[] TEMPLATES = {
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\": true}\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
        "HTTP/1.0 404 Not Found\r\nServer: x\r\n\r\nclose-delimited body",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nETag: \"a\"\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\noops!",
    };

    private static final String[] TOKENS = {
        "\r\n", "\r", "\n", "\r\n\r\n", ":", " ", "\t", "\0", ";", ",", "chunked", "Content-Length: ",
        "Transfer-Encoding: ", "HTTP/1.1 ", "HTTP/2 ", "100 Continue\r\n\r\n", "0\r\n\r\n", "ffffffffffffffff",
        "-1", "+5", "99999999999999999999", "\u00ff\u00fe", "Content-Length: 5\r\nContent-Length: 6\r\n",
        "Transfer-Encoding: gzip\r\n", "7fffffff\r\n", " \r\n folded", "x".repeat(9000),
    };

    @Test
    void anyResponseEndsInAResponseOrAPeerCausedRefusalByTheDeadline() throws Exception {
        long seed = Long.getLong("s5a.fuzz.seed", 20260928L);
        int cases = Integer.getInteger("s5a.fuzz.cases", 600);
        Random random = new Random(seed);
        AddressPolicy local = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build();
        OutboundHttp http = OutboundHttp.builder(local).maxBodyBytes(CAP).headerTimeout(Duration.ofMillis(400)).build();
        Map<Reason, Integer> reasons = new EnumMap<>(Reason.class);
        int responses = 0;
        try (TestServer server = TestServer.plain(TestServer.ok(""))) {
            String url = "http://127.0.0.1:" + server.port() + "/fuzz";
            for (int i = 0; i < cases; i++) {
                byte[] payload = payload(random);
                boolean holdOpen = random.nextInt(40) == 0;
                server.handler((request, out) -> {
                    out.write(payload);
                    out.flush();
                    if (holdOpen) {
                        Thread.sleep(700);
                    }
                });
                long totalMillis = 600;
                long start = System.nanoTime();
                try {
                    OutboundResponse response = http.get(url, "*/*", Deadline.after(Duration.ofMillis(totalMillis)));
                    responses++;
                    assertTrue(response.body().length <= CAP, () -> describe(seed, payload) + " body over the cap");
                    assertTrue(response.status() >= 200 && response.status() <= 599, () -> describe(seed, payload));
                } catch (OutboundHttpException e) {
                    assertTrue(PEER_CAUSED.contains(e.reason()), () -> describe(seed, payload) + " gave " + e.reason() + ": " + e);
                    reasons.merge(e.reason(), 1, Integer::sum);
                } catch (Throwable t) {
                    fail(describe(seed, payload) + " threw " + t, t);
                }
                long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
                assertTrue(elapsedMillis < totalMillis + 500, () -> describe(seed, payload) + " took " + elapsedMillis + " ms");
            }
        }
        // The corpus must reach both outcomes, or it is not testing the parser.
        assertTrue(responses > cases / 20, "only " + responses + " responses in " + cases + " cases");
        assertTrue(reasons.getOrDefault(Reason.MALFORMED_RESPONSE, 0) > cases / 20, reasons.toString());
    }

    private static byte[] payload(Random random) {
        if (random.nextInt(10) == 0) {
            byte[] noise = new byte[random.nextInt(300)];
            random.nextBytes(noise);
            return noise;
        }
        byte[] bytes = TEMPLATES[random.nextInt(TEMPLATES.length)].getBytes(StandardCharsets.ISO_8859_1);
        int mutations = random.nextInt(4);
        for (int m = 0; m < mutations && bytes.length > 0; m++) {
            bytes = mutate(random, bytes);
        }
        return bytes;
    }

    private static byte[] mutate(Random random, byte[] bytes) {
        int at = random.nextInt(bytes.length);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        switch (random.nextInt(6)) {
            case 0:
                bytes[at] = (byte) random.nextInt(256);
                return bytes;
            case 1:
                out.write(bytes, 0, at);
                out.writeBytes(TOKENS[random.nextInt(TOKENS.length)].getBytes(StandardCharsets.ISO_8859_1));
                out.write(bytes, at, bytes.length - at);
                return out.toByteArray();
            case 2:
                int drop = Math.min(bytes.length - at, 1 + random.nextInt(8));
                out.write(bytes, 0, at);
                out.write(bytes, at + drop, bytes.length - at - drop);
                return out.toByteArray();
            case 3:
                int length = Math.min(bytes.length - at, 1 + random.nextInt(20));
                out.write(bytes, 0, at + length);
                out.write(bytes, at, bytes.length - at);
                return out.toByteArray();
            case 4:
                out.write(bytes, 0, at);
                return out.toByteArray();
            default:
                out.write(bytes, 0, bytes.length);
                out.writeBytes("x".repeat(random.nextInt(2) == 0 ? 10 : 5000).getBytes(StandardCharsets.ISO_8859_1));
                return out.toByteArray();
        }
    }

    private static String describe(long seed, byte[] payload) {
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        return "seed " + seed + ", payload " + (text.length() > 200 ? text.substring(0, 200) + "..." : text)
                .replace("\r", "\\r").replace("\n", "\\n");
    }
}
