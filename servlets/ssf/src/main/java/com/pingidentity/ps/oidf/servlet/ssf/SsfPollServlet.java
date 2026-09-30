/*
 * SSF poll-delivery endpoint (RFC 8936).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Poll-based SET delivery per RFC 8936. A poll stream's transmitter-assigned URL is
 * {@code <issuer>/ssf/poll?stream_id=<id>}; the receiver POSTs the RFC 8936 request body
 * ({@code maxEvents}, {@code returnImmediately}, {@code ack}) there. The response is
 * {@code {"sets": {jti: <compact JWS>, …}, "moreAvailable": <bool>}}; acked jtis are deleted before the next
 * batch is returned. Authenticated with the same receiver bearer token as the management API, and answerable
 * only to the client that created the stream: anyone else's poll is a 404, and acknowledges nothing.
 *
 * <p>From 0.6.0 (plan item H-SSF-2) {@code maxEvents} is capped, {@code setErrs} is recorded, a stream that is not
 * enabled returns nothing ({@link StreamManagementService#poll(String, StreamManagementService.PollRequest, AuthContext)}),
 * and a poll whose {@code returnImmediately} is not {@code true} is a long poll. RFC 8936 §2.2: "The default value is
 * "false", which indicates the request is to be treated as an HTTP long poll". With nothing to return it is held
 * off the request thread ({@link LongPolls}) for up to {@code OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS}, and answered
 * when a SET arrives or the wait runs out. That needs the request in async mode, which every filter in front of this
 * servlet must allow; where one does not - PingFederate's own runtime filters declare no {@code async-supported} -
 * the poll is answered at once, as a wait of 0 would answer it, and a line in the log says so once.
 */
@WebServlet(urlPatterns = {"/ssf/poll"}, asyncSupported = true)
public class SsfPollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfPollServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        SsfHttp.bootstrap(config); // fail-soft: unconfigured SSF is disabled, not fatal
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (SsfHttp.gate(resp)) {
            return; // the transmitter is starting, failed, refused (503) or off (404)
        }
        SsfConfiguration cfg = SsfSupport.configuration();
        AuthContext auth = SsfHttp.authorize(req, resp, cfg);
        if (auth == null) {
            return; // 401/403/503 already written
        }
        handle(req, resp, SsfSupport.streamService(), auth);
    }

    /** Whether the log has said long polling is unavailable in this chain; said once. */
    private static volatile boolean syncChainLogged;

    /** Everything after authentication, against a given service - the seam the servlet is tested through. */
    static void handle(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc, AuthContext auth)
            throws IOException {
        String streamId = req.getParameter("stream_id");
        if (streamId == null || streamId.isBlank()) {
            SsfHttp.writeError(resp, 400, "invalid_request", "missing required parameter: stream_id");
            return;
        }
        try {
            Map<String, Object> body = SsfHttp.readBody(req);
            List<String> acks = parseStringList(body.get("ack"));
            Integer maxEvents = parseInt(body.get("maxEvents"));
            boolean returnImmediately = Boolean.TRUE.equals(body.get("returnImmediately"));
            StreamManagementService.PollRequest request = new StreamManagementService.PollRequest(acks,
                    parseSetErrs(body.get("setErrs")), maxEvents, returnImmediately);
            StreamManagementService.Polled polled = svc.poll(streamId, request, auth);
            Duration wait = polled.hold();
            if (returnImmediately || wait.isZero() || !asyncAvailable(req)) {
                SsfHttp.writeJson(resp, 200, polled.body());
                return;
            }
            hold(req, streamId, new StreamManagementService.PollRequest(List.of(), Map.of(), maxEvents, false), svc, auth,
                    wait, polled.body());
        } catch (StreamManagementService.NotFoundException e) {
            SsfHttp.writeError(resp, 404, "not_found", e.getMessage());
        } catch (IllegalArgumentException e) {
            SsfHttp.writeError(resp, 400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error((Object) "SSF poll error", e);
            SsfHttp.writeError(resp, 500, "server_error", e.getMessage());
        }
    }

    /** Whether this request can go async; said once in the log when it cannot. */
    private static boolean asyncAvailable(HttpServletRequest req) {
        if (req.isAsyncSupported()) {
            return true;
        }
        if (!syncChainLogged) {
            syncChainLogged = true;
            log.info((Object) ("SSF long polling is unavailable here: a filter in front of " + req.getRequestURI()
                    + " does not support async requests, so a poll is answered at once, as with "
                    + "OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS=0"));
        }
        return false;
    }

    /**
     * Holds the request in async mode until {@link LongPolls} answers it: a SET for the stream, the wait, or the
     * container's own timeout (the wait and five seconds), whichever is first. The answer repeats the poll without the
     * acknowledgements and errors, which the first poll has already recorded.
     */
    private static void hold(HttpServletRequest req, String streamId, StreamManagementService.PollRequest again,
            StreamManagementService svc, AuthContext auth, Duration wait, Map<String, Object> empty) throws IOException {
        AsyncContext async = req.startAsync();
        async.setTimeout(wait.plusSeconds(5).toMillis());
        Optional<Runnable> held = LongPolls.hold(wait, () -> svc.hasPending(streamId),
                () -> svc.poll(streamId, again, auth).body(), body -> answer(async, body), empty);
        if (held.isEmpty()) {
            answer(async, empty);
            return;
        }
        async.addListener(new AsyncListener() {
            @Override
            public void onTimeout(AsyncEvent event) {
                held.get().run();
            }

            @Override
            public void onError(AsyncEvent event) {
                held.get().run();
            }

            @Override
            public void onComplete(AsyncEvent event) {
                // answered
            }

            @Override
            public void onStartAsync(AsyncEvent event) {
                // not restarted
            }
        });
    }

    /** Writes a held poll's answer and completes it; a client that has gone away is only logged. */
    static void answer(AsyncContext async, Map<String, Object> body) {
        try {
            SsfHttp.writeJson((HttpServletResponse) async.getResponse(), 200, body);
        } catch (IOException | RuntimeException e) {
            log.debug((Object) ("SSF long poll answer not delivered: " + e));
        } finally {
            async.complete();
        }
    }

    /**
     * RFC 8936 §2.2's {@code setErrs}: an object whose members are {@code jti}s, each an object with {@code err} and
     * {@code description}. Anything else is a 400 (§2.5.1: "the service provider SHALL respond to an invalid poll
     * request with an HTTP status code of 400").
     */
    @SuppressWarnings("unchecked")
    static Map<String, Map<String, Object>> parseSetErrs(Object raw) {
        LinkedHashMap<String, Map<String, Object>> out = new LinkedHashMap<>();
        if (raw == null) {
            return out;
        }
        if (!(raw instanceof Map)) {
            throw new IllegalArgumentException("setErrs is not a JSON object");
        }
        for (Map.Entry<String, Object> e : ((Map<String, Object>) raw).entrySet()) {
            if (!(e.getValue() instanceof Map)) {
                throw new IllegalArgumentException("setErrs member " + e.getKey() + " is not an object with err and description");
            }
            out.put(e.getKey(), (Map<String, Object>) e.getValue());
        }
        return out;
    }

    private static List<String> parseStringList(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof Iterable) {
            for (Object o : (Iterable<?>) raw) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
        }
        return out;
    }

    private static Integer parseInt(Object raw) {
        if (raw instanceof Number) {
            return ((Number) raw).intValue();
        }
        if (raw instanceof String && !((String) raw).isBlank()) {
            try {
                return Integer.valueOf(((String) raw).trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
