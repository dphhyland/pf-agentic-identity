/*
 * PingFederate's own discovery documents, read in-process.
 */
package com.pingidentity.ps.oidf.pf;

import com.pingidentity.ps.oidf.federation.ProviderMetadata;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.sourceid.openid.connect.handlers.ProviderConfigurationInfoHandler;

/**
 * What PingFederate itself serves at {@code /.well-known/openid-configuration} and {@code /.well-known/oauth-authorization-server},
 * for the federation Entity Configuration to start from - so the {@code openid_provider} metadata it publishes is the OP's
 * own, with every parameter OpenID Connect Discovery requires, rather than a sketch of it (OpenID Federation 1.0 §5.1.3).
 *
 * <p>Read in-process, from the handlers that render those documents: nothing leaves the server, and no certificate has to
 * name it. A request to the federation servlet reads them for its issuer when they are missing or five minutes old;
 * discovery changes only when an administrator changes PingFederate's configuration.
 *
 * <p>The handlers are PingFederate internals, not SDK. If one is missing or fails, the Entity Configuration falls back to
 * what the federation module derives for itself, and a warning says so, once.
 */
public final class PfProviderMetadata implements ProviderMetadata {
    private static final Log LOGGER = LogFactory.getLog(PfProviderMetadata.class);
    /** How long a discovery document is used before it is read again. */
    static final long REFRESH_SECONDS = 300L;
    private static final List<String> TYPES = List.of("openid_provider", "oauth_authorization_server");

    /** Renders one discovery document for a request. */
    @FunctionalInterface
    public interface Reader {
        String read(String entityType, HttpServletRequest request) throws Exception;
    }

    /** What a handler does with a request: writes its document to the response. */
    @FunctionalInterface
    interface Handler {
        void process(HttpServletRequest request, HttpServletResponse response) throws Exception;
    }

    private record Snapshot(Map<String, Object> metadata, long at) {
    }

    private final Reader reader;
    private final Clock clock;
    private final Map<String, Snapshot> documents = new ConcurrentHashMap<>();
    private final AtomicBoolean warned = new AtomicBoolean();

    /** PingFederate's own handlers. */
    public PfProviderMetadata() {
        this(PfProviderMetadata::render, Clock.systemUTC());
    }

    /** Test seam: documents from {@code reader} instead of PingFederate's handlers. */
    public PfProviderMetadata(Reader reader, Clock clock) {
        this.reader = Objects.requireNonNull(reader, "reader");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Reads PingFederate's discovery documents for {@code issuer} when they are missing or stale. */
    public void refresh(String issuer, HttpServletRequest request) {
        long now = this.clock.instant().getEpochSecond();
        for (String type : TYPES) {
            String key = type + " " + issuer;
            Snapshot kept = this.documents.get(key);
            if (kept != null && now - kept.at() < REFRESH_SECONDS) {
                continue;
            }
            Map<String, Object> metadata;
            try {
                metadata = JsonUtil.parseJson(this.reader.read(type, request));
            } catch (Exception | LinkageError e) {
                if (this.warned.compareAndSet(false, true)) {
                    LOGGER.warn("PingFederate's " + type + " discovery document could not be read, so the federation Entity"
                            + " Configuration carries only what this module derives for itself: " + e);
                }
                // Not read again for a while either way; a document read before is better than none.
                metadata = kept == null ? Map.of() : kept.metadata();
            }
            this.documents.put(key, new Snapshot(metadata, now));
        }
    }

    @Override
    public Map<String, Object> of(String entityType, String issuer) {
        Snapshot kept = this.documents.get(entityType + " " + issuer);
        return kept == null ? Map.of() : kept.metadata();
    }

    /** PingFederate's handler for {@code entityType}'s document, run on {@code request}. */
    private static String render(String entityType, HttpServletRequest request) throws Exception {
        ProviderConfigurationInfoHandler handler = "openid_provider".equals(entityType)
                ? ProviderConfigurationInfoHandler.createOpenIDConnectProviderConfigurationInfoHandler()
                : ProviderConfigurationInfoHandler.createOAuthProviderConfigurationInfoHandler();
        return capture(handler::process, request);
    }

    /**
     * What {@code handler} writes for a GET of {@code request} carrying no parameters - the federation request's own
     * {@code sub} or {@code trust_anchor} mean nothing to a discovery handler - into a response that goes nowhere.
     */
    static String capture(Handler handler, HttpServletRequest request) throws Exception {
        StringWriter text = new StringWriter();
        PrintWriter writer = new PrintWriter(text);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ServletOutputStream stream = new ServletOutputStream() {
            @Override
            public void write(int b) {
                bytes.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }
        };
        // Everything but the body is dropped: headers, status, cookies. A method this doesn't know answers as an empty
        // response would, so a handler that asks something new of its response still renders.
        HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(PfProviderMetadata.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getWriter" -> writer;
                    case "getOutputStream" -> stream;
                    case "getCharacterEncoding" -> "UTF-8";
                    case "getStatus" -> 200;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "discovery capture";
                    default -> emptyAnswer(method.getReturnType());
                });
        handler.process(new ParameterFree(request), response);
        writer.flush();
        return text.toString() + bytes.toString(StandardCharsets.UTF_8);
    }

    /** What an empty response answers: false, zero, or nothing. */
    static Object emptyAnswer(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        return type == long.class ? 0L : null;
    }

    /** {@code request} as a GET with no parameters. */
    private static final class ParameterFree extends HttpServletRequestWrapper {
        private ParameterFree(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getMethod() {
            return "GET";
        }

        @Override
        public String getParameter(String name) {
            return null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return Map.of();
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.emptyEnumeration();
        }

        @Override
        public String[] getParameterValues(String name) {
            return null;
        }

        @Override
        public String getQueryString() {
            return null;
        }
    }
}
