/*
 * S-9's per-surface table, driven over every surface the war maps: each @WebServlet class and each filter in
 * build/pingfederate/filters.xml, found rather than listed (the Phase 3 plan's risk 4).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Finds the surfaces and drives them. A surface is a class the war maps: annotated {@link WebServlet} in the code source
 * of an anchor class (its module's classes directory or jar), or named by a {@code <filter class>} in filters.xml. Each
 * is instantiated with its no-argument constructor and given its {@code init}, as the container does, and its part is
 * the one its gate reads: the {@link ComponentParts.Part} field it holds, or - for a surface that holds none - the part
 * {@link #SHARED} names. What its gate must do then follows from its component and whether it is a filter
 * ({@link #kind}), not from a list of classes.
 */
final class SurfaceMatrix {

    /** What a surface does while its component is disabled or failed (ComponentGate's table). */
    enum Kind { FEDERATION_ENDPOINT, OAUTH_ENDPOINT, AUTO_REGISTRATION, ATTESTATION, LISTED_CLIENTS, EMISSION }

    /** Every state a part can be put in; the first two serve. */
    static final List<ComponentState> STATES = List.of(ComponentState.READY, ComponentState.DEGRADED, ComponentState.DISABLED,
            ComponentState.STARTING, ComponentState.FAILED_CONFIG, ComponentState.FAILED_DEPENDENCY, ComponentState.REFUSED);

    /** Surfaces that hold no part of their own, and the part whose gate they share. */
    static final Map<String, String> SHARED = Map.of(
            "com.pingidentity.ps.oidf.servlet.ssf.SsfPollServlet", "SsfConfigurationServlet",
            "com.pingidentity.ps.oidf.servlet.ssf.SsfEventEmitServlet", "SsfConfigurationServlet",
            "com.pingidentity.ps.oidf.servlet.ssf.SsfStreamManagementServlet", "SsfConfigurationServlet",
            "com.pingidentity.ps.oidf.servlet.ssf.SsfScimSubjectServlet", "SsfConfigurationServlet",
            "com.pingidentity.ps.oidf.servlet.ssf.LogoutEventFilter", "SsfConfigurationServlet");

    /** Mapped classes that are not a component's surface, each with the reason. */
    static final Map<String, String> NOT_COMPONENTS = Map.of(
            "com.pingidentity.ps.oidf.platform.pf.health.HealthServlet",
            "health itself: it answers from every component's state, whatever those states are",
            "com.pingidentity.ps.oidf.servlet.clientregistration.RegisteredClientsServlet",
            "an operator route with its own switch (OIDF_REGISTERED_CLIENTS_ENABLED) and an init that never throws; not one of"
                    + " S-9's nine components",
            "com.pingidentity.ps.oidf.servlet.fapi1.FapiResourceServerFilter",
            "no component and nothing to configure: it echoes x-fapi-interaction-id and refuses a token in the query",
            "com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorDescriptionFilter",
            "no component and nothing to configure: it brings error_description inside RFC 6749's character set",
            "com.pingidentity.ps.oidf.servlet.oauth.AttestationMetadataFilter",
            "no component: it never refuses, and adds ATTESTATION_AUTH's metadata members to PingFederate's discovery documents"
                    + " only while that component's switch allows them");

    /** A mapped class, as the war maps it. */
    record Surface(Class<?> type, boolean filter, List<String> paths, int loadOnStartup) {
        String name() {
            return this.type.getName();
        }
    }

    private SurfaceMatrix() {
    }

    // ---- finding them ------------------------------------------------------------------------------------------

    /** The @WebServlet classes in each anchor's code source. */
    static List<Surface> servlets(Class<?>... anchors) throws Exception {
        List<Surface> out = new ArrayList<>();
        for (Class<?> anchor : anchors) {
            for (String name : classNames(anchor)) {
                Class<?> type;
                try {
                    type = Class.forName(name, false, anchor.getClassLoader());
                } catch (LinkageError | ClassNotFoundException e) {
                    continue;
                }
                WebServlet mapped = type.getAnnotation(WebServlet.class);
                if (mapped != null && out.stream().noneMatch(s -> s.type() == type)) {
                    List<String> paths = new ArrayList<>(List.of(mapped.urlPatterns()));
                    paths.addAll(List.of(mapped.value()));
                    out.add(new Surface(type, false, paths, mapped.loadOnStartup()));
                }
            }
        }
        return out;
    }

    private static List<String> classNames(Class<?> anchor) throws IOException, URISyntaxException {
        Path source = Path.of(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
        List<String> names = new ArrayList<>();
        if (Files.isDirectory(source)) {
            try (Stream<Path> files = Files.walk(source)) {
                files.filter(f -> f.toString().endsWith(".class")).forEach(f -> names.add(className(source.relativize(f).toString())));
            }
        } else {
            try (JarFile jar = new JarFile(source.toFile())) {
                for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();) {
                    String entry = e.nextElement().getName();
                    if (entry.endsWith(".class")) {
                        names.add(className(entry));
                    }
                }
            }
        }
        return names;
    }

    private static String className(String file) {
        return file.substring(0, file.length() - ".class".length()).replace('/', '.').replace('\\', '.');
    }

    /** The filters build/pingfederate/filters.xml registers, each with its url-patterns. */
    static List<Surface> filters(Path filtersXml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        NodeList declared = factory.newDocumentBuilder().parse(filtersXml.toFile()).getElementsByTagName("filter");
        List<Surface> out = new ArrayList<>();
        for (int i = 0; i < declared.getLength(); i++) {
            Element filter = (Element) declared.item(i);
            List<String> paths = new ArrayList<>();
            NodeList patterns = filter.getElementsByTagName("url-pattern");
            for (int j = 0; j < patterns.getLength(); j++) {
                paths.add(patterns.item(j).getTextContent().trim());
            }
            out.add(new Surface(Class.forName(filter.getAttribute("class")), true, paths, 0));
        }
        return out;
    }

    /** The repository's filters.xml, found from the module directory the tests run in. */
    static Path filtersXml() {
        for (Path dir = Path.of("").toAbsolutePath(); dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve("build/pingfederate/filters.xml");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new AssertionError("build/pingfederate/filters.xml not found above " + Path.of("").toAbsolutePath());
    }

    // ---- starting them -----------------------------------------------------------------------------------------

    /** Each surface, instantiated and initialised in the container's order: load-on-startup ones first, by their order. */
    static Map<Surface, Object> start(List<Surface> surfaces) throws Exception {
        List<Surface> ordered = new ArrayList<>(surfaces);
        ordered.sort(Comparator.comparingInt((Surface s) -> s.filter() ? -1 : s.loadOnStartup() < 0 ? Integer.MAX_VALUE : s.loadOnStartup()));
        Map<Surface, Object> out = new LinkedHashMap<>();
        for (Surface s : ordered) {
            Object instance = s.type().getDeclaredConstructor().newInstance();
            if (s.filter()) {
                FilterConfig config = mock(FilterConfig.class);
                when(config.getServletContext()).thenReturn(mock(ServletContext.class));
                when(config.getFilterName()).thenReturn(s.type().getSimpleName());
                ((Filter) instance).init(config);
            } else {
                ServletConfig config = mock(ServletConfig.class);
                when(config.getServletContext()).thenReturn(mock(ServletContext.class));
                when(config.getServletName()).thenReturn(s.type().getSimpleName());
                when(config.getInitParameterNames()).thenReturn(Collections.emptyEnumeration());
                ((HttpServlet) instance).init(config);
            }
            out.put(s, instance);
        }
        return out;
    }

    /** A part by its names. */
    record Named(String component, String part) {
    }

    /** The part a started surface's gate reads, or null when it has none. */
    static Named partOf(Surface s, Object instance) throws Exception {
        for (Class<?> c = s.type(); c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == ComponentParts.Part.class && !Modifier.isStatic(f.getModifiers())) {
                    f.setAccessible(true);
                    ComponentParts.Part part = (ComponentParts.Part) f.get(instance);
                    return part == null ? null : new Named(part.component(), part.part());
                }
            }
        }
        String shared = SHARED.get(s.name());
        if (shared == null) {
            return null;
        }
        return Startup.parts().parts().stream().filter(p -> p.part().equals(shared)).findFirst()
                .map(p -> new Named(p.component(), p.part())).orElse(null);
    }

    /** What a surface of {@code component} must do, by S-9's table. */
    static Kind kind(String component, boolean filter) {
        if (filter) {
            return switch (component) {
                case Startup.AUTO_REGISTRATION -> Kind.AUTO_REGISTRATION;
                case Startup.ATTESTATION_AUTH -> Kind.ATTESTATION;
                case Startup.FAPI -> Kind.LISTED_CLIENTS;
                case Startup.SSF -> Kind.EMISSION;
                default -> throw new AssertionError("a filter of " + component + " has no row in S-9's table: add one");
            };
        }
        return switch (component) {
            case Startup.FEDERATION, Startup.HOSTING, Startup.OPERATOR_API -> Kind.FEDERATION_ENDPOINT;
            case Startup.SSF, Startup.SSF_RECEIVER, Startup.ATTESTATION_ISSUER, Startup.ATTESTATION_AUTH -> Kind.OAUTH_ENDPOINT;
            default -> throw new AssertionError("a servlet of " + component + " has no row in S-9's table: add one");
        };
    }

    /** Every part of {@code component} but {@code part} made ready, so a sibling's state (a refusal) is not this row's. */
    static void siblingsReady(String component, String part) {
        for (com.pingidentity.ps.oidf.platform.health.PartStatus p : Startup.parts().parts()) {
            if (p.component().equals(component) && !p.part().equals(part)) {
                Startup.begin(component, p.part()).ready();
            }
        }
    }

    /** {@code component}'s part named {@code part}, registered again and put in {@code state}. */
    static void put(String component, String part, ComponentState state) {
        ComponentParts.Part p = Startup.begin(component, part);
        switch (state) {
            case READY -> p.ready();
            case DEGRADED -> p.degraded("the matrix");
            case DISABLED -> p.disabled();
            case FAILED_CONFIG -> p.failedConfig("the matrix");
            case FAILED_DEPENDENCY -> p.failedDependency("the matrix");
            case REFUSED -> p.refused("the matrix");
            default -> { }
        }
        if (p.status().state() != state) {
            throw new AssertionError(component + "/" + part + " would not move to " + state + ": it is " + p.status());
        }
    }

    // ---- driving them ------------------------------------------------------------------------------------------

    /** What a surface answered. */
    static final class Answer {
        int status = -1;
        int error = -1;
        boolean passed;
        Integer contentLength;
        final Map<String, String> headers = new LinkedHashMap<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletRequest request;
        FilterChain chain;
        HttpServletResponse response;
        Throwable thrown;

        String body() {
            return this.body.toString(StandardCharsets.UTF_8);
        }

        /** Whether the request was read at all, beyond the method and protocol the container's dispatch reads. */
        boolean readTheRequest() {
            return mockingDetails(this.request).getInvocations().stream().map(i -> i.getMethod().getName())
                    .anyMatch(m -> !m.equals("getMethod") && !m.equals("getProtocol") && !m.equals("getDispatcherType"));
        }

        @Override
        public String toString() {
            return "status=" + this.status + " error=" + this.error + " passed=" + this.passed + " body=" + this.body()
                    + (this.thrown == null ? "" : " thrown=" + this.thrown);
        }
    }

    /** A request to {@code path} with {@code method}, the parameters and headers given. */
    static HttpServletRequest request(String method, String path, Map<String, String> parameters, Map<String, String> headers) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getProtocol()).thenReturn("HTTP/1.1");
        when(request.getRequestURI()).thenReturn(path);
        when(request.getServletPath()).thenReturn(path);
        when(request.getContextPath()).thenReturn("");
        when(request.getParameter(anyString())).thenAnswer(i -> parameters.get((String) i.getArgument(0)));
        when(request.getHeader(anyString())).thenAnswer(i -> headers.get((String) i.getArgument(0)));
        when(request.getHeaders(anyString())).thenAnswer(i -> {
            String value = headers.get((String) i.getArgument(0));
            return value == null ? Collections.emptyEnumeration() : Collections.enumeration(List.of(value));
        });
        when(request.getParameterValues(anyString())).thenAnswer(i -> {
            String value = parameters.get((String) i.getArgument(0));
            return value == null ? null : new String[] {value};
        });
        return request;
    }

    /** Sends {@code request} to a servlet or through a filter, and records the answer. */
    static Answer drive(Object instance, HttpServletRequest request) throws Exception {
        Answer a = new Answer();
        a.request = request;
        HttpServletResponse response = mock(HttpServletResponse.class);
        a.response = response;
        doAnswer(i -> {
            a.status = i.getArgument(0);
            return null;
        }).when(response).setStatus(anyInt());
        doAnswer(i -> {
            a.error = i.getArgument(0);
            return null;
        }).when(response).sendError(anyInt());
        doAnswer(i -> {
            a.error = i.getArgument(0);
            return null;
        }).when(response).sendError(anyInt(), any());
        doAnswer(i -> {
            a.headers.put(i.getArgument(0), i.getArgument(1));
            return null;
        }).when(response).setHeader(anyString(), any());
        doAnswer(i -> {
            a.contentLength = i.getArgument(0);
            return null;
        }).when(response).setContentLength(anyInt());
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                a.body.write(b);
            }
        });
        when(response.getWriter()).thenReturn(new PrintWriter(a.body, true, StandardCharsets.UTF_8));
        FilterChain chain = mock(FilterChain.class);
        doAnswer(i -> {
            a.passed = true;
            return null;
        }).when(chain).doFilter(any(), any());
        a.chain = chain;
        try {
            if (instance instanceof Filter filter) {
                filter.doFilter(request, response, chain);
            } else {
                ((HttpServlet) instance).service(request, response);
            }
        } catch (Exception | Error e) {
            // A serving surface that is not configured in a unit test may fail past its gate: that is past the gate.
            a.thrown = e;
        }
        return a;
    }

    /** A compact JWS whose parts are the JSON given: nothing verifies it, and nothing here needs to. */
    static String jwt(String header, String claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString(claims.getBytes(StandardCharsets.UTF_8))
                + ".c2ln";
    }

    /**
     * The HTTP methods a servlet declares a {@code doX} handler for below HttpServlet (a servlet that dispatches in its
     * own {@code service} - PATCH, or every method - declares none of them for it). HEAD is GET without the body, and
     * HttpServlet answers it through a wrapper that keeps the body from this test, so GET stands for it.
     */
    static List<String> declaredMethods(Class<?> type) {
        List<String> out = new ArrayList<>();
        for (String method : List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")) {
            String handler = "do" + method.charAt(0) + method.substring(1).toLowerCase(java.util.Locale.ROOT);
            if (declares(type, handler)) {
                out.add(method);
            }
        }
        return out;
    }

    /** Whether a class below HttpServlet (and below RequestScopedServlet, which only wraps) declares {@code name}. */
    static boolean declares(Class<?> type, String name) {
        for (Class<?> c = type; c != null && c != HttpServlet.class; c = c.getSuperclass()) {
            if (c.getSimpleName().equals("RequestScopedServlet")) {
                continue;
            }
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(name) && m.getParameterCount() == 2 && m.getParameterTypes()[0] == HttpServletRequest.class) {
                    return true;
                }
            }
        }
        return false;
    }
}
