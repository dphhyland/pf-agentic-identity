/*
 * The listener marks, audits and shuts down only the copy of platform its own war loaded, and only once.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import org.junit.jupiter.api.Test;

class LifecycleListenerTest {

    /** What the fake context was asked to do. */
    static final class Container {
        final List<String> added = new ArrayList<>();
        Servlet servlet;
        Integer loadOnStartup;
        /** What addServlet does: "add", "null", "state" (IllegalStateException) or "unsupported". */
        String onAdd = "add";
    }

    private static ServletContext context(String path, String name, ClassLoader loader, Container container) {
        return (ServletContext) Proxy.newProxyInstance(ServletContext.class.getClassLoader(), new Class<?>[] {ServletContext.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getContextPath" -> path;
                    case "getServletContextName" -> name;
                    case "getClassLoader" -> loader;
                    case "addServlet" -> add(container, (String) args[0], (Servlet) args[1]);
                    case "toString" -> "context " + path;
                    default -> null;
                });
    }

    private static ServletRegistration.Dynamic add(Container container, String name, Servlet servlet) {
        switch (container.onAdd) {
            case "null":
                return null;
            case "state":
                throw new IllegalStateException("the context has started");
            case "unsupported":
                throw new UnsupportedOperationException("a listener added programmatically");
            default:
                container.added.add(name);
                container.servlet = servlet;
                return (ServletRegistration.Dynamic) Proxy.newProxyInstance(ServletRegistration.class.getClassLoader(),
                        new Class<?>[] {ServletRegistration.Dynamic.class}, (p, m, args) -> {
                            if (m.getName().equals("setLoadOnStartup")) {
                                container.loadOnStartup = (Integer) args[0];
                            }
                            return null;
                        });
        }
    }

    private static ServletConfig config(ServletContext context) {
        return (ServletConfig) Proxy.newProxyInstance(ServletConfig.class.getClassLoader(), new Class<?>[] {ServletConfig.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getServletContext" -> context;
                    case "getServletName" -> LifecycleListener.AUDIT_SERVLET;
                    default -> null;
                });
    }

    /**
     * A copy of platform and platform-pf of its own - as the webapp's WEB-INF/lib and the engine's server/default/deploy
     * each are - over a parent that shares only the JDK and the servlet API, which the container supplies to both.
     */
    private static URLClassLoader copy() {
        URL platform = Lifecycle.class.getProtectionDomain().getCodeSource().getLocation();
        URL platformPf = LifecycleListener.class.getProtectionDomain().getCodeSource().getLocation();
        ClassLoader test = LifecycleListenerTest.class.getClassLoader();
        ClassLoader container = new ClassLoader(ClassLoader.getPlatformClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.startsWith("jakarta.servlet.")) {
                    return test.loadClass(name);
                }
                throw new ClassNotFoundException(name);
            }
        };
        return new URLClassLoader(new URL[] {platform, platformPf}, container);
    }

    private static Object lifecycle(ClassLoader loader) throws Exception {
        return loader.loadClass(Lifecycle.class.getName()).getMethod("current").invoke(null);
    }

    private static String role(ClassLoader loader) throws Exception {
        Object lifecycle = lifecycle(loader);
        return lifecycle.getClass().getMethod("loaderRole").invoke(lifecycle).toString();
    }

    private static boolean shutDown(ClassLoader loader) throws Exception {
        Object lifecycle = lifecycle(loader);
        return (Boolean) lifecycle.getClass().getMethod("isShutDown").invoke(lifecycle);
    }

    @SuppressWarnings("unchecked")
    private static Optional<ObjectName> mxBean(ClassLoader loader) throws Exception {
        return (Optional<ObjectName>) loader.loadClass("com.pingidentity.ps.oidf.platform.metrics.Metrics").getMethod("registerMXBean")
                .invoke(null);
    }

    private static ServletContextListener listener(ClassLoader loader) throws Exception {
        return (ServletContextListener) loader.loadClass(LifecycleListener.class.getName()).getConstructor().newInstance();
    }

    @SuppressWarnings("unchecked")
    private static Optional<String> auditAgain(Object listener, String war) throws Exception {
        Method audit = listener.getClass().getDeclaredMethod("audit", String.class);
        audit.setAccessible(true);
        return (Optional<String>) audit.invoke(listener, war);
    }

    @Test
    void theWebappsCopyIsMarkedAuditedOnceAfterTheOtherInitsAndShutDownWhileTheEnginesIsLeftAlone() throws Exception {
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        try (URLClassLoader webapp = copy(); URLClassLoader engine = copy()) {
            Container container = new Container();
            ServletContext context = context("", "pf-runtime", webapp, container);
            ServletContextListener listener = listener(webapp);
            listener.contextInitialized(new ServletContextEvent(context));

            assertEquals("WEBAPP", role(webapp));
            assertEquals("UNKNOWN", role(engine), "the engine's copy gets no callback and stays unmarked");
            ObjectName name = mxBean(webapp).orElseThrow();
            assertTrue(server.isRegistered(name), "the webapp's MXBean is registered at contextInitialized");
            assertTrue(name.toString().contains(webapp.getURLs()[0].toString()), name + " names where this copy came from");
            assertEquals(List.of(LifecycleListener.AUDIT_SERVLET), container.added);
            assertEquals(Integer.MAX_VALUE, container.loadOnStartup, "initialised after every other load-on-startup servlet");

            container.servlet.init(config(context));
            assertEquals(Optional.empty(), auditAgain(listener, "/ (pf-runtime)"), "the audit servlet's init has run it");
            container.servlet.init(config(context));

            listener.contextDestroyed(new ServletContextEvent(context));
            assertTrue(shutDown(webapp));
            assertFalse(server.isRegistered(name), "the MXBean went with the webapp's lifecycle");
            assertFalse(shutDown(engine), "nothing of the engine's copy was closed");
            listener.contextDestroyed(new ServletContextEvent(context));
            assertTrue(shutDown(webapp), "a second destroy finds nothing to close");
        }
    }

    @Test
    void aListenerWhoseCopyOfPlatformTheWarDidNotLoadLeavesThatCopyAlone() throws Exception {
        try (URLClassLoader webapp = copy(); URLClassLoader engine = copy()) {
            Container container = new Container();
            // A war that asked its parent first: the listener it runs is the engine's copy.
            ServletContext context = context("/gm-api", "Grant Management API", webapp, container);
            ServletContextListener enginesListener = listener(engine);
            enginesListener.contextInitialized(new ServletContextEvent(context));
            enginesListener.contextDestroyed(new ServletContextEvent(context));
            assertEquals("UNKNOWN", role(engine));
            assertFalse(shutDown(engine), "the engine's copy is never shut down by a war");
            assertEquals(List.of(), container.added, "no audit servlet either");
            assertEquals("UNKNOWN", role(webapp));
        }
    }

    @Test
    void aDestroyWithNothingRegisteredSaysSo() throws Exception {
        try (URLClassLoader webapp = copy()) {
            ServletContext context = context("", null, webapp, new Container());
            listener(webapp).contextDestroyed(new ServletContextEvent(context));
            assertTrue(shutDown(webapp));
        }
    }

    @Test
    void whenTheContainerWillNotAddTheServletTheAuditRunsAtOnce() {
        for (String onAdd : List.of("null", "state", "unsupported")) {
            Container container = new Container();
            container.onAdd = onAdd;
            LifecycleListener listener = new LifecycleListener(Map.of("OIDF_ACCEPTED_RISKS", "pkce-off,unheard-of")::get,
                    () -> LocalDate.of(2026, 9, 28));
            ServletContext context = context("/oidf", "oidf", LifecycleListener.class.getClassLoader(), container);
            assertFalse(listener.deferAudit(context, "/oidf (oidf)"), onAdd);
            Optional<String> banner = listener.audit("/oidf (oidf)");
            assertTrue(banner.orElseThrow().contains("  risk refusals:  1, each logged at WARN"), banner.toString());
            assertTrue(banner.orElseThrow().contains("  accepted risks: pkce-off (no expiry)"), banner.toString());
            assertEquals(Optional.empty(), listener.audit("/oidf (oidf)"), "once per listener");
        }
    }

    @Test
    void contextInitializedAuditsAtOnceWhenTheServletCannotBeAdded() {
        Container container = new Container();
        container.onAdd = "null";
        LifecycleListener listener = new LifecycleListener();
        listener.contextInitialized(new ServletContextEvent(context("/oidf", "oidf", LifecycleListener.class.getClassLoader(), container)));
        assertEquals(Lifecycle.LoaderRole.WEBAPP, Lifecycle.current().loaderRole());
        assertEquals(Optional.empty(), listener.audit("/oidf (oidf)"), "contextInitialized already audited");
    }

    @Test
    void theWarIsNamedByItsPathAndDisplayName() {
        Container c = new Container();
        assertEquals("/", LifecycleListener.warOf(context("", null, null, c)));
        assertEquals("/", LifecycleListener.warOf(context(null, " ", null, c)));
        assertEquals("/gm-api (Grant Management API)", LifecycleListener.warOf(context("/gm-api", "Grant Management API", null, c)));
        assertEquals("/x (a?b)", LifecycleListener.warOf(context("/x", "a\nb", null, c)));
    }

    @Test
    void aCopyWithNoLocationSaysSo() throws Exception {
        assertEquals("a location its loader does not report", LifecycleListener.where(null));
        assertEquals("a location its loader does not report", LifecycleListener.where(new CodeSource(null, (Certificate[]) null)));
        assertEquals("file:/a.jar", LifecycleListener.where(new CodeSource(new URL("file:/a.jar"), (Certificate[]) null)));
    }

    @Test
    void theAuditServletAnswersNothingButA404() throws Exception {
        List<Integer> errors = new ArrayList<>();
        HttpServletResponse http = (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class}, (proxy, m, args) -> {
                    if (m.getName().equals("sendError")) {
                        errors.add((Integer) args[0]);
                    }
                    return null;
                });
        ServletResponse plain = (ServletResponse) Proxy.newProxyInstance(ServletResponse.class.getClassLoader(),
                new Class<?>[] {ServletResponse.class}, (proxy, m, args) -> null);
        StartupAuditServlet servlet = new StartupAuditServlet(() -> { });
        servlet.service(null, http);
        servlet.service(null, plain);
        assertEquals(List.of(404), errors);
        assertNull(servlet.getServletConfig());
    }
}
