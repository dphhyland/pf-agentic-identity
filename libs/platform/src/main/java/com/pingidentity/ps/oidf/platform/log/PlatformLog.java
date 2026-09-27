/*
 * How platform code writes a log line, wherever its copy was loaded.
 */
package com.pingidentity.ps.oidf.platform.log;

/**
 * A logger for platform code: commons-logging when the loader platform sits in can see it, and
 * {@link System.Logger} when it cannot.
 *
 * <p>commons-logging first, because in PingFederate 13.1.3 it is the route to server.log at the right level:
 * {@code server/default/lib} ships {@code commons-logging.jar} beside {@code log4j-jcl.jar}, and every loader
 * this code runs in (the webapp's {@code WEB-INF/lib}, the engine's {@code server/default/deploy}, a plugin's
 * own loader) delegates to that directory. {@code java.util.logging} is not routed there - {@code log4j-jul.jar}
 * is present but {@code run.sh} sets no {@code java.util.logging.manager} - so its lines reach server.log as
 * {@code ERROR [SystemErr]} whatever their level (F-0075, seen on the rig 2026-09-27). {@link System.Logger}
 * with no provider installed is {@code java.util.logging}, so it is only the fallback: for a standalone
 * program that has no commons-logging, so that the jar needs nothing but the JDK to load.
 *
 * <p>The choice is made once per loaded copy of this class, against the loader that loaded it, so a plugin
 * that shades and relocates platform decides for its own loader. commons-logging is never shaded: it is
 * {@code provided}, and a relocated copy would bypass PingFederate's log4j bridge.
 */
public final class PlatformLog {

    /** The class whose presence decides the route. */
    static final String COMMONS_LOGGING = "org.apache.commons.logging.LogFactory";

    private static final boolean COMMONS = commonsLoggingVisible(PlatformLog.class.getClassLoader());

    /** The four levels platform code logs at. */
    enum Level { DEBUG, INFO, WARN, ERROR }

    /** Where a line goes. */
    interface Sink {
        boolean isDebugEnabled();

        void log(Level level, String message, Throwable thrown);
    }

    private final Sink sink;

    private PlatformLog(Sink sink) {
        this.sink = sink;
    }

    /** The logger for a class, named as the class is. */
    public static PlatformLog get(Class<?> owner) {
        return of(owner.getName(), COMMONS);
    }

    /** The logger for a name, through commons-logging or through {@link System.Logger}. */
    static PlatformLog of(String name, boolean commons) {
        return new PlatformLog(commons ? CommonsLoggingSink.of(name) : new JdkSink(name));
    }

    /**
     * Whether a loader can see commons-logging. The class is looked up without being initialised, so asking
     * costs no logging set-up; a loader that fails to link it is treated as one that cannot see it.
     */
    static boolean commonsLoggingVisible(ClassLoader loader) {
        try {
            Class.forName(COMMONS_LOGGING, false, loader);
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /** Whether commons-logging carries this copy's lines. */
    public static boolean viaCommonsLogging() {
        return COMMONS;
    }

    public boolean isDebugEnabled() {
        return this.sink.isDebugEnabled();
    }

    public void debug(String message) {
        this.sink.log(Level.DEBUG, message, null);
    }

    public void info(String message) {
        this.sink.log(Level.INFO, message, null);
    }

    public void warn(String message) {
        this.sink.log(Level.WARN, message, null);
    }

    public void warn(String message, Throwable thrown) {
        this.sink.log(Level.WARN, message, thrown);
    }

    public void error(String message, Throwable thrown) {
        this.sink.log(Level.ERROR, message, thrown);
    }

    /** The fallback: {@link System.Logger}, which is {@code java.util.logging} unless a provider is installed. */
    static final class JdkSink implements Sink {
        private final System.Logger logger;

        JdkSink(String name) {
            this.logger = System.getLogger(name);
        }

        @Override
        public boolean isDebugEnabled() {
            return this.logger.isLoggable(System.Logger.Level.DEBUG);
        }

        @Override
        public void log(Level level, String message, Throwable thrown) {
            System.Logger.Level jdk = switch (level) {
                case DEBUG -> System.Logger.Level.DEBUG;
                case INFO -> System.Logger.Level.INFO;
                case WARN -> System.Logger.Level.WARNING;
                case ERROR -> System.Logger.Level.ERROR;
            };
            if (thrown == null) {
                this.logger.log(jdk, message);
            } else {
                this.logger.log(jdk, message, thrown);
            }
        }
    }
}
