/*
 * Registers one copy's MXBean under a name no other copy has, once, and unregisters it at shutdown.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.security.CodeSource;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.JMException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.StandardMBean;

/**
 * The MXBean of one loaded copy of platform. Registered at most once, lazily; unregistered by the close it hands to
 * the copy's lifecycle (platform.lifecycle), which the webapp's lifecycle listener runs at undeploy (F-2). Nothing
 * runs the engine's copy's lifecycle, so its MXBean stays until the JVM stops (see the README).
 *
 * <p>The name's {@code copy} key is the copy's package - which differs for each plugin's relocated copy - and where
 * it was loaded from - which differs between the webapp's {@code WEB-INF/lib}, {@code server/default/deploy} and
 * another war's {@code WEB-INF/lib}. Two copies loaded from the same place (two loaders over one jar) would still
 * clash, so a name that is taken is retried with {@code #2}, {@code #3} and so on: neither registration fails the
 * other. A registration that fails for any other reason is logged once and not retried; the metrics work without
 * it.
 */
final class MXBeanRegistration {

    /** The JMX domain every copy registers in. */
    static final String DOMAIN = "com.pingidentity.ps.oidf";

    /** How many names are tried before giving up. */
    static final int MAX_ATTEMPTS = 16;

    private static final PlatformLog LOG = PlatformLog.get(MXBeanRegistration.class);

    private enum State { NONE, REGISTERED, CLOSED, FAILED }

    private final Supplier<MBeanServer> server;
    private final MetricsMXBean bean;
    private final String copy;
    private final BooleanSupplier shutDown;
    private final BiConsumer<String, AutoCloseable> atShutdown;
    private State state = State.NONE;
    private ObjectName name;

    /**
     * @param server     the MBean server, asked for only when the MXBean is first registered
     * @param bean       what it shows
     * @param copy       which copy this is ({@link #copyOf})
     * @param shutDown   whether this copy's lifecycle has already shut down, in which case nothing is registered
     * @param atShutdown hands the lifecycle the close that unregisters it
     */
    MXBeanRegistration(Supplier<MBeanServer> server, MetricsMXBean bean, String copy, BooleanSupplier shutDown,
            BiConsumer<String, AutoCloseable> atShutdown) {
        this.server = server;
        this.bean = bean;
        this.copy = copy;
        this.shutDown = shutDown;
        this.atShutdown = atShutdown;
    }

    /** Registers the MXBean if it never has been; the name it is registered under, or empty when it is not. */
    Optional<ObjectName> ensure() {
        MBeanServer s;
        ObjectName registered;
        synchronized (this) {
            if (this.state == State.REGISTERED) {
                return Optional.of(this.name);
            }
            if (this.state != State.NONE) {
                return Optional.empty();
            }
            if (this.shutDown.getAsBoolean()) {
                this.state = State.CLOSED;
                return Optional.empty();
            }
            try {
                s = this.server.get();
                registered = register(s, new StandardMBean(this.bean, MetricsMXBean.class, true), this.copy);
            } catch (JMException | RuntimeException | LinkageError e) {
                this.state = State.FAILED;
                LOG.warn("Metrics: the MXBean for " + this.copy + " could not be registered; the metrics still count", e);
                return Optional.empty();
            }
            if (registered == null) {
                this.state = State.FAILED;
                LOG.warn("Metrics: the MXBean for " + this.copy + " was not registered: " + MAX_ATTEMPTS + " names were taken");
                return Optional.empty();
            }
            this.state = State.REGISTERED;
            this.name = registered;
        }
        LOG.info("Metrics: registered " + registered);
        // Outside the lock: a lifecycle already shut down closes at once, on another thread, which takes it.
        this.atShutdown.accept("metrics MXBean " + registered, () -> unregister(s, registered));
        return Optional.of(registered);
    }

    /** Unregisters the MXBean; this copy registers none again. */
    synchronized void unregister(MBeanServer s, ObjectName n) throws JMException {
        this.state = State.CLOSED;
        this.name = null;
        try {
            s.unregisterMBean(n);
        } catch (InstanceNotFoundException e) {
            LOG.info("Metrics: " + n + " was already unregistered");
            return;
        }
        LOG.info("Metrics: unregistered " + n);
    }

    /** Registers under the first free name; {@code null} when all {@value #MAX_ATTEMPTS} are taken. */
    static ObjectName register(MBeanServer s, Object bean, String copy) throws JMException {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            ObjectName n = objectName(copy, attempt);
            try {
                s.registerMBean(bean, n);
                return n;
            } catch (InstanceAlreadyExistsException e) {
                LOG.debug("Metrics: " + n + " is taken by another copy loaded from the same place");
            }
        }
        return null;
    }

    static ObjectName objectName(String copy, int attempt) throws MalformedObjectNameException {
        String value = attempt == 1 ? copy : copy + " #" + attempt;
        return new ObjectName(DOMAIN + ":type=Metrics,copy=" + ObjectName.quote(value));
    }

    /**
     * Which copy of platform this is: the package of its metrics classes - a plugin's relocated copy has its own -
     * and where they were loaded from, or, for a loader that does not say, the loader's class and identity.
     */
    static String copyOf(String packageName, CodeSource source, ClassLoader loader) {
        String from;
        if (source != null && source.getLocation() != null) {
            from = source.getLocation().toString();
        } else if (loader != null) {
            from = loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
        } else {
            from = "the bootstrap loader";
        }
        return packageName + " from " + from;
    }
}
