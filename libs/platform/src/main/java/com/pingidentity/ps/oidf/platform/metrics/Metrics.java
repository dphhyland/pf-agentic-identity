/*
 * This loader's metrics.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.Optional;
import java.util.function.DoubleSupplier;
import javax.management.ObjectName;

/**
 * Counters, timers and gauges for this loaded copy of platform, and its one MXBean.
 *
 * <pre>{@code
 * private static final Counter DECISIONS = Metrics.counter("oidf_attestation_decisions_total",
 *         "Client attestation decisions at the token endpoint", Label.oneOf("outcome", "accepted", "refused"));
 * ...
 * DECISIONS.inc("refused");
 * }</pre>
 *
 * <p>Statics are per loader (docs/development/classloaders.md), so the webapp's copy, the engine's copy, each
 * plugin's relocated copy and a separate war's copy each have their own registry and their own MXBean. The MXBean
 * is registered the first time a metric is, or when {@link #registerMXBean()} is called - F-2's lifecycle listener
 * calls it for the webapp - and unregistered through this copy's {@link Lifecycle}. The engine's copy has no
 * listener and no lifecycle shutdown, so its MXBean stays until the JVM stops; that is where the OGNL criteria
 * run, and their decisions have to stay visible.
 */
public final class Metrics {

    private static final MetricRegistry REGISTRY = new MetricRegistry(Metrics::registerMXBean);
    private static final MXBeanRegistration MXBEAN = new MXBeanRegistration(ManagementFactory::getPlatformMBeanServer,
            new MetricsView(REGISTRY, copy()), copy(), () -> Lifecycle.current().isShutDown(),
            (name, close) -> Lifecycle.current().register(name, close));

    private Metrics() {
    }

    private static String copy() {
        return MXBeanRegistration.copyOf(Metrics.class.getPackageName(), Metrics.class.getProtectionDomain().getCodeSource(),
                Metrics.class.getClassLoader());
    }

    /** See {@link MetricRegistry#counter}. */
    public static Counter counter(String name, String help, Label... labels) {
        return REGISTRY.counter(name, help, labels);
    }

    /** See {@link MetricRegistry#timer}. */
    public static Timer timer(String name, String help, Label... labels) {
        return REGISTRY.timer(name, help, labels);
    }

    /** See {@link MetricRegistry#gauge(String, String, Label...)}. */
    public static Gauge gauge(String name, String help, Label... labels) {
        return REGISTRY.gauge(name, help, labels);
    }

    /** See {@link MetricRegistry#gauge(String, String, DoubleSupplier)}. */
    public static Gauge gauge(String name, String help, DoubleSupplier supplier) {
        return REGISTRY.gauge(name, help, supplier);
    }

    /** This loader's registry. */
    public static MetricRegistry registry() {
        return REGISTRY;
    }

    /** Every metric now; see {@link MetricRegistry#snapshot()}. */
    public static List<MetricSnapshot> snapshot() {
        return REGISTRY.snapshot();
    }

    /**
     * Registers this copy's MXBean if it is not registered yet, and says under which name. Empty when it could
     * not be, or when this copy's lifecycle has shut down (it is not registered again after that).
     */
    public static Optional<ObjectName> registerMXBean() {
        return MXBEAN.ensure();
    }
}
