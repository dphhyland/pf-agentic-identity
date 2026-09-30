/*
 * The lifecycle listener: marks a war's copy of platform as the webapp's, audits it at start-up and closes it at undeploy.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.pf.health.BuildInfo;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.Catalogues;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.ServletRegistration;
import java.security.CodeSource;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.management.ObjectName;

/**
 * Plan item F-2, registered by name - never by annotation - in {@code pf-runtime.war} (through
 * {@code build/pingfederate/filters.xml}, which the war assembler writes into its {@code web.xml}), {@code oidf.war}
 * and {@code gm-api.war}. Each war that bundles platform-pf has its own copy of platform (docs/development/
 * classloaders.md, rule 1), and this listener works on that copy only:
 *
 * <ol>
 *   <li>{@code contextInitialized} marks the copy as the webapp's ({@link Lifecycle#markWebapp()}), registers its
 *       metrics MXBean, and runs the production profile's sweep (plan item PR-5): {@link ProfileAudit#evaluate} over
 *       the environment, the system properties and every catalogue the war's loader sees, published in
 *       {@link ProfileRefusals} before any filter's or servlet's {@code init} runs, so {@code Startup.begin} refuses the
 *       parts of each component a violation names. The full list is logged once, at ERROR under production and at WARN
 *       under development, which refuses nothing. It then arranges the start-up audit ({@link StartupAudit}): it adds a servlet with no mapping and
 *       the highest load-on-startup, so the container initialises it after every filter and every other
 *       load-on-startup servlet, and its {@code init} logs the banner once, at INFO, with the components those
 *       {@code init}s registered. A container that will not add the servlet gets the banner at once.</li>
 *   <li>{@code contextDestroyed} runs the copy's lifecycle shutdown - its managed executors, its MXBean and its Redis
 *       pools - within {@link #SHUTDOWN_BUDGET}, and logs how each close ended.</li>
 * </ol>
 *
 * <p>It acts only when its own copy of platform was loaded by the war's own classloader. The same jars sit in
 * {@code server/default/deploy}, on the engine's loader, and a war whose loader asked its parent first would see the
 * engine's copy: marking or shutting that down would close what the OGNL criteria use. So when the loader that
 * defined {@link Lifecycle} is not the war's, the listener logs a WARN and does nothing else.
 */
public class LifecycleListener implements ServletContextListener {

    /** The name of the servlet that runs the audit after the other load-on-startup inits. */
    static final String AUDIT_SERVLET = "oidf-startup-audit";

    /**
     * How long {@code contextDestroyed} waits in all for the closes it starts: under {@code docker stop}'s ten
     * seconds, with PingFederate's own shutdown still to come.
     */
    static final Duration SHUTDOWN_BUDGET = Duration.ofSeconds(5);

    /** platform's event catalogue, and the code of one violation the production profile refused. */
    static final String EVENTS = "platform";
    static final String PROFILE_REFUSED = "platform.profile.refused";

    /** The longest line of the sweep's log entry: a violation's whole message, never cut in practice. */
    static final int SWEEP_LINE = 4096;

    private static final PlatformLog LOG = PlatformLog.get(LifecycleListener.class);

    private final Function<String, String> env;
    private final Sources sources;
    private final Supplier<LocalDate> today;
    private final ClassLoader catalogues;
    private final AtomicBoolean audited = new AtomicBoolean();

    public LifecycleListener() {
        this(System::getenv, Sources.process(), () -> LocalDate.now(ZoneOffset.UTC), LifecycleListener.class.getClassLoader());
    }

    /** Test seam: this environment, no system properties, and this class's loader's catalogues. */
    LifecycleListener(Function<String, String> env, Supplier<LocalDate> today) {
        this(env, Sources.of(env, name -> null, null), today, LifecycleListener.class.getClassLoader());
    }

    /**
     * @param env        the environment, for the banner's profile and accepted risks
     * @param sources    what the sweep reads: the same environment, and the system properties
     * @param today      the date risks are judged against
     * @param catalogues the loader whose catalogues the sweep reads
     */
    LifecycleListener(Function<String, String> env, Sources sources, Supplier<LocalDate> today, ClassLoader catalogues) {
        this.env = env;
        this.sources = sources;
        this.today = today;
        this.catalogues = catalogues;
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        String war = warOf(context);
        if (!ownsCopy(context, war)) {
            return;
        }
        Lifecycle.current().markWebapp();
        Metrics.registerMXBean();
        sweep(war);
        if (!deferAudit(context, war)) {
            audit(war);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        String war = warOf(context);
        if (!ownsCopy(context, war)) {
            return;
        }
        List<Lifecycle.Closed> closed = Lifecycle.current().shutdown(SHUTDOWN_BUDGET);
        StringBuilder line = new StringBuilder("Lifecycle listener: ").append(war).append(" stopped; ");
        if (closed.isEmpty()) {
            line.append("nothing to close");
        } else {
            line.append("closed ").append(closed.size()).append(':');
            for (Lifecycle.Closed c : closed) {
                line.append(' ').append(c.name()).append(" (").append(c.outcome()).append(')');
            }
        }
        LOG.info(line.toString());
    }

    /**
     * The production profile's sweep of this process, published in {@link ProfileRefusals} and logged once: every
     * violation, then every warning, at ERROR under production and at WARN under development. A sweep that fails - a
     * fault in this code, never a setting - refuses every component under production rather than let an unchecked
     * deployment serve.
     *
     * @return what it published
     */
    ProfileAudit.Result sweep(String war) {
        DeploymentProfile profile = DeploymentProfile.of(this.env);
        ProfileAudit.Result result;
        try {
            result = ProfileAudit.evaluate(this.sources, Catalogues.onClassPath(this.catalogues), profile,
                    AcceptedRisks.of(this.env, this.today.get()));
        } catch (RuntimeException | LinkageError e) {
            result = new ProfileAudit.Result(profile, List.of(new ProfileAudit.Violation(ProfileAudit.Kind.CATALOGUE, "the sweep",
                    "The production profile's start-up sweep failed (" + StartupAudit.oneLine(e.toString()) + "), so no setting"
                            + " was checked", "Report it: this is a fault in pf-agentic-identity, not in the deployment",
                    List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING", "SSF",
                            "SSF_RECEIVER", "OPERATOR_API", "FAPI"))), List.of());
        }
        ProfileRefusals.publish(result);
        Predicate<ProfileAudit.Violation> refusing = refusing(result);
        String list = sweepLog(war, result, refusing);
        if (result.violations().stream().anyMatch(refusing)) {
            LOG.error(list, null);
        } else if (list != null) {
            LOG.warn(list);
        }
        return result;
    }

    /**
     * Which of {@code result}'s violations refuse something: none under development, and under production each that
     * refuses a component by {@code Startup.begin}'s rule ({@link ProfileRefusals#refusedBy}) - not one whose components
     * are all switched off, nor a {@code required-in-production} one whose components are none of them switched on.
     */
    static Predicate<ProfileAudit.Violation> refusing(ProfileAudit.Result result) {
        return v -> result.refuses() && !ProfileRefusals.refusedBy(v,
                c -> Startup.parts().verdict(c).kind() == ComponentSwitches.Kind.ENABLED,
                c -> Startup.parts().verdict(c).kind() == ComponentSwitches.Kind.DISABLED).isEmpty();
    }

    /** The sweep's one log entry: a heading and a line per violation and per warning; null when there is nothing. */
    static String sweepLog(String war, ProfileAudit.Result result, Predicate<ProfileAudit.Violation> refusing) {
        if (result.violations().isEmpty() && result.warnings().isEmpty()) {
            return null;
        }
        long refused = result.violations().stream().filter(refusing).count();
        StringBuilder out = new StringBuilder("Deployment profile ").append(result.profile().value()).append(" for ").append(war)
                .append(refused > 0
                ? " - " + refused + " violation(s) refuse the components they name, which answer 503; PingFederate's own"
                        + " endpoints keep serving:"
                : result.violations().isEmpty() || result.profile().isProduction() ? " - nothing refused:"
                : " - " + result.violations().size() + " violation(s) the production profile would refuse; the development"
                        + " profile refuses nothing:");
        for (ProfileAudit.Violation v : result.violations()) {
            out.append(System.lineSeparator()).append("  ").append(StartupAudit.label(v, result, refusing))
                    .append(StartupAudit.oneLine(v.line(), SWEEP_LINE));
        }
        for (String warning : result.warnings()) {
            out.append(System.lineSeparator()).append("  warning: ").append(StartupAudit.oneLine(warning, SWEEP_LINE));
        }
        return out.toString();
    }

    /**
     * Logs the start-up audit, the first time it is called for this listener: the banner at INFO, then each
     * {@code OIDF_ACCEPTED_RISKS} refusal at WARN, and, under production, one {@code platform.profile.refused} event
     * per violation - the sweep's and those refused in code - now that the {@code init}s have installed the audit sink.
     *
     * <p>The banner is a diagnostic: when collecting it fails, it logs a WARN and returns, so that it never fails the
     * listener or the load-on-startup servlet it runs in.
     *
     * @return the banner it logged, or empty when it had already logged one or could not collect it
     */
    Optional<String> audit(String war) {
        if (!this.audited.compareAndSet(false, true)) {
            return Optional.empty();
        }
        try {
            return Optional.of(logAudit(war));
        } catch (RuntimeException | LinkageError e) {
            LOG.warn("Start-up audit: " + war + " could not write its banner (" + StartupAudit.oneLine(e.toString()) + ")");
            return Optional.empty();
        }
    }

    private String logAudit(String war) {
        ClassLoader loader = LifecycleListener.class.getClassLoader();
        StartupAudit.Facts facts = StartupAudit.collect(war, BuildInfo.read(loader), this.env, this.today.get(),
                ProfileRefusals.current(), refusing(ProfileRefusals.current()), ProfileRefusals.codeRefusals(),
                Settings.legacySpellings(),
                InsecureTls.uses(), InsecureTls.jdkHostnameVerificationDisabled(), Components.snapshot(),
                ManagedExecutors.snapshot(), Metrics.registerMXBean().map(ObjectName::toString),
                where(Lifecycle.class.getProtectionDomain().getCodeSource()));
        String banner = StartupAudit.banner(facts);
        LOG.info(banner);
        for (String refusal : facts.risks().refusals()) {
            LOG.warn("Start-up audit: " + StartupAudit.oneLine(refusal) + " - that risk is not accepted");
        }
        if (facts.audit().profile().isProduction()) {
            List<ProfileAudit.Violation> refused = new ArrayList<>(facts.audit().violations().stream().filter(facts.refusing()).toList());
            refused.addAll(facts.codeRefusals());
            for (ProfileAudit.Violation v : refused) {
                Events.event(EVENTS, PROFILE_REFUSED).audit().failure(v.kind().name().toLowerCase(java.util.Locale.ROOT))
                        .description(v.message()).field("setting", v.setting()).field("violation", v.kind().name())
                        .field("components", String.join(",", v.components())).emit();
            }
        }
        return banner;
    }

    /**
     * Adds the audit servlet, initialised after every other load-on-startup servlet.
     *
     * @return whether the container took it; {@code false} when it would not add a servlet now, or one of that
     *         name already exists, and the caller audits at once
     */
    boolean deferAudit(ServletContext context, String war) {
        ServletRegistration.Dynamic registration;
        try {
            registration = context.addServlet(AUDIT_SERVLET, new StartupAuditServlet(() -> audit(war)));
        } catch (IllegalStateException | UnsupportedOperationException e) {
            LOG.info("Lifecycle listener: " + war + " cannot add the audit servlet (" + e + "); auditing now");
            return false;
        }
        if (registration == null) {
            LOG.info("Lifecycle listener: " + war + " already has a servlet named " + AUDIT_SERVLET + "; auditing now");
            return false;
        }
        registration.setLoadOnStartup(Integer.MAX_VALUE);
        return true;
    }

    /**
     * Whether this listener's copy of platform is the war's own: the war's classloader defined it. Logs a WARN when
     * it is not.
     */
    static boolean ownsCopy(ServletContext context, String war) {
        ClassLoader copy = Lifecycle.class.getClassLoader();
        ClassLoader own = context.getClassLoader();
        if (copy == own) {
            return true;
        }
        LOG.warn("Lifecycle listener: " + war + " sees a copy of platform its own classloader did not load ("
                + where(Lifecycle.class.getProtectionDomain().getCodeSource()) + "); it leaves that copy alone - no"
                + " mark, no audit, no shutdown. Bundle platform in the war's WEB-INF/lib and load it child-first");
        return false;
    }

    /** How the log names a war: its context path, or {@code /} for the root context, with its display name if any. */
    static String warOf(ServletContext context) {
        String path = context.getContextPath();
        String name = context.getServletContextName();
        String where = path == null || path.isEmpty() ? "/" : path;
        return StartupAudit.oneLine(name == null || name.isBlank() ? where : where + " (" + name + ")");
    }

    /** Where a copy's classes came from, or that the loader does not say. */
    static String where(CodeSource source) {
        return Optional.ofNullable(source).map(CodeSource::getLocation).map(Object::toString)
                .orElse("a location its loader does not report");
    }
}
