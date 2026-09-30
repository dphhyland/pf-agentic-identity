/*
 * The SSF transmitter's and receiver's start functions: what their servlets' init hands to the component parts.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.ssf.ReceiverStream;
import com.pingidentity.ps.oidf.ssf.ReceiverStreamClient;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.SQLException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The SSF components' start functions (plan items S-9 and ST-5), which the servlets' {@code init} hands to
 * {@link ComponentParts.Part#start}. The part applies the switch first - {@code OIDF_SSF_ENABLED=false} is
 * {@code DISABLED} and nothing here runs, an unset switch in production with SSF's settings present is
 * {@code FAILED_CONFIG} naming the switch - and then:
 *
 * <ul>
 *   <li><b>SSF</b> ({@code SsfConfigurationServlet}): no {@code OIDF_SSF_ISSUER} is not configured - {@code DISABLED},
 *       or {@code FAILED_CONFIG} naming the issuer at ERROR when the switch is {@code true}. A setting the catalogue
 *       refuses, or a combination {@link SsfConfiguration} refuses, is {@code FAILED_CONFIG} with an ERROR naming it
 *       (findings F-0191, F-0237). An in-memory store under production without the {@code in-memory-state} risk, and
 *       a store that is not PostgreSQL under production, are {@code REFUSED} ({@link ProfileRefusals}). A store that
 *       cannot be opened is {@code FAILED_DEPENDENCY}, with an ERROR naming the cause (the {@code jdbcUrl} replaced),
 *       and platform's supervisor runs this again with backoff until it opens. Otherwise the whole transmitter is
 *       published in one write ({@link SsfSupport#start}) and the part is ready.</li>
 *   <li><b>SSF_RECEIVER</b> ({@code SsfReceiverServlet}): the receiver runs inside the transmitter, so it waits for
 *       it - {@code FAILED_DEPENDENCY} while the transmitter is starting or failed on a dependency, retried by the
 *       supervisor - and takes its answer when the transmitter is off, failed on its configuration or refused. With
 *       the transmitter up, no {@code OIDF_SSF_RECEIVER_EXPECTED_ISSUER} is not configured, and a receiver without its
 *       audience or endpoint token is {@code FAILED_CONFIG}. A receiver that manages its own stream at the transmitter
 *       (H-SSF-1) sets it up here: {@code FAILED_DEPENDENCY} while the transmitter cannot be reached or refuses,
 *       retried by the supervisor, and {@code FAILED_CONFIG} when its metadata or stream is not the receiver's.</li>
 * </ul>
 *
 * <p>Nothing here throws but the production profile's {@link ProfileRefused}, which the part records as
 * {@code REFUSED}; every other outcome is set on the part directly, so what reaches the log is the lines written here,
 * never an exception whose message could carry the {@code jdbcUrl}.
 */
final class SsfComponents {

    private static final Log LOG = LogFactory.getLog(SsfComponents.class);

    /** The part the transmitter's servlets are gated by: {@code SsfConfigurationServlet}'s, once its init has run. */
    private static volatile ComponentParts.Part transmitterPart;

    /**
     * Whether the transmitter's settings name a receiver ({@code OIDF_SSF_RECEIVER_EXPECTED_ISSUER}), as its last start
     * read them; null before it has read them. The receiver's part asks it when the transmitter is not up, so a
     * deployment with no receiver has its receiver {@code DISABLED}, not failed or waiting with the transmitter.
     */
    private static volatile Boolean receiverWanted;

    private SsfComponents() {
    }

    /** The transmitter's part, for the gate of the SSF servlets that register none of their own; null before it registers. */
    static ComponentParts.Part transmitterPart() {
        return transmitterPart;
    }

    static void transmitterPart(ComponentParts.Part part) {
        transmitterPart = part;
    }

    /**
     * What the SSF transmitter's start reads beyond its settings: the profile and the accepted risks it is judged
     * under, whether the receiver may run, the store factory, and where its ERROR lines go. {@link #process()} is this
     * process's; a test supplies its own.
     */
    record Context(DeploymentProfile profile, AcceptedRisks risks, boolean receiverAllowed, SsfSupport.StoreFactory stores,
            Consumer<String> errors) {

        static Context process() {
            return new Context(DeploymentProfile.current(), AcceptedRisks.current(), SsfComponents.receiverAllowed(Startup.parts()),
                    new PfJdbcStoreFactory(), line -> LOG.error((Object) line));
        }
    }

    /**
     * Whether the receiver may run: its switch lets it start and the production profile does not refuse it. Asked by
     * the transmitter, which builds the receiver.
     */
    static boolean receiverAllowed(ComponentParts parts) {
        ComponentSwitches.Verdict verdict = parts.verdict(Startup.SSF_RECEIVER);
        return verdict.mayStart()
                && ProfileRefusals.reason(Startup.SSF_RECEIVER, verdict.kind() == ComponentSwitches.Kind.ENABLED) == null;
    }

    /** The SSF transmitter's start function, reading {@code config}'s init-params and this process. */
    static void transmitter(ComponentParts.Part part, jakarta.servlet.ServletConfig config) {
        transmitter(part, SsfConfiguration.settings(config), Context.process());
    }

    /** The SSF transmitter's start function, for {@code settings} read under {@code context}. */
    static void transmitter(ComponentParts.Part part, Settings settings, Context context) {
        SsfSupport.installStoreFactory(context.stores());
        if (SsfSupport.isConfigured()) {
            return; // a second init of the servlet, or a retry that raced a start: the state is published once
        }
        receiverWanted = receiverWanted(settings);
        SsfConfiguration cfg;
        try {
            if (!SsfConfiguration.issuerSet(settings)) {
                notConfigured(part, context);
                return;
            }
            cfg = SsfConfiguration.from(settings);
        } catch (ProfileRefused e) {
            throw e;
        } catch (SettingRefused e) {
            context.errors().accept("SSF transmitter NOT started: " + e.getMessage() + ". Its endpoints answer 503 until the"
                    + " setting is corrected and PingFederate restarted");
            part.failedConfig(e.getMessage());
            return;
        }
        refuseTheStore(cfg, context);
        try {
            SsfSupport.start(cfg, context.receiverAllowed(), SsfHttp::afterConfigure);
        } catch (ProfileRefused e) {
            throw e;
        } catch (RuntimeException e) {
            SsfSupport.logBootFailure(cfg, e);
            String reason = SsfSupport.describe(e, cfg.jdbcUrl());
            if (dependency(e)) {
                part.failedDependency("the SSF store could not be opened: " + reason);
            } else {
                part.failedConfig(reason);
            }
        }
    }

    /** Whether {@code settings} name a receiver; a value that cannot be read counts as one, so it is not hidden. */
    static boolean receiverWanted(Settings settings) {
        try {
            return settings.string(SsfConfiguration.RECEIVER_EXPECTED_ISSUER) != null;
        } catch (RuntimeException e) {
            return true;
        }
    }

    /** Test hook: forget the part and what the last start read. */
    static void resetForTests() {
        transmitterPart = null;
        receiverWanted = null;
    }

    /**
     * No issuer. Switched on, that is the component's configuration missing ({@code FAILED_CONFIG}, at ERROR); inferred
     * off, {@code DISABLED}, said at INFO in development only - in production an SSF with none of its settings is off
     * and the start-up audit says so.
     */
    private static void notConfigured(ComponentParts.Part part, Context context) {
        String missing = SsfConfiguration.ISSUER + " is not set";
        if (part.verdict().kind() == ComponentSwitches.Kind.ENABLED) {
            context.errors().accept("SSF transmitter NOT started: " + ComponentSwitches.SSF + "=true but " + missing);
        } else if (context.profile().isDevelopment()) {
            LOG.info((Object) ("SSF transmitter not configured (" + missing + "); its endpoints answer 404 until it is set,"
                    + " or set " + ComponentSwitches.SSF + "=false to say SSF is not used"));
        }
        part.notConfigured(missing);
    }

    /**
     * PR-2's refusals of the SSF store (Phase 3 plan, decisions 9, 10 and 15), under production: a store in memory
     * without the {@code in-memory-state} risk, and a {@code jdbcUrl} that is not a {@code jdbc:postgresql:} URL. A
     * data store id is checked on its first connection, by the database's own product name ({@link PfJdbcStoreFactory}).
     * Under development each is a WARN and the store is used.
     */
    static void refuseTheStore(SsfConfiguration cfg, Context context) {
        if (cfg.usesInMemoryStore() && !context.risks().accepts(AcceptedRisk.IN_MEMORY_STATE)) {
            ProfileRefusals.requireRisk(Startup.SSF, AcceptedRisk.IN_MEMORY_STATE, "the SSF store is in memory (no"
                    + " OIDF_SSF_DATA_STORE_ID)");
        }
        String url = cfg.jdbcUrl();
        if (url != null && !url.regionMatches(true, 0, PfJdbcStoreFactory.POSTGRESQL_URL, 0, PfJdbcStoreFactory.POSTGRESQL_URL.length())) {
            ProfileRefusals.refuse(Startup.SSF, SsfConfiguration.JDBC_URL + " names a " + PfJdbcStoreFactory.scheme(url)
                    + " database: the SSF store is PostgreSQL (its tables and the ldm dialect are written and tested for"
                    + " PostgreSQL only); use a " + PfJdbcStoreFactory.POSTGRESQL_URL + " URL or a PingFederate data store"
                    + " on PostgreSQL");
        }
    }

    /**
     * Whether a store failure is a dependency's - an I/O, SQL or timeout failure, or a class that would not link,
     * somewhere in its causes - and so worth the supervisor's retry; anything else is the configuration's. The rule is
     * platform's for an exception out of a start function.
     */
    static boolean dependency(Throwable thrown) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable t = thrown; t != null && seen.size() < 16 && seen.add(t); t = t.getCause()) {
            if (t instanceof IOException || t instanceof UncheckedIOException || t instanceof SQLException
                    || t instanceof TimeoutException || t instanceof LinkageError) {
                return true;
            }
        }
        return false;
    }

    /** The SSF receiver's start function, judged against the SSF component's state in this loader's parts. */
    static void receiver(ComponentParts.Part part) {
        receiver(part, () -> Startup.parts().component(Startup.SSF));
    }

    /**
     * The SSF receiver's start function. It never builds anything: the transmitter builds the receiver
     * ({@link SsfSupport#configure}); this says what became of it. While the transmitter is starting or failed on a
     * dependency the part is {@code FAILED_DEPENDENCY}, and the supervisor runs this again until the transmitter has
     * an answer.
     *
     * @param ssf the SSF component's state as the registry holds it
     */
    static void receiver(ComponentParts.Part part, Supplier<Optional<ComponentStatus>> ssf) {
        if (!SsfSupport.isConfigured()) {
            Optional<ComponentStatus> transmitter = ssf.get();
            ComponentState state = transmitter.map(ComponentStatus::state).orElse(ComponentState.STARTING);
            if (state != ComponentState.DISABLED && Boolean.FALSE.equals(receiverWanted)) {
                // No receiver is configured: it is off whatever became of the transmitter (FAILED_CONFIG when switched on).
                part.notConfigured(SsfConfiguration.RECEIVER_EXPECTED_ISSUER + " is not set");
                return;
            }
            switch (state) {
                case DISABLED -> part.notConfigured("the SSF transmitter it runs inside is off");
                case FAILED_CONFIG, REFUSED -> {
                    String why = "the SSF transmitter it runs inside is " + state + ": "
                            + transmitter.map(ComponentStatus::reason).orElse("");
                    LOG.error((Object) ("SSF receiver NOT started: " + why));
                    part.failedConfig(why);
                }
                default -> part.failedDependency(WAITING + " (" + state + ")");
            }
            return;
        }
        SsfConfiguration cfg = SsfSupport.configuration();
        if (!cfg.receiverConfigured()) {
            part.notConfigured(SsfConfiguration.RECEIVER_EXPECTED_ISSUER + " is not set");
            return;
        }
        List<String> missing = cfg.receiverMissingRequirements().stream().map(SsfComponents::settingOf).toList();
        if (!missing.isEmpty()) {
            // SsfSupport.receiverMayRun has logged the ERROR naming them.
            part.failedConfig("the SSF receiver is not started: " + missing + " must be set");
            return;
        }
        if (SsfSupport.receiverService() == null) {
            part.notConfigured("the SSF transmitter did not build the receiver: " + ComponentSwitches.SSF_RECEIVER
                    + " is false or the production profile refuses SSF_RECEIVER");
            return;
        }
        receiverStream(part, SsfSupport.receiverStream());
    }

    /**
     * The receiver's own stream at its transmitter (H-SSF-1), when it manages one: set up before the receiver is ready.
     * A transmitter that cannot be reached or refuses leaves the part {@code FAILED_DEPENDENCY}, and the supervisor runs
     * the start again; one whose metadata or stream does not match the receiver's settings is {@code FAILED_CONFIG}. A
     * stream it created and could not accept is deleted again ({@link ReceiverStreamClient#ensure}).
     */
    static void receiverStream(ComponentParts.Part part, ReceiverStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.ensure();
        } catch (ReceiverStreamClient.Misconfigured e) {
            LOG.error((Object) ("SSF receiver NOT started: its stream at the transmitter does not match its settings: "
                    + e.getMessage()));
            part.failedConfig("the receiver's stream: " + e.getMessage());
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOG.warn((Object) ("SSF receiver waiting for its transmitter: its stream could not be set up (" + e
                    + "); the supervisor tries again"));
            part.failedDependency("the receiver's stream could not be set up at the transmitter: " + e.getMessage());
        }
    }

    /** The receiver's reason while it waits for the transmitter. */
    static final String WAITING = "waiting for the SSF transmitter it runs inside";

    /** The catalogue's name for one of {@link SsfConfiguration#receiverMissingRequirements()}'s. */
    static String settingOf(String requirement) {
        switch (requirement) {
            case "receiverAudience":
                return SsfConfiguration.RECEIVER_AUDIENCE;
            case "receiverEndpointAuthToken":
                return SsfConfiguration.RECEIVER_ENDPOINT_AUTH_TOKEN;
            default:
                return requirement;
        }
    }
}
