/*
 * Process-wide singletons shared across the SSF servlets and the delivery executor.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.IomInstanceRegistry;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link SsfConfiguration}, {@link SsfStore}, and {@link SetMinter} so every SSF servlet
 * (configuration, stream management, poll) and the background push executor operate on one shared state — the
 * same pattern as {@code AttestationSupport}. First servlet to {@code init()} configures it; later servlets
 * see the same instance.
 *
 * <p>Store selection follows {@code dataStoreId}: blank selects the per-node {@link InMemorySsfStore} (not
 * cluster-safe, not durable); a set id selects the PingFederate JDBC-backed store. The JDBC store is installed
 * by {@link #installStoreFactory} so this core has no compile-time dependency on the PF SDK.
 *
 * <p>{@link #start} is the boot path: it configures, runs the servlet layer's wiring, and starts the push
 * loop, and it never throws. A store that cannot be opened when PingFederate boots - the data store down,
 * its schema not applicable - is logged and tried again every {@link #bootRetrySeconds} until it can be,
 * and the loops start then.
 */
public final class SsfSupport {

    private static final Log LOGGER = LogFactory.getLog(SsfSupport.class);
    private static final Object LOCK = new Object();

    /** How long a boot that could not open the store waits before trying again. A constant until S-5 makes it a setting. */
    static volatile int bootRetrySeconds = 30;
    private static ScheduledExecutorService bootRetry;
    private static boolean bootRetryPending;

    private static volatile SsfConfiguration configuration;
    private static volatile SsfStore store;
    private static volatile SetMinter minter;
    private static volatile StreamManagementService streamService;
    private static volatile SsfEventEmitter eventEmitter;
    private static volatile ScimSubjectService scimSubjectService;
    private static volatile SsfEmitService emitService;
    private static volatile PushDeliveryService pushDeliveryService;
    private static volatile SetPublisher setPublisher;
    private static volatile SsfReceiverService receiverService;
    private static volatile PollReceiverClient pollReceiverClient;
    private static volatile ReceiverAuthenticator receiverAuthenticator;
    private static volatile StoreFactory storeFactory;

    private SsfSupport() {
    }

    /** Creates an {@link SsfStore} from configuration; supplied by the JDBC-backed servlet layer at init. */
    public interface StoreFactory {
        SsfStore create(SsfConfiguration config);
    }

    /**
     * Register a factory that can build a JDBC-backed store from a {@code dataStoreId}. Called by the servlet
     * layer (which can reach the PF SDK) before {@link #configure}. If none is registered, a configured
     * {@code dataStoreId} falls back to the in-memory store with a warning.
     */
    public static void installStoreFactory(StoreFactory factory) {
        synchronized (LOCK) {
            storeFactory = factory;
        }
    }

    /**
     * Idempotently configure the shared singletons from the first servlet's parsed configuration. Throws
     * what opening the store throws (a {@code tables} store applies its DDL here), and then leaves nothing
     * behind: every singleton is built before any is assigned, so a failed configure is a transmitter that
     * is not configured and can be configured again - not one with a configuration and no store, which is
     * what an early assignment used to leave, with every later configure returning at the first check.
     */
    public static void configure(SsfConfiguration config) {
        Objects.requireNonNull(config, "config");
        synchronized (LOCK) {
            if (configuration != null) {
                return;
            }
            SetMinter theMinter = new SetMinter(config.signingAlgorithm());
            SsfStore theStore = selectStore(config);
            warnOfUnownedStreams(theStore, config);
            SetPublisher thePublisher = buildPublisher(config);
            SsfEventEmitter theEmitter = new SsfEventEmitter(theStore, theMinter, config, thePublisher);
            SsfReceiverService theReceiver = null;
            PollReceiverClient thePollClient = null;
            if (receiverMayRun(config)) {
                theReceiver = new SsfReceiverService(new SetVerifier(
                        config.receiverExpectedIssuer(), config.receiverAudience(),
                        SetVerifier.httpJwksSource(config.receiverJwksUrl(),
                                config.receiverJwksCacheSeconds(), config.receiverInsecureTls())));
                LOGGER.info((Object) ("SSF receiver: accepting SETs from " + config.receiverExpectedIssuer()
                        + " (jwks " + config.receiverJwksUrl() + ")"));
                if (config.receiverInstanceRegistry()) {
                    installInstanceRegistryHandler(theReceiver, theStore, config);
                }
                if (config.receiverPollUrl() != null) {
                    thePollClient = new PollReceiverClient(theReceiver,
                            PollReceiverClient.httpTransport(config.receiverPollUrl(),
                                    config.receiverPollToken(), config.receiverInsecureTls()),
                            config.pollMaxEvents());
                }
            }
            minter = theMinter;
            store = theStore;
            setPublisher = thePublisher;
            streamService = new StreamManagementService(theStore, theMinter, config, thePublisher);
            eventEmitter = theEmitter;
            scimSubjectService = new ScimSubjectService(theStore, theEmitter, config);
            emitService = new SsfEmitService(theStore, theEmitter, config);
            pushDeliveryService = new PushDeliveryService(theStore, config, PushDeliveryService.httpClient());
            receiverService = theReceiver;
            pollReceiverClient = thePollClient;
            configuration = config;
        }
    }

    /**
     * Bring the transmitter up: {@link #configure}, then the servlet layer's wiring ({@code afterConfigure}:
     * the receiver's PF actions and polling, the audit source), then the push loop. Idempotent - every SSF
     * servlet's {@code init} runs it, and at boot the first is {@code SsfConfigurationServlet}, which loads
     * on start-up, so the loop runs before any request arrives. Returns whether the transmitter is up.
     *
     * <p>Never throws. Before 0.4.0 a store that could not be opened threw out of the servlet's
     * {@code init} - for the load-on-startup servlet, at boot ("Found while designing" 11; what the container
     * made of that is U-0057, not reproduced). Now it is an ERROR in the log, endpoints that stay disabled,
     * and a retry every {@link #bootRetrySeconds} until the store can be opened; the loops start on the retry
     * that succeeds. The wiring is guarded the same way: a failure there is logged and the loop still starts.
     */
    public static boolean start(SsfConfiguration config, Runnable afterConfigure) {
        try {
            configure(config);
        } catch (RuntimeException e) {
            LOGGER.error((Object) ("SSF transmitter NOT started: its store could not be opened (" + e
                    + "). The SSF endpoints stay disabled and nothing is delivered; trying again in "
                    + bootRetrySeconds + "s"), e);
            scheduleBootRetry(config, afterConfigure);
            return false;
        }
        try {
            afterConfigure.run();
        } catch (RuntimeException e) {
            LOGGER.error((Object) ("SSF transmitter wiring failed after configuration: " + e), e);
        }
        startPushDelivery();
        return true;
    }

    /** One retry in flight at a time: a second servlet's failed init joins the pending one. */
    private static void scheduleBootRetry(SsfConfiguration config, Runnable afterConfigure) {
        synchronized (LOCK) {
            if (bootRetryPending) {
                return;
            }
            if (bootRetry == null) {
                bootRetry = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "ssf-boot-retry");
                    t.setDaemon(true);
                    return t;
                });
            }
            bootRetryPending = true;
            bootRetry.schedule(() -> {
                synchronized (LOCK) {
                    bootRetryPending = false;
                }
                start(config, afterConfigure);
            }, bootRetrySeconds, TimeUnit.SECONDS);
        }
    }

    /** Whether a boot retry is scheduled and has not run yet. */
    static boolean bootRetryPending() {
        synchronized (LOCK) {
            return bootRetryPending;
        }
    }

    /**
     * Whether to bring the receiver up: it is switched on, and it has the audience and the endpoint token it
     * may not run without. Short of those it stays down - its endpoint answers 404 and nothing is polled -
     * and the log says which is missing. The transmitter is unaffected.
     */
    static boolean receiverMayRun(SsfConfiguration config) {
        if (!config.receiverConfigured()) {
            return false;
        }
        List<String> missing = config.receiverMissingRequirements();
        if (!missing.isEmpty()) {
            LOGGER.error((Object) ("SSF receiver NOT started: " + missing + " must be set (OIDF_SSF_RECEIVER_AUDIENCE, "
                    + "OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN). Without them a SET is accepted on the transmitter's "
                    + "signature alone, whoever it was minted for and whoever delivers it, and grants are revoked on it"));
            return false;
        }
        return true;
    }

    /** Kafka fan-out sink when enabled (best-effort — a build failure falls back to no-op, never crashes init). */
    private static SetPublisher buildPublisher(SsfConfiguration config) {
        if (!config.kafkaEnabled()) {
            return SetPublisher.NOOP;
        }
        try {
            return KafkaSetPublisher.create(config);
        } catch (RuntimeException e) {
            LOGGER.error((Object) ("SSF Kafka publisher disabled — " + e.getMessage()));
            return SetPublisher.NOOP;
        }
    }

    /** Start the background push-delivery loop (idempotent). {@link #start} calls it once the store is open. */
    public static void startPushDelivery() {
        PushDeliveryService local = pushDeliveryService;
        if (local != null) {
            local.start();
        }
    }

    /** Start the receiver's remote-poll loop when {@code receiverPollUrl} is configured (idempotent). */
    public static void startReceiverPolling() {
        PollReceiverClient local = pollReceiverClient;
        if (local != null) {
            local.start(configuration().receiverPollIntervalSeconds());
        }
    }

    /**
     * Install a receiver authenticator (tests inject a fake). If none is installed, {@link #receiverAuthenticator()}
     * lazily builds a PF-introspection authenticator from configuration.
     */
    public static void installReceiverAuthenticator(ReceiverAuthenticator authenticator) {
        synchronized (LOCK) {
            receiverAuthenticator = authenticator;
        }
    }

    /**
     * Wires the agent instance registry into the receiver pipeline, reusing the {@code ldm} store's own
     * {@link javax.sql.DataSource} — the registry lives in the same Identity Object Model database, so
     * this opens no second connection pool. Refuses (with a warning, not a startup failure) on any other
     * {@code storeDialect}: an in-memory or {@code tables} store has no IOM connection to share, and
     * opening a bespoke one here would reintroduce the very database this registry replaced.
     */
    private static void installInstanceRegistryHandler(SsfReceiverService receiver, SsfStore store,
            SsfConfiguration config) {
        if (!(store instanceof LdmSsfStore ldmStore)) {
            LOGGER.warn((Object) ("SSF receiverInstanceRegistry=true requires storeDialect=ldm; got '"
                    + config.storeDialect() + "' — instance registry CAEP handler NOT installed"));
            return;
        }
        receiver.addHandler(new InstanceRegistryReceiverHandler(
                new CaepSignalApplier(new IomInstanceRegistry(ldmStore.dataSource()))));
        LOGGER.info((Object) "SSF receiver: instance registry CAEP handler installed (ldm store)");
    }

    /**
     * Streams stored before streams had owners answer every receiver as though they did not exist. Said once
     * at boot, so it is read in a log rather than worked out from a receiver's 404s. Returns the count, or -1
     * if the store could not be asked - which must not stop the transmitter starting.
     */
    static int warnOfUnownedStreams(SsfStore store, SsfConfiguration config) {
        int unowned = 0;
        try {
            for (Stream s : store.listStreams()) {
                if (s.ownerClientId() == null) {
                    unowned++;
                }
            }
        } catch (RuntimeException e) {
            LOGGER.warn((Object) ("SSF store: could not count streams with no owner: " + e.getMessage()));
            return -1;
        }
        if (unowned > 0) {
            LOGGER.warn((Object) (unowned + " SSF stream(s) have no owner. " + (config.unownedStreamOwner() == null
                    ? "No receiver is admitted to them: name their client in OIDF_SSF_UNOWNED_STREAM_OWNER or set "
                            + "their owners in the store (servlets/ssf/README.md, Stream ownership)"
                    : "Client '" + config.unownedStreamOwner() + "' is admitted to them (OIDF_SSF_UNOWNED_STREAM_OWNER)")));
        }
        return unowned;
    }

    private static SsfStore selectStore(SsfConfiguration config) {
        if (config.usesInMemoryStore()) {
            LOGGER.info((Object) "SSF store: in-memory (per-node; NOT cluster-safe, NOT durable across restarts)");
            return new InMemorySsfStore();
        }
        StoreFactory factory = storeFactory;
        if (factory == null) {
            LOGGER.warn((Object) ("SSF dataStoreId '" + config.dataStoreId()
                    + "' configured but no JDBC store factory installed; falling back to in-memory (per-node)"));
            return new InMemorySsfStore();
        }
        LOGGER.info((Object) ("SSF store: JDBC data store '" + config.dataStoreId() + "' dialect '"
                + config.storeDialect() + "' (cluster-safe, durable)"));
        return factory.create(config);
    }

    public static SsfConfiguration configuration() {
        SsfConfiguration local = configuration;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SsfStore store() {
        SsfStore local = store;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SetMinter minter() {
        SetMinter local = minter;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static StreamManagementService streamService() {
        StreamManagementService local = streamService;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SsfEventEmitter eventEmitter() {
        SsfEventEmitter local = eventEmitter;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static ScimSubjectService scimSubjectService() {
        ScimSubjectService local = scimSubjectService;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SsfEmitService emitService() {
        SsfEmitService local = emitService;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static PushDeliveryService pushDeliveryService() {
        PushDeliveryService local = pushDeliveryService;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    /** The inbound-SET receiver pipeline; null when the receiver is not configured. */
    public static SsfReceiverService receiverService() {
        return receiverService;
    }

    /** The receiver authenticator: an installed one (tests) or a lazily-built PF-introspection authenticator. */
    public static ReceiverAuthenticator receiverAuthenticator() {
        ReceiverAuthenticator local = receiverAuthenticator;
        if (local == null) {
            synchronized (LOCK) {
                if (receiverAuthenticator == null) {
                    receiverAuthenticator = buildIntrospectionAuthenticator(configuration());
                }
                local = receiverAuthenticator;
            }
        }
        return local;
    }

    private static ReceiverAuthenticator buildIntrospectionAuthenticator(SsfConfiguration cfg) {
        if (!cfg.receiverAuthConfigured()) {
            LOGGER.warn((Object) "SSF receiver auth: introspection client not configured; all receiver "
                    + "requests will be rejected until introspectionClientId/Secret are set");
            return token -> AuthContext.inactive();
        }
        return PfIntrospectionReceiverAuthenticator.forEndpoint(
                cfg.introspectionEndpoint(), cfg.introspectionClientId(),
                cfg.introspectionClientSecret(), cfg.introspectionInsecureTls());
    }

    /** Test hook: reset all singletons so a fresh {@link #configure} takes effect. */
    static void resetForTests() {
        synchronized (LOCK) {
            if (bootRetry != null) {
                bootRetry.shutdownNow();
                bootRetry = null;
            }
            bootRetryPending = false;
            bootRetrySeconds = 30;
            if (pushDeliveryService != null) {
                pushDeliveryService.stop();
            }
            if (setPublisher != null) {
                setPublisher.close();
            }
            configuration = null;
            store = null;
            minter = null;
            streamService = null;
            eventEmitter = null;
            scimSubjectService = null;
            emitService = null;
            pushDeliveryService = null;
            setPublisher = null;
            if (pollReceiverClient != null) {
                pollReceiverClient.stop();
            }
            pollReceiverClient = null;
            receiverService = null;
            receiverAuthenticator = null;
            storeFactory = null;
        }
    }
}
