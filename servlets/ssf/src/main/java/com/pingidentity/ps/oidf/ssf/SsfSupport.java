/*
 * Process-wide singletons shared across the SSF servlets and the delivery executor.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.IomInstanceRegistry;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link SsfConfiguration}, {@link SsfStore}, {@link SetMinter} and the services built on them,
 * so every SSF servlet (configuration, stream management, poll) and the background push executor operate on one
 * shared state - the same pattern as {@code AttestationSupport}.
 *
 * <p>The state is one immutable {@link State}, built whole by {@link #configure} and published in one write (plan
 * item S-9, finding F-0040): a reader sees every member or none, never a configuration without its store. Before it is
 * published every accessor but {@link #receiverService()} throws {@link #NOT_CONFIGURED}.
 *
 * <p>Store selection follows {@code dataStoreId}: blank selects the per-node {@link InMemorySsfStore} (not
 * cluster-safe, not durable); a set id selects the PingFederate JDBC-backed store. The JDBC store is installed
 * by {@link #installStoreFactory} so this core has no compile-time dependency on the PF SDK.
 *
 * <p>{@link #start} is the transmitter's start: it configures, runs the servlet layer's wiring, and starts the push
 * loop, and throws what configuring threw. The servlet layer runs it as the {@code SSF} component's start function
 * ({@code SsfComponents}), which records the outcome on the part - a store that cannot be opened is
 * {@code FAILED_DEPENDENCY}, and platform's supervisor runs the start again with backoff until it opens.
 */
public final class SsfSupport {

    private static final Log LOGGER = LogFactory.getLog(SsfSupport.class);
    private static final Object LOCK = new Object();

    /**
     * What every accessor throws before {@link #configure} has succeeded: SSF is off, a setting is wrong, or the store
     * has not opened yet (the SSF component's state and server.log say which).
     */
    static final String NOT_CONFIGURED =
            "SSF transmitter is not started: it is off, a setting is wrong, or its store has not opened yet (see the SSF"
                    + " component's state and the SSF lines in the server log)";

    /** Whether a failed start has been logged; the stack trace goes with the first only. */
    private static boolean bootFailureLogged;

    /** Everything the transmitter shares, built together and published together. */
    private record State(SsfConfiguration configuration, SsfStore store, SetMinter minter, StreamManagementService streamService,
            SsfEventEmitter eventEmitter, ScimSubjectService scimSubjectService, SsfEmitService emitService,
            PushDeliveryService pushDeliveryService, SetPublisher setPublisher, SsfReceiverService receiverService,
            PollReceiverClient pollReceiverClient, ReceiverAuthenticator receiverAuthenticator, ReceiverStream receiverStream) {
    }

    private static volatile State state;
    /** A receiver authenticator a test installed; it wins over the one built at {@link #configure}. */
    private static volatile ReceiverAuthenticator installedAuthenticator;
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
     * The receiver's verifier: the configured issuer and audience, and an inbound {@code sub_id} kept to
     * {@link SsfSubjects#RECEIVER_FORMATS} - the five, {@code did}, {@code uri}, {@code aliases} and the complex
     * subject (H-SSF-1); SSF 1.0's {@code jwt_id}, {@code saml_assertion_id} and {@code ip-addresses} name no one the
     * receiver acts on and stay refused at the top level.
     */
    static SetVerifier receiverVerifier(SsfConfiguration config, SetVerifier.JwksSource keys) {
        return new SetVerifier(config.receiverExpectedIssuer(), config.receiverAudience(), keys,
                Clock.systemUTC(), SsfSubjects.RECEIVER_FORMATS);
    }

    /**
     * The receiver's bearer for its poll and stream calls (H-SSF-1): a client-credentials token when it has a client,
     * otherwise the static development token, which may be none.
     */
    static ReceiverBearer receiverBearer(SsfConfiguration config) {
        if (config.receiverTokenEndpoint() != null) {
            return ClientCredentialsToken.of(config, ClientCredentialsToken.httpTransport(config.receiverInsecureTls()),
                    Clock.systemUTC());
        }
        return ReceiverBearer.fixed(config.receiverPollToken());
    }

    /** {@link #configure(SsfConfiguration, boolean)} with the receiver allowed to run. */
    public static boolean configure(SsfConfiguration config) {
        return configure(config, true);
    }

    /**
     * Idempotently configure the shared state from the transmitter's parsed configuration: build every member - the
     * minter, the store (a {@code tables} store applies its DDL here), the publisher, the services, the receiver when
     * {@code receiverAllowed} and it is configured, and the receiver authenticator - and then publish them in one
     * write. Throws what building a member throws, and then leaves nothing behind: a failed configure is a
     * transmitter that is not configured and can be configured again, never one with a configuration and no store.
     *
     * @param receiverAllowed whether the {@code SSF_RECEIVER} component may run: its switch is not {@code false} and
     *                        the production profile does not refuse it
     * @return whether this call published the state; false when it was published already
     */
    public static boolean configure(SsfConfiguration config, boolean receiverAllowed) {
        Objects.requireNonNull(config, "config");
        synchronized (LOCK) {
            if (state != null) {
                return false;
            }
            SetMinter theMinter = new SetMinter(config.signingAlgorithm(), new PfSetSigningKeys(config.signingAlgorithm()));
            SsfStore theStore = selectStore(config);
            warnOfUnownedStreams(theStore, config);
            SetPublisher thePublisher = buildPublisher(config);
            SsfEventEmitter theEmitter = new SsfEventEmitter(theStore, theMinter, config, thePublisher);
            SsfReceiverService theReceiver = null;
            PollReceiverClient thePollClient = null;
            ReceiverStream theStream = null;
            if (receiverAllowed && receiverMayRun(config)) {
                theReceiver = new SsfReceiverService(receiverVerifier(config,
                        JwksHttpSource.of(config.receiverJwksUrl(),
                                config.receiverJwksCacheSeconds(), config.receiverInsecureTls())));
                LOGGER.info((Object) ("SSF receiver: accepting SETs from " + config.receiverExpectedIssuer()
                        + " (jwks " + config.receiverJwksUrl() + ")"));
                if (config.receiverInstanceRegistry()) {
                    installInstanceRegistryHandler(theReceiver, theStore, config);
                }
                ReceiverBearer bearer = receiverBearer(config);
                if (config.receiverTransmitterConfigurationUrl() != null) {
                    theStream = new ReceiverStream(ReceiverStreamClient.httpTransport(bearer, config.receiverInsecureTls()),
                            ReceiverStream.plan(config), theReceiver);
                }
                String pollUrl = config.receiverPollUrl();
                ReceiverStream managed = theStream;
                if (pollUrl != null || (managed != null && config.receiverPushEndpointUrl() == null)) {
                    thePollClient = new PollReceiverClient(theReceiver,
                            PollReceiverClient.httpTransport(pollUrl != null ? () -> pollUrl : managed::pollUrl,
                                    bearer, config.receiverInsecureTls()),
                            config.pollMaxEvents());
                }
            } else if (!receiverAllowed && config.receiverConfigured()) {
                LOGGER.info((Object) "SSF receiver: not started, its component (SSF_RECEIVER) is switched off or refused");
            }
            state = new State(config, theStore, theMinter, new StreamManagementService(theStore, theMinter, config, thePublisher),
                    theEmitter, new ScimSubjectService(theStore, theEmitter, config), new SsfEmitService(theStore, theEmitter, config),
                    new PushDeliveryService(theStore, config, PushDeliveryService.httpClient()), thePublisher, theReceiver,
                    thePollClient, buildIntrospectionAuthenticator(config), theStream);
            return true;
        }
    }

    /** Whether the shared state is published. */
    public static boolean isConfigured() {
        return state != null;
    }

    /**
     * Bring the transmitter up: {@link #configure}, then the servlet layer's wiring ({@code afterConfigure}: the
     * receiver's PF actions and polling, the audit source), then the push loop. Idempotent: once the state is
     * published a later call does nothing. Throws what {@link #configure} throws - the caller, the {@code SSF}
     * component's start function, records it on the part and never lets it reach the container. A failure of the
     * wiring is logged, and the loop still starts.
     */
    public static void start(SsfConfiguration config, boolean receiverAllowed, Runnable afterConfigure) {
        if (!configure(config, receiverAllowed)) {
            return;
        }
        try {
            afterConfigure.run();
        } catch (RuntimeException e) {
            LOGGER.error((Object) ("SSF transmitter wiring failed after configuration: " + e), e);
        }
        startPushDelivery();
    }

    /**
     * One ERROR per failed start, naming the cause chain with the {@code jdbcUrl} replaced: a JDBC URL can
     * carry a password, and the messages repeat it ({@code DriverManager}'s "No suitable driver found for"
     * and the store factory's missing-driver message both end with it). The exception goes with the line,
     * for its stack trace, on the first failure only - the supervisor's retries would otherwise repeat it for as
     * long as the store is down - and never when a {@code jdbcUrl} is set, because a logged exception prints
     * its messages as they are. Returns the exception that was logged with the line, or null.
     */
    public static Throwable logBootFailure(SsfConfiguration config, RuntimeException e) {
        String line = "SSF transmitter NOT started: " + describe(e, config.jdbcUrl()) + ". The SSF endpoints "
                + "answer 503 and nothing is delivered until it starts; the supervisor starts it again with backoff";
        Throwable stack;
        synchronized (LOCK) {
            stack = bootFailureLogged || config.jdbcUrl() != null ? null : e;
            bootFailureLogged = true;
        }
        if (stack == null) {
            LOGGER.error((Object) line);
        } else {
            LOGGER.error((Object) line, stack);
        }
        return stack;
    }

    /** The cause chain on one line, at most eight deep, with {@code jdbcUrl} replaced wherever it appears. */
    public static String describe(Throwable e, String jdbcUrl) {
        StringBuilder chain = new StringBuilder();
        int depth = 0;
        for (Throwable t = e; t != null && depth < 8; t = t.getCause(), depth++) {
            chain.append(depth == 0 ? "" : "; caused by ").append(t.getClass().getName());
            if (t.getMessage() != null) {
                chain.append(": ").append(t.getMessage());
            }
        }
        String line = chain.toString();
        return jdbcUrl == null || jdbcUrl.isEmpty() ? line : line.replace(jdbcUrl, "<jdbcUrl>");
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
        State local = state;
        if (local != null) {
            local.pushDeliveryService().start();
        }
    }

    /** Start the receiver's remote-poll loop when {@code receiverPollUrl} is configured (idempotent). */
    public static void startReceiverPolling() {
        State local = state;
        if (local != null && local.pollReceiverClient() != null) {
            local.pollReceiverClient().start(local.configuration().receiverPollIntervalSeconds());
        }
    }

    /**
     * The receiver's own stream at its transmitter, when {@code OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL} is set
     * and the receiver was built; null otherwise, and before the state is published.
     */
    public static ReceiverStream receiverStream() {
        State local = state;
        return local == null ? null : local.receiverStream();
    }

    /**
     * Install a receiver authenticator (tests inject a fake), which {@link #receiverAuthenticator()} answers instead
     * of the PF-introspection authenticator {@link #configure} built; null removes it.
     */
    public static void installReceiverAuthenticator(ReceiverAuthenticator authenticator) {
        installedAuthenticator = authenticator;
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
                new CaepSignalApplier(new IomInstanceRegistry(ldmStore.dataSource())), config.receiverLocalIssuers()));
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
        // The URL itself is not logged: a JDBC URL can carry a password.
        String source = config.jdbcUrl() != null ? "the jdbcUrl setting" : "JDBC data store '" + config.dataStoreId() + "'";
        LOGGER.info((Object) ("SSF store: " + source + ", dialect '" + config.storeDialect() + "' (cluster-safe, durable)"));
        return factory.create(config);
    }

    /** The published state, or {@link #NOT_CONFIGURED}. */
    private static State published() {
        State local = state;
        if (local == null) {
            throw new IllegalStateException(NOT_CONFIGURED);
        }
        return local;
    }

    public static SsfConfiguration configuration() {
        return published().configuration();
    }

    public static SsfStore store() {
        return published().store();
    }

    public static SetMinter minter() {
        return published().minter();
    }

    public static StreamManagementService streamService() {
        return published().streamService();
    }

    public static SsfEventEmitter eventEmitter() {
        return published().eventEmitter();
    }

    public static ScimSubjectService scimSubjectService() {
        return published().scimSubjectService();
    }

    public static SsfEmitService emitService() {
        return published().emitService();
    }

    public static PushDeliveryService pushDeliveryService() {
        return published().pushDeliveryService();
    }

    /** The inbound-SET receiver pipeline; null when the receiver is not configured or the transmitter is not started. */
    public static SsfReceiverService receiverService() {
        State local = state;
        return local == null ? null : local.receiverService();
    }

    /** The receiver authenticator: an installed one (tests), or the PF-introspection authenticator {@link #configure} built. */
    public static ReceiverAuthenticator receiverAuthenticator() {
        ReceiverAuthenticator installed = installedAuthenticator;
        return installed != null ? installed : published().receiverAuthenticator();
    }

    /** The receiver authenticator {@code cfg} describes: introspection, holding an answer's {@code aud} to the issuer. */
    static ReceiverAuthenticator buildIntrospectionAuthenticator(SsfConfiguration cfg) {
        if (!cfg.receiverAuthConfigured()) {
            LOGGER.warn((Object) "SSF receiver auth: introspection client not configured; all receiver "
                    + "requests will be rejected until introspectionClientId/Secret are set");
            return token -> AuthContext.inactive();
        }
        return PfIntrospectionReceiverAuthenticator.forEndpoint(
                cfg.introspectionEndpoint(), cfg.introspectionClientId(),
                cfg.introspectionClientSecret(), cfg.introspectionInsecureTls(), cfg.issuer());
    }

    /** Test hook: stop the loops and forget the published state, so a fresh {@link #configure} takes effect. */
    static void resetForTests() {
        synchronized (LOCK) {
            bootFailureLogged = false;
            State local = state;
            state = null;
            if (local != null) {
                local.pushDeliveryService().stop();
                local.setPublisher().close();
                if (local.pollReceiverClient() != null) {
                    local.pollReceiverClient().stop();
                }
            }
            installedAuthenticator = null;
            storeFactory = null;
        }
    }
}
