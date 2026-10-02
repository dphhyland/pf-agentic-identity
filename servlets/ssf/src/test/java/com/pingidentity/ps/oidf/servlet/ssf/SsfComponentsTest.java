/*
 * The SSF start functions: every outcome is the part's state, a failed dependency is retried to ready, and the store is refused where production says.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Supervisor;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.ssf.InMemorySsfStore;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import com.pingidentity.ps.oidf.ssf.SsfSupportTestAccess;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfComponentsTest {

    private static final Map<String, String> ISSUER = Map.of("OIDF_SSF_ISSUER", "https://op.example.com");
    private static final Map<String, String> RECEIVER = Map.of("OIDF_SSF_ISSUER", "https://op.example.com",
            "OIDF_SSF_RECEIVER_EXPECTED_ISSUER", "https://transmitter.example.com",
            "OIDF_SSF_RECEIVER_AUDIENCE", "https://op.example.com", "OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN", "t0ken");

    /** The supervisor's retries, run by hand: the fake clock. */
    private final List<Runnable> retries = new ArrayList<>();
    private final List<Duration> waits = new ArrayList<>();
    private final Map<String, ComponentSwitches.Kind> switches = new HashMap<>();
    private final List<String> errors = new ArrayList<>();
    private final AtomicInteger opened = new AtomicInteger();
    private ComponentParts parts;

    @BeforeEach
    void fresh() {
        SsfSupportTestAccess.reset();
        SsfHttp.resetForTests();
        SsfComponents.resetForTests();
        ProfileRefusals.resetForTests();
        Supervisor supervisor = new Supervisor((delay, task) -> {
            this.waits.add(delay);
            this.retries.add(task);
            return true;
        }, () -> 0.5, component -> { });
        this.parts = new ComponentParts(new ComponentRegistry(), Clock.fixed(Instant.parse("2026-09-30T00:00:00Z"), ZoneOffset.UTC),
                component -> new ComponentSwitches.Verdict(component, ComponentSwitches.SWITCHES.getOrDefault(component, ""),
                        this.switches.getOrDefault(component, ComponentSwitches.Kind.INFERRED), "test"), supervisor);
    }

    @AfterEach
    void cleanUp() {
        SsfSupportTestAccess.reset();
        SsfHttp.resetForTests();
        SsfComponents.resetForTests();
        ProfileRefusals.resetForTests();
    }

    private static Settings settings(Map<String, String> env) {
        return Settings.of(Catalogue.load(SsfComponentsTest.class.getClassLoader(), "ssf-transmitter"),
                Sources.of(env::get, name -> null, name -> null));
    }

    private static void profile(DeploymentProfile profile) {
        ProfileRefusals.publish(new ProfileAudit.Result(profile, List.of(), List.of()));
    }

    private SsfComponents.Context context(DeploymentProfile profile, SsfSupport.StoreFactory stores) {
        return context(profile, AcceptedRisks.none(), stores);
    }

    private SsfComponents.Context context(DeploymentProfile profile, AcceptedRisks risks, SsfSupport.StoreFactory stores) {
        return new SsfComponents.Context(profile, risks, true, config -> {
            this.opened.incrementAndGet();
            return stores.create(config);
        }, this.errors::add);
    }

    private SsfComponents.Context development() {
        profile(DeploymentProfile.DEVELOPMENT);
        return context(DeploymentProfile.DEVELOPMENT, config -> new InMemorySsfStore());
    }

    private ComponentParts.Part transmitter(Map<String, String> env, SsfComponents.Context context) {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        Settings settings = settings(env);
        part.start(() -> SsfComponents.transmitter(part, settings, context));
        return part;
    }

    /** The first retry the supervisor scheduled, run now. */
    private void retry() {
        assertFalse(this.retries.isEmpty(), "a retry is scheduled");
        this.retries.remove(0).run();
    }

    private static int gate(ComponentParts.Part part) throws IOException {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        if (!ComponentGate.oauthEndpoint(part, resp)) {
            return 0;
        }
        verify(resp, never()).setStatus(200);
        for (int status : new int[] {503, 404}) {
            try {
                verify(resp).setStatus(status);
                return status;
            } catch (AssertionError notThis) {
                // the other one
            }
        }
        return -1;
    }

    @Test
    void aStartedTransmitterIsReadyAndPublishedWhole() throws IOException {
        ComponentParts.Part part = transmitter(ISSUER, development());

        assertEquals(ComponentState.READY, part.status().state());
        assertTrue(SsfSupport.isConfigured());
        assertTrue(SsfSupport.pushDeliveryService().isRunning());
        assertEquals(0, gate(part), "the gate lets requests through");
        assertEquals(List.of(), this.errors);
    }

    @Test
    void withTheSwitchOffTheTransmitterIsDisabledAndNothingRuns() throws IOException {
        this.switches.put(Startup.SSF, ComponentSwitches.Kind.DISABLED);

        ComponentParts.Part part = transmitter(ISSUER, development());

        assertEquals(ComponentState.DISABLED, part.status().state());
        assertEquals(0, this.opened.get(), "the start function never ran");
        assertFalse(SsfSupport.isConfigured());
        assertEquals(404, gate(part), "a disabled servlet answers 404");
    }

    @Test
    void noIssuerIsDisabledWhenInferred() {
        ComponentParts.Part part = transmitter(Map.of(), development());

        assertEquals(ComponentState.DISABLED, part.status().state());
        assertEquals(List.of(), this.errors, "not configured is INFO, in development only");
    }

    @Test
    void noIssuerWithTheSwitchOnIsAFailedConfigurationAtError() {
        this.switches.put(Startup.SSF, ComponentSwitches.Kind.ENABLED);

        ComponentParts.Part part = transmitter(Map.of(), context(DeploymentProfile.PRODUCTION, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("OIDF_SSF_ENABLED=true but OIDF_SSF_ISSUER is not set", part.status().reason());
        assertEquals(List.of("SSF transmitter NOT started: OIDF_SSF_ENABLED=true but OIDF_SSF_ISSUER is not set"), this.errors);
    }

    /** Findings F-0191 and F-0237: a typo in a configured transmitter is a failed configuration naming the setting, not "not configured". */
    @Test
    void aValueThatDoesNotParseIsAFailedConfigurationNamingTheSetting() throws IOException {
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS", "lots");

        ComponentParts.Part part = transmitter(env, development());

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS must be a whole number, not lots", part.status().reason());
        assertEquals(1, this.errors.size());
        assertTrue(this.errors.get(0).startsWith("SSF transmitter NOT started: OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS must be a whole number"),
                this.errors.get(0));
        assertEquals(0, this.opened.get(), "no store was opened");
        assertTrue(this.retries.isEmpty(), "a configuration is never retried");
        assertEquals(503, gate(part));
    }

    @Test
    void aCombinationTheConfigurationRefusesIsAFailedConfigurationNamingBothSettings() {
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_PROVISIONER_SCOPE", "ssf.manage");

        ComponentParts.Part part = transmitter(env, development());

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertTrue(part.status().reason().startsWith("OIDF_SSF_PROVISIONER_SCOPE must not be the receiver scope (OIDF_SSF_RECEIVER_SCOPE"),
                part.status().reason());
    }

    /**
     * A database that is down at deploy: FAILED_DEPENDENCY, 503 on the endpoints, and the supervisor's retry brings it up
     * once the database is back - the same start function, run again.
     */
    @Test
    void aStoreThatIsDownIsAFailedDependencyRetriedToReady() throws IOException {
        profile(DeploymentProfile.DEVELOPMENT);
        AtomicInteger calls = new AtomicInteger();
        String url = "jdbc:postgresql://db.example.com/ssf?password=hunter2";
        SsfComponents.Context context = context(DeploymentProfile.DEVELOPMENT, config -> {
            if (calls.incrementAndGet() <= 2) {
                throw new IllegalStateException("the SSF store's database could not be reached",
                        new SQLException("Connection to " + url + " refused"));
            }
            return new InMemorySsfStore();
        });
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_JDBC_URL", url);

        ComponentParts.Part part = transmitter(env, context);

        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
        assertTrue(part.status().reason().startsWith("the SSF store could not be opened: "), part.status().reason());
        assertTrue(part.status().reason().contains("<jdbcUrl>") && !part.status().reason().contains("hunter2"), part.status().reason());
        assertFalse(SsfSupport.isConfigured(), "nothing published");
        assertEquals(503, gate(part), "the endpoints answer 503 in between");
        assertEquals(1, this.retries.size());

        retry();
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state(), "still down");
        assertEquals(503, gate(part));
        assertEquals(1, this.retries.size(), "and the supervisor tries again");
        assertTrue(this.waits.get(1).compareTo(this.waits.get(0)) > 0, "after a longer wait: " + this.waits);

        retry();
        assertEquals(ComponentState.READY, part.status().state());
        assertTrue(SsfSupport.isConfigured());
        assertTrue(SsfSupport.pushDeliveryService().isRunning());
        assertEquals(0, gate(part));
        assertTrue(this.retries.isEmpty(), "and stops");
        assertEquals(3, calls.get());
    }

    @Test
    void aStoreRefusedForItsConfigurationIsNotRetried() {
        profile(DeploymentProfile.DEVELOPMENT);
        SsfComponents.Context context = context(DeploymentProfile.DEVELOPMENT, config -> {
            throw new IllegalArgumentException("a jdbc:h2: SSF store URL is not supported");
        });
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_JDBC_URL", "jdbc:h2:mem:ssf");

        ComponentParts.Part part = transmitter(env, context);

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertTrue(this.retries.isEmpty());
    }

    /**
     * Plan item H-SSF-3. SSF 1.0 §7.1: the issuer is a "URL using the https scheme with no query or fragment
     * component", and each endpoint it advertises "MUST use HTTP over TLS". An http issuer is FAILED_CONFIG in
     * production, before any store is opened, and never retried.
     */
    @Test
    @Requirement("SSF §7.1")
    void anHttpIssuerIsAFailedConfigurationInProduction() throws IOException {
        profile(DeploymentProfile.PRODUCTION);
        AcceptedRisks risks = AcceptedRisks.parse("in-memory-state", LocalDate.now(ZoneOffset.UTC));

        ComponentParts.Part part = transmitter(Map.of("OIDF_SSF_ISSUER", "http://op.example.com"),
                context(DeploymentProfile.PRODUCTION, risks, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertTrue(part.status().reason().startsWith("OIDF_SSF_ISSUER is http: SSF 1.0 §7.1 requires an https issuer"),
                part.status().reason());
        assertEquals(1, this.errors.size());
        assertTrue(this.errors.get(0).startsWith("SSF transmitter NOT started: OIDF_SSF_ISSUER is http"), this.errors.get(0));
        assertEquals(0, this.opened.get(), "no store was opened");
        assertTrue(this.retries.isEmpty());
        assertEquals(503, gate(part));
    }

    /** The development profile's escape: an http issuer starts, with a WARN. */
    @Test
    @Requirement("SSF §7.1")
    void anHttpIssuerStartsInDevelopment() {
        ComponentParts.Part part = transmitter(Map.of("OIDF_SSF_ISSUER", "http://localhost:9031"), development());

        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(List.of(), this.errors);
        assertEquals("http://localhost:9031/ssf/streams", SsfSupport.configuration().configurationEndpoint());
    }

    /** What SSF 1.0 §7.1 rules out whatever the profile: no host, a query, a fragment, a scheme that is not http(s). */
    @Test
    @Requirement("SSF §7.1")
    void anIssuerThatIsNoHttpsUrlIsAFailedConfigurationInEitherProfile() {
        SsfComponents.Context development = development();
        for (String issuer : List.of("https://op.example.com?tenant=a", "https://op.example.com#x", "urn:example:op", "ftp://op.example.com",
                "https:///nohost", "https://op example.com")) {
            String problem = SsfComponents.issuerProblem(issuer, development);
            assertTrue(problem != null && problem.startsWith("OIDF_SSF_ISSUER "), issuer + ": " + problem);
        }
        ComponentParts.Part part = transmitter(Map.of("OIDF_SSF_ISSUER", "https://op.example.com?tenant=a"), development);
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("OIDF_SSF_ISSUER must be an https URL with a host and no query or fragment (SSF 1.0 §7.1)", part.status().reason());
    }

    @Test
    void anHttpsIssuerIsAcceptedInProduction() {
        assertEquals(null, SsfComponents.issuerProblem("https://op.example.com/tenant-a", context(DeploymentProfile.PRODUCTION,
                config -> new InMemorySsfStore())));
    }

    @Test
    void anInMemoryStoreIsRefusedInProductionWithoutTheRisk() throws IOException {
        profile(DeploymentProfile.PRODUCTION);

        ComponentParts.Part part = transmitter(ISSUER, context(DeploymentProfile.PRODUCTION, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.REFUSED, part.status().state());
        assertTrue(part.status().reason().contains("in-memory-state") && part.status().reason().contains("OIDF_SSF_DATA_STORE_ID"),
                part.status().reason());
        assertFalse(SsfSupport.isConfigured());
        assertEquals(1, ProfileRefusals.codeRefusals().size(), "listed for the start-up audit");
        assertEquals(503, gate(part));
        assertTrue(this.retries.isEmpty(), "a refusal is never retried");
    }

    @Test
    void anInMemoryStoreRunsInProductionWithTheRiskAccepted() {
        profile(DeploymentProfile.PRODUCTION);
        AcceptedRisks risks = AcceptedRisks.parse("in-memory-state", LocalDate.now(ZoneOffset.UTC));

        ComponentParts.Part part = transmitter(ISSUER, context(DeploymentProfile.PRODUCTION, risks, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
    }

    @Test
    void anInMemoryStoreRunsInDevelopment() {
        ComponentParts.Part part = transmitter(ISSUER, development());

        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(List.of(), ProfileRefusals.codeRefusals(), "a WARN, not a refusal");
    }

    @Test
    void aJdbcUrlThatIsNotPostgresqlIsRefusedInProductionWithoutItsPassword() {
        profile(DeploymentProfile.PRODUCTION);
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_JDBC_URL", "jdbc:mysql://db.example.com/ssf?password=hunter2");

        ComponentParts.Part part = transmitter(env, context(DeploymentProfile.PRODUCTION, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.REFUSED, part.status().state());
        String reason = part.status().reason();
        assertTrue(reason.contains("OIDF_SSF_JDBC_URL names a jdbc:mysql: database"), reason);
        assertFalse(reason.contains("hunter2"), reason);
        assertEquals(0, this.opened.get(), "refused before anything connects");
    }

    @Test
    void aJdbcUrlThatIsNotPostgresqlIsUsedInDevelopment() {
        profile(DeploymentProfile.DEVELOPMENT);
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_JDBC_URL", "jdbc:mysql://db.example.com/ssf");

        ComponentParts.Part part = transmitter(env, context(DeploymentProfile.DEVELOPMENT, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(1, this.opened.get());
    }

    @Test
    void aSecondStartIsANoOp() {
        SsfComponents.Context context = development();
        transmitter(ISSUER, context);
        Object store = SsfSupport.store();
        ComponentParts.Part again = transmitter(ISSUER, context);

        assertEquals(ComponentState.READY, again.status().state());
        assertTrue(store == SsfSupport.store(), "the state is published once");
    }

    /**
     * Finding F-0295: a part the production profile refused when it registered runs no start, so nothing is configured,
     * and its gate answers 503 - the SSF servlets no longer serve past a refusal.
     */
    @Test
    void aRefusedPartConfiguresNothingAndItsServletsAnswer503() throws IOException {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        part.refused("refused by the production profile: OIDF_SSF_JDBC_URL is set");
        Settings settings = settings(ISSUER);
        SsfComponents.Context context = development();

        assertEquals(ComponentState.REFUSED, part.start(() -> SsfComponents.transmitter(part, settings, context)));

        assertFalse(SsfSupport.isConfigured(), "the start function never ran");
        SsfComponents.transmitterPart(part);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        assertTrue(SsfHttp.gate(resp));
        verify(resp).setStatus(503);
    }

    @Test
    void dependencyFailuresAreIoSqlTimeoutAndLinkage() {
        assertTrue(SsfComponents.dependency(new IllegalStateException("x", new SQLException("down"))));
        assertTrue(SsfComponents.dependency(new java.io.UncheckedIOException(new IOException("down"))));
        assertTrue(SsfComponents.dependency(new IllegalStateException(new java.util.concurrent.TimeoutException())));
        assertTrue(SsfComponents.dependency(new IllegalStateException(new NoClassDefFoundError("org/postgresql/Driver"))));
        assertTrue(SsfComponents.dependency(new IOException("down")));
        assertFalse(SsfComponents.dependency(new IllegalArgumentException("h2")));
        Throwable deep = new SQLException("at the bottom");
        for (int i = 0; i < 20; i++) {
            deep = new IllegalStateException("level " + i, deep);
        }
        assertFalse(SsfComponents.dependency(deep), "sixteen causes are followed, no more");
        RuntimeException loop = new RuntimeException("a");
        loop.initCause(new RuntimeException("b", loop));
        assertFalse(SsfComponents.dependency(loop), "a loop is cut");
    }

    @Test
    void noIssuerInProductionIsDisabledWithoutALine() {
        ComponentParts.Part part = transmitter(Map.of(), context(DeploymentProfile.PRODUCTION, config -> new InMemorySsfStore()));

        assertEquals(ComponentState.DISABLED, part.status().state());
        assertEquals(List.of(), this.errors);
    }

    /** PR-5's read-time refusal: a governed value from an init-param, which the start-up sweep cannot see. */
    @Test
    void aGovernedInitParamIsRefusedInProduction() {
        profile(DeploymentProfile.PRODUCTION);
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        Settings settings = Settings.of(Catalogue.load(SsfComponentsTest.class.getClassLoader(), "ssf-transmitter"),
                Sources.of(ISSUER::get, name -> null, Map.of("receiverInsecureTls", "true")::get));
        SsfComponents.Context context = context(DeploymentProfile.PRODUCTION,
                AcceptedRisks.parse("in-memory-state", LocalDate.now(ZoneOffset.UTC)), config -> new InMemorySsfStore());

        part.start(() -> SsfComponents.transmitter(part, settings, context));

        assertEquals(ComponentState.REFUSED, part.status().state());
        assertTrue(part.status().reason().contains("OIDF_SSF_RECEIVER_INSECURE_TLS"), part.status().reason());
    }

    /** A data store the factory finds is not PostgreSQL, under production: refused, not retried. */
    @Test
    void aStoreTheFactoryRefusesIsRefused() {
        profile(DeploymentProfile.PRODUCTION);
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_DATA_STORE_ID", "pf-ds");

        ComponentParts.Part part = transmitter(env, context(DeploymentProfile.PRODUCTION, config -> {
            ProfileRefusals.refuse(Startup.SSF, "the SSF store's database (PingFederate data store 'pf-ds') is MySQL, not PostgreSQL");
            return new InMemorySsfStore();
        }));

        assertEquals(ComponentState.REFUSED, part.status().state());
        assertTrue(this.retries.isEmpty());
        assertFalse(SsfSupport.isConfigured());
    }

    // ---- the receiver ----

    private ComponentParts.Part receiver(Optional<ComponentStatus> ssf) {
        ComponentParts.Part part = this.parts.begin(Startup.SSF_RECEIVER, "SsfReceiverServlet");
        part.start(() -> SsfComponents.receiver(part, () -> ssf));
        return part;
    }

    private Optional<ComponentStatus> ssf() {
        return this.parts.component(Startup.SSF);
    }

    @Test
    void aConfiguredReceiverIsReadyOnceTheTransmitterBuiltIt() {
        transmitter(RECEIVER, development());

        assertEquals(ComponentState.READY, receiver(ssf()).status().state());
    }

    @Test
    void theReceiverIsDisabledWhenNoExpectedIssuerIsSet() {
        transmitter(ISSUER, development());

        assertEquals(ComponentState.DISABLED, receiver(ssf()).status().state());
    }

    @Test
    void aReceiverMissingItsAudienceOrTokenIsAFailedConfigurationNamingThem() {
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_RECEIVER_EXPECTED_ISSUER", "https://transmitter.example.com");
        transmitter(env, development());

        ComponentParts.Part part = receiver(ssf());

        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("the SSF receiver is not started: [OIDF_SSF_RECEIVER_AUDIENCE, OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN] must be set",
                part.status().reason());
    }

    @Test
    void aReceiverTheTransmitterDidNotBuildIsNotConfigured() {
        profile(DeploymentProfile.DEVELOPMENT);
        ComponentParts.Part tx = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        Settings settings = settings(RECEIVER);
        SsfComponents.Context noReceiver = new SsfComponents.Context(DeploymentProfile.DEVELOPMENT, AcceptedRisks.none(), false,
                config -> new InMemorySsfStore(), this.errors::add);
        tx.start(() -> SsfComponents.transmitter(tx, settings, noReceiver));

        assertEquals(ComponentState.DISABLED, receiver(ssf()).status().state());
    }

    @Test
    void theReceiverWaitsForATransmitterThatIsDownAndComesUpWithIt() {
        profile(DeploymentProfile.DEVELOPMENT);
        AtomicInteger calls = new AtomicInteger();
        SsfComponents.Context context = context(DeploymentProfile.DEVELOPMENT, config -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException(new SQLException("down"));
            }
            return new InMemorySsfStore();
        });
        Map<String, String> env = new HashMap<>(RECEIVER);
        env.put("OIDF_SSF_DATA_STORE_ID", "pf-ds");
        ComponentParts.Part tx = transmitter(env, context);
        ComponentParts.Part rx = receiver(ssf());

        assertEquals(ComponentState.FAILED_DEPENDENCY, rx.status().state());
        assertTrue(rx.status().reason().startsWith(SsfComponents.WAITING), rx.status().reason());
        assertEquals(2, this.retries.size(), "both are retried");

        retry(); // the transmitter
        assertEquals(ComponentState.READY, tx.status().state());
        retry(); // the receiver
        assertEquals(ComponentState.READY, rx.status().state());
    }

    /** Seen on the rig (2026-09-30): a transmitter down on its database took an unconfigured receiver down with it. */
    @Test
    void aReceiverNobodyConfiguredIsDisabledWhateverBecameOfTheTransmitter() {
        profile(DeploymentProfile.DEVELOPMENT);
        Map<String, String> env = new HashMap<>(ISSUER);
        env.put("OIDF_SSF_DATA_STORE_ID", "pf-ds");
        transmitter(env, context(DeploymentProfile.DEVELOPMENT, config -> {
            throw new IllegalStateException(new SQLException("down"));
        }));
        assertEquals(ComponentState.DISABLED, receiver(ssf()).status().state(), "the transmitter failed on a dependency");

        Map<String, String> bad = new HashMap<>(ISSUER);
        bad.put("OIDF_SSF_SIGNING_ALGORITHM", "ES512");
        SsfSupportTestAccess.reset();
        transmitter(bad, development());
        assertEquals(ComponentState.DISABLED, receiver(ssf()).status().state(), "the transmitter failed on its configuration");

        this.switches.put(Startup.SSF_RECEIVER, ComponentSwitches.Kind.ENABLED);
        ComponentParts.Part on = receiver(ssf());
        assertEquals(ComponentState.FAILED_CONFIG, on.status().state(), "switched on with nothing to run");
        assertEquals("OIDF_SSF_RECEIVER_ENABLED=true but OIDF_SSF_RECEIVER_EXPECTED_ISSUER is not set", on.status().reason());
    }

    @Test
    void theReceiverTakesTheTransmittersAnswerWhenItIsOffOrFailedOnItsConfiguration() {
        ComponentRegistry registry = new ComponentRegistry();
        ComponentRegistry.Component off = registry.register(Startup.SSF, false, "");
        assertEquals(ComponentState.DISABLED, receiver(registry.status(Startup.SSF)).status().state());

        this.switches.put(Startup.SSF_RECEIVER, ComponentSwitches.Kind.ENABLED);
        assertEquals(ComponentState.FAILED_CONFIG, receiver(registry.status(Startup.SSF)).status().state(),
                "switched on inside a transmitter that is off");
        this.switches.remove(Startup.SSF_RECEIVER);

        ComponentRegistry failed = new ComponentRegistry();
        failed.register(Startup.SSF, true, "").failedConfig("OIDF_SSF_SET_TTL_SECONDS must be a whole number, not x");
        ComponentParts.Part part = receiver(failed.status(Startup.SSF));
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertTrue(part.status().reason().contains("OIDF_SSF_SET_TTL_SECONDS"), part.status().reason());
        assertTrue(off != null);
    }

    @Test
    void theReceiverMayRunUnlessItsSwitchSaysNoOrProductionRefusesIt() {
        assertTrue(SsfComponents.receiverAllowed(this.parts));
        this.switches.put(Startup.SSF_RECEIVER, ComponentSwitches.Kind.ENABLED);
        assertTrue(SsfComponents.receiverAllowed(this.parts));
        this.switches.remove(Startup.SSF_RECEIVER);
        ProfileRefusals.publish(new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(new ProfileAudit.Violation(
                ProfileAudit.Kind.FORBIDDEN, "OIDF_SSF_RECEIVER_INSECURE_TLS", "OIDF_SSF_RECEIVER_INSECURE_TLS=true", "unset it",
                List.of(Startup.SSF_RECEIVER))), List.of()));
        assertFalse(SsfComponents.receiverAllowed(this.parts), "refused by the production profile");
        ProfileRefusals.resetForTests();
        this.switches.put(Startup.SSF_RECEIVER, ComponentSwitches.Kind.DISABLED);
        assertFalse(SsfComponents.receiverAllowed(this.parts));
        this.switches.put(Startup.SSF_RECEIVER, ComponentSwitches.Kind.FAILED_CONFIG);
        assertFalse(SsfComponents.receiverAllowed(this.parts));
    }

    @Test
    void settingOfNamesTheCatalogueEntry() {
        assertEquals("OIDF_SSF_RECEIVER_AUDIENCE", SsfComponents.settingOf("receiverAudience"));
        assertEquals("OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN", SsfComponents.settingOf("receiverEndpointAuthToken"));
        assertEquals("other", SsfComponents.settingOf("other"));
    }

    // ---- the receiver's own stream (H-SSF-1) ----

    /** A stub transmitter: its metadata, a stream list and a create, each answered with the status it is given. */
    private com.sun.net.httpserver.HttpServer transmitter(int[] status, String issuer) throws IOException {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            String path = exchange.getRequestURI().getPath();
            String body;
            if (path.endsWith("/ssf-configuration")) {
                body = "{\"issuer\":\"" + issuer + "\",\"configuration_endpoint\":\"" + base + "/streams\"}";
            } else if ("GET".equals(exchange.getRequestMethod())) {
                body = "[]";
            } else {
                body = "{\"stream_id\":\"s-1\",\"iss\":\"" + issuer + "\",\"aud\":\"https://op.example.com\","
                        + "\"delivery\":{\"method\":\"urn:ietf:rfc:8936\",\"endpoint_url\":\"" + base + "/poll\"}}";
            }
            byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status[0], bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }

    private Map<String, String> managed(com.sun.net.httpserver.HttpServer server) {
        Map<String, String> env = new HashMap<>(RECEIVER);
        env.put("OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL", "http://127.0.0.1:" + server.getAddress().getPort()
                + "/.well-known/ssf-configuration");
        env.put("OIDF_SSF_RECEIVER_POLL_TOKEN", "pt");
        return env;
    }

    @Test
    void aReceiverThatManagesItsStreamIsReadyOnceTheStreamIsSetUp() throws IOException {
        com.sun.net.httpserver.HttpServer server = transmitter(new int[] {200}, "https://transmitter.example.com");
        try {
            transmitter(managed(server), development());
            assertEquals(ComponentState.READY, receiver(ssf()).status().state());
            assertEquals("s-1", SsfSupport.receiverStream().setup().streamId());
            assertEquals("http://127.0.0.1:" + server.getAddress().getPort() + "/poll", SsfSupport.receiverStream().pollUrl());
        } finally {
            server.stop(0);
        }
    }

    /** A transmitter that refuses leaves the receiver waiting on a dependency, retried until it answers. */
    @Test
    void aTransmitterThatRefusesLeavesTheReceiverFailedOnADependencyAndItIsRetried() throws IOException {
        int[] status = {503};
        com.sun.net.httpserver.HttpServer server = transmitter(status, "https://transmitter.example.com");
        try {
            transmitter(managed(server), development());
            ComponentParts.Part rx = receiver(ssf());
            assertEquals(ComponentState.FAILED_DEPENDENCY, rx.status().state());
            assertTrue(rx.status().reason().startsWith("the receiver's stream could not be set up at the transmitter"),
                    rx.status().reason());
            assertEquals(null, SsfSupport.receiverStream().setup(), "no stream recorded");
            status[0] = 200;
            retry();
            assertEquals(ComponentState.READY, rx.status().state());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void aTransmitterOfAnotherIssuerIsAFailedConfiguration() throws IOException {
        com.sun.net.httpserver.HttpServer server = transmitter(new int[] {200}, "https://evil.example.com");
        try {
            transmitter(managed(server), development());
            ComponentParts.Part rx = receiver(ssf());
            assertEquals(ComponentState.FAILED_CONFIG, rx.status().state());
            assertTrue(rx.status().reason().contains("SSF 1.0 §7.2.4"), rx.status().reason());
            assertTrue(this.retries.isEmpty(), "a setting to correct, not a dependency to wait for");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void anInterruptedSetUpKeepsTheInterrupt() throws Exception {
        ComponentParts.Part part = this.parts.begin(Startup.SSF_RECEIVER, "SsfReceiverServlet");
        com.pingidentity.ps.oidf.ssf.ReceiverStream stream = new com.pingidentity.ps.oidf.ssf.ReceiverStream((m, u, b) -> {
            throw new InterruptedException("stopping");
        }, new com.pingidentity.ps.oidf.ssf.ReceiverStreamClient.Plan("https://tx/.well-known/ssf-configuration", "https://tx",
                "aud", List.of(), null, null), new com.pingidentity.ps.oidf.ssf.SsfReceiverService(
                        new com.pingidentity.ps.oidf.signals.SetVerifier("https://tx", null, refresh -> List.of())));
        part.start(() -> SsfComponents.receiverStream(part, stream));
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
        assertTrue(Thread.interrupted(), "the interrupt is kept");
        SsfComponents.receiverStream(part, null);
    }
}
