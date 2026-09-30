/*
 * The start-up scan of every client's attestation properties.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.domain.Client;

/**
 * Reads every client's {@code attestation_*} properties once after the token-endpoint filter starts, and again every
 * {@link #INTERVAL}, and records the clients whose properties are refused as a {@code DEGRADED} part of
 * {@code ATTESTATION_AUTH} ({@value #PART}), naming the clients and the properties, never the values, in the health
 * detail. Each client first found refused is an {@code attestation.policy.invalid} event. An operator finds a client
 * the upgrade to strict, tighten-only properties refuses here before its first request does.
 *
 * <p>It runs on this copy's managed executor ({@link ManagedExecutors}), started from the filter's start function, so
 * only the webapp's copy runs it: the engine's copy, where the OGNL criterion runs, has no start-up hook and never
 * starts one. It never blocks the filter's start and never throws. A {@code attestation_expected_htu} is checked for
 * its form here; whether it names a URL this server answers at depends on the request's issuer, and is checked there.
 */
public final class AttestationPolicyScan {
    private static final Log LOGGER = LogFactory.getLog(AttestationPolicyScan.class);

    /** The executor's name. */
    public static final String JOB = "attestation-policy-scan";
    /** The part of {@code ATTESTATION_AUTH} the scan records its findings as. */
    public static final String PART = "AttestationPolicyScan";
    /** How often the scan runs again. */
    public static final Duration INTERVAL = Duration.ofMinutes(10);
    /** How many client ids the health detail names before it counts the rest. */
    static final int NAMED = 20;

    private static final Object LOCK = new Object();
    private static final AtomicInteger STARTS = new AtomicInteger();
    private static ManagedExecutor executor;
    private static volatile Set<String> refused = Set.of();

    private AttestationPolicyScan() {
    }

    /**
     * Starts the scan in this copy, once: a later call while it runs does nothing. Never throws; a scan that cannot
     * start leaves its part {@code DEGRADED}, saying so.
     */
    public static void start(ClientStore store, AttestationPolicyResolver resolver) {
        try {
            synchronized (LOCK) {
                if (executor != null && !executor.isClosed()) {
                    return;
                }
                ComponentParts.Part part = Startup.begin(Startup.ATTESTATION_AUTH, PART);
                Optional<ManagedExecutor> started = ManagedExecutors.every(JOB, Duration.ZERO, INTERVAL,
                        () -> AttestationPolicyScan.runOnce(part, store, resolver));
                if (started.isEmpty()) {
                    part.degraded("the scan of client attestation properties could not start in this copy");
                    return;
                }
                executor = started.get();
                STARTS.incrementAndGet();
            }
        } catch (RuntimeException e) {
            LOGGER.warn((Object) "the scan of client attestation properties could not start", e);
        }
    }

    /** How many times this copy has started the scan: the engine copy's is always 0. */
    public static int starts() {
        return STARTS.get();
    }

    /**
     * One scan: every client's properties parsed and applied to the server's policy, the part {@code READY} when none is
     * refused and {@code DEGRADED} naming the refused ones otherwise. Never throws.
     *
     * @return the ids of the clients refused, or null when the clients could not be read
     */
    static List<String> runOnce(ComponentParts.Part part, ClientStore store, AttestationPolicyResolver resolver) {
        try {
            Collection<Client> clients = store.getAll();
            ClientAttestationConfig global = ClientAttestationUtils.globalPolicy(null, null);
            List<String> bad = new ArrayList<>();
            List<String> named = new ArrayList<>();
            Set<String> before = refused;
            for (Client client : clients == null ? List.<Client>of() : clients) {
                String id = client.getClientId();
                try {
                    resolver.parse(id, AttestationPolicyResolver.properties(client)).apply(global, Set.of());
                } catch (AttestationPolicyException e) {
                    bad.add(id);
                    if (named.size() < NAMED) {
                        named.add(id + " (" + e.property() + ")");
                    }
                    if (!before.contains(id)) {
                        LOGGER.warn((Object) ("attestation policy: " + e.getMessage() + "; the client is refused (401 invalid_client)"));
                        AttestationEvents.policyInvalid(AttestationEvents.SCAN, e);
                    }
                }
            }
            refused = Set.copyOf(bad);
            if (bad.isEmpty()) {
                part.ready();
            } else {
                part.degraded(bad.size() + " client(s) have attestation properties that are refused, and are answered 401"
                        + " invalid_client until they are fixed: " + String.join(", ", named)
                        + (bad.size() > named.size() ? " and " + (bad.size() - named.size()) + " more" : ""));
            }
            return bad;
        } catch (Exception | LinkageError e) {
            part.degraded("the scan of client attestation properties could not read PingFederate's clients ("
                    + e.getClass().getSimpleName() + ")");
            return null;
        }
    }

    /** Tests only: stop this copy's scan and forget what it found. */
    static void resetForTests() {
        synchronized (LOCK) {
            if (executor != null) {
                executor.close();
            }
            executor = null;
            refused = Set.of();
        }
    }
}
