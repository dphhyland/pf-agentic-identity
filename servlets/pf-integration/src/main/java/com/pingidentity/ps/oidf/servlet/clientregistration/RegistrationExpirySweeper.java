/*
 * Disables federation clients whose registration has expired.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.domain.Client;

/**
 * OpenID Federation 1.0 §12.3 says a registration "MUST NOT exceed the lifetime of the Trust Chain". The token
 * endpoint enforces that on every request; this makes it visible in PingFederate too, by disabling each
 * federation client whose registration has expired. Clients are disabled, never deleted - §12.2.2 lets an OP
 * keep an invalidated registration's key material - and marked as disabled here, so a renewal enables them
 * again. A client an operator disabled carries no mark and stays disabled.
 *
 * <p>A client registered before expiries were recorded has none to check and is left to the token endpoint,
 * which renews or refuses it on its next request; disabling every such client at once on upgrade would be a
 * surprise nobody asked for. Nor does it touch anything while {@code OIDF_REGISTRATION_EXPIRY_ENFORCEMENT} is
 * {@code log}: that setting records expiries and enforces none, so disabling clients here would enforce them anyway.
 */
final class RegistrationExpirySweeper {
    private static final Log LOGGER = LogFactory.getLog(RegistrationExpirySweeper.class);
    /**
     * Set once a sweeper runs in this JVM, so two filter instances (or classloaders) never start two; given back
     * when its executor is closed.
     */
    static final String OWNER_PROPERTY = "oidf.registration.sweeper.owner";
    /** The managed executor's name; its thread is {@code oidf-registration-sweeper-1}. */
    static final String EXECUTOR_NAME = "registration-sweeper";

    private final ClientStore clientStore;
    private final RegistrationLifetime lifetime;
    private volatile ManagedExecutor executor;

    RegistrationExpirySweeper(ClientStore clientStore, RegistrationLifetime lifetime) {
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
    }

    /** One pass: disables every enabled federation client whose recorded expiry has passed, and names them. */
    List<String> sweepOnce() {
        List<String> disabled = new ArrayList<>();
        if (this.lifetime.settings().expiryEnforcement() == ExpiryEnforcement.LOG) {
            return disabled;
        }
        for (Client client : this.clientStore.getAll()) {
            String status = RegistrationService.extendedParamValue(client, FederationClientParams.STATUS);
            boolean federation = RegistrationService.STATUS_AUTO.equals(status) || RegistrationService.STATUS_REGISTERED.equals(status);
            OptionalLong expiry = RegistrationLifetime.storedExpiry(client);
            if (!federation || !client.isEnabled() || expiry.isEmpty() || !this.lifetime.isExpired(expiry)) {
                continue;
            }
            RegistrationService.disableExpired(this.clientStore, client, this.lifetime.now());
            disabled.add(client.getClientId());
            FederationEvents.event(FederationEvents.REGISTRATION_DISABLED).subject(client.getClientId()).role("OP")
                    .field("expires_at", expiry.getAsLong()).audit().description("registration expired").emit();
        }
        if (!disabled.isEmpty()) {
            LOGGER.info("Disabled " + disabled.size() + " federation client(s) whose registration expired: " + disabled);
        }
        return disabled;
    }

    /** One pass as the sweeper thread runs it: under a tracking id of its own. */
    Runnable pass() {
        return PfTracking.decorate("oidf-sweep", this::sweepOnce);
    }

    /**
     * Starts the sweep on a managed executor ({@code oidf-registration-sweeper-1}) every {@code intervalSeconds}, the
     * first pass one interval from now, unless it is 0, expiries are only logged, or a sweeper already runs in this
     * JVM. Returns whether this call started it. Each pass logs under a tracking id of its own
     * ({@code oidf-sweep-<8 hex>}), as a request's lines do under PingFederate's. A pass that throws is logged and
     * the next interval tries again.
     */
    boolean startOnce(long intervalSeconds) {
        if (intervalSeconds <= 0) {
            return false;
        }
        if (this.lifetime.settings().expiryEnforcement() == ExpiryEnforcement.LOG) {
            LOGGER.info("Federation registration sweeper not started: OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log records expiries"
                    + " and enforces none");
            return false;
        }
        String owner = Integer.toHexString(System.identityHashCode(this));
        synchronized (System.class) {
            if (System.getProperty(OWNER_PROPERTY) != null) {
                return false;
            }
            System.setProperty(OWNER_PROPERTY, owner);
        }
        Runnable pass = this.pass();
        Optional<ManagedExecutor> started = ManagedExecutors.every(EXECUTOR_NAME, Duration.ofSeconds(intervalSeconds), () -> {
            try {
                pass.run();
            } catch (RuntimeException e) {
                LOGGER.warn("Federation registration sweep failed; retrying next interval: " + e.getMessage());
            }
        });
        if (started.isEmpty()) {
            releaseOwner(owner);
            return false;
        }
        this.executor = started.get();
        this.executor.whenClosed(() -> releaseOwner(owner));
        LOGGER.info("Federation registration sweeper started (every " + intervalSeconds + "s)");
        return true;
    }

    /** Gives the JVM-wide owner property back, if this sweeper still holds it. */
    private static void releaseOwner(String owner) {
        synchronized (System.class) {
            if (owner.equals(System.getProperty(OWNER_PROPERTY))) {
                System.clearProperty(OWNER_PROPERTY);
            }
        }
    }

    /**
     * Stops the sweep this sweeper started, if it started one: a pass in progress is interrupted, and the owner
     * property is given back so that another may start. The lifecycle's shutdown does the same.
     */
    void stop() {
        ManagedExecutor running = this.executor;
        if (running != null) {
            running.close();
        }
    }
}
