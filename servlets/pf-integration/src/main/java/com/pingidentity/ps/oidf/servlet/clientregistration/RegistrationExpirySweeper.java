/*
 * Disables federation clients whose registration has expired.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.PfTracking;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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
    /** Set once a sweeper runs in this JVM, so two filter instances (or classloaders) never start two. */
    static final String OWNER_PROPERTY = "oidf.registration.sweeper.owner";

    private final ClientStore clientStore;
    private final RegistrationLifetime lifetime;

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
     * Starts the sweep on a daemon thread every {@code intervalSeconds}, unless it is 0, expiries are only logged, or
     * a sweeper already runs in this JVM. Returns whether this call started it. Each pass logs under a tracking id of
     * its own ({@code oidf-sweep-<8 hex>}), as a request's lines do under PingFederate's.
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
        synchronized (System.class) {
            if (System.getProperty(OWNER_PROPERTY) != null) {
                return false;
            }
            System.setProperty(OWNER_PROPERTY, Integer.toHexString(System.identityHashCode(this)));
        }
        Runnable pass = this.pass();
        Thread sweeper = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(intervalSeconds * 1000L);
                    pass.run();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (RuntimeException e) {
                    LOGGER.warn("Federation registration sweep failed; retrying next interval: " + e.getMessage());
                }
            }
        }, "oidf-registration-sweeper");
        sweeper.setDaemon(true);
        sweeper.start();
        LOGGER.info("Federation registration sweeper started (every " + intervalSeconds + "s)");
        return true;
    }
}
