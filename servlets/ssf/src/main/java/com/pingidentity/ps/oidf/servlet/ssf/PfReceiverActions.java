/*
 * PF-side receiver actions: revoke OAuth grants via the PF SDK (runtime-only).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.AccessGrantManagerAccessor;
import com.pingidentity.ps.oidf.ssf.ReceiverActionHandler;
import com.pingidentity.sdk.accessgrant.AccessGrant;
import com.pingidentity.sdk.accessgrant.AccessGrantManager;
import java.util.Collection;

/**
 * The runtime {@link ReceiverActionHandler.ReceiverActions}: revokes a subject's OAuth grants through
 * PingFederate's {@code AccessGrantManagerAccessor} — the same in-process SDK accessor family the signing
 * and data-store integrations use. Revoking the grants kills refresh-token use immediately and invalidates
 * reference tokens on their next validation. Compiles against the {@code provided} PF SDK; exercised only
 * inside PingFederate.
 */
public final class PfReceiverActions implements ReceiverActionHandler.ReceiverActions {

    @Override
    public int revokeGrantsFor(String userKey) {
        try {
            AccessGrantManager manager = AccessGrantManagerAccessor.getAccessGrantManager();
            Collection<AccessGrant> grants = manager.getByUserKey(userKey);
            int revoked = 0;
            for (AccessGrant grant : grants) {
                manager.revokeGrant(grant.getGuid());
                revoked++;
            }
            return revoked;
        } catch (Exception e) {
            throw new IllegalStateException("grant revocation failed for '" + userKey + "': " + e.getMessage(), e);
        }
    }
}
