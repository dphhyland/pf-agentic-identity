/*
 * Who each SSF path answers: the transmitter's receivers and provisioners on SSF's own scopes, never an operator.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import java.util.Map;

/**
 * Every path the SSF servlets map, by the kind of caller it takes (plan item S8b). None of them is an operator route:
 * stream management, polling, {@code events:emit} and SCIM keep SSF's own scopes - the receiver scope
 * ({@code OIDF_SSF_RECEIVER_SCOPE}, a receiver acting on its own streams, {@code StreamAccess}) and the provisioner
 * scope ({@code OIDF_SSF_PROVISIONER_SCOPE}) - checked through platform's TokenIntrospector
 * ({@code PfIntrospectionReceiverAuthenticator}). There is no SSF administration outside a receiver's own streams on
 * this release, so no path needs the operator scope {@code ssf.admin}; one that is added must be put here, and
 * SsfRoutesTest fails until it is.
 */
public final class SsfRoutes {

    private SsfRoutes() {
    }

    /** The kind of caller a path takes. */
    public enum Access {
        /** Anyone: the transmitter's metadata. */
        PUBLIC,
        /** A receiver's PingFederate access token with the receiver scope, for its own streams (SsfHttp.authorize). */
        RECEIVER,
        /** A PingFederate access token with the provisioner scope, acting across streams (SsfHttp.authorizeProvisioner). */
        PROVISIONER,
        /**
         * This deployment as a receiver: the bearer token the remote transmitter was given for its push
         * ({@code receiverPushToken}), compared by SsfReceiverServlet - a credential for one transmitter, not an operator's.
         */
        PUSH
    }

    /** Every {@code @WebServlet} pattern of the SSF servlets, and what it takes. */
    public static final Map<String, Access> BY_PATTERN = Map.ofEntries(
            Map.entry("/.well-known/ssf-configuration", Access.PUBLIC),
            Map.entry("/ssf/.well-known/ssf-configuration", Access.PUBLIC),
            Map.entry("/ssf/streams", Access.RECEIVER),
            Map.entry("/ssf/status", Access.RECEIVER),
            Map.entry("/ssf/subjects:add", Access.RECEIVER),
            Map.entry("/ssf/subjects:remove", Access.RECEIVER),
            Map.entry("/ssf/verify", Access.RECEIVER),
            Map.entry("/ssf/poll", Access.RECEIVER),
            Map.entry("/ssf/events:emit", Access.PROVISIONER),
            Map.entry("/ssf/scim/v2/Users", Access.PROVISIONER),
            Map.entry("/ssf/scim/v2/Users/*", Access.PROVISIONER),
            Map.entry("/ssf/receiver/events", Access.PUSH));
}
