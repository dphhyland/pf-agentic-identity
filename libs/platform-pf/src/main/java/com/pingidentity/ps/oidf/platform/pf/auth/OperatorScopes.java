/*
 * The scopes of the operator APIs, one per surface.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import java.util.List;

/**
 * One OAuth scope per operator surface (plan item S8a; decision 1: "Each API surface has its own scope"). An operator
 * client in PingFederate is given the scopes of the surfaces it may use, as exclusive scopes, and nothing else: a
 * token for one surface does not open another. Plan item S8b puts each route of each surface in an
 * {@link OperatorRoutes} table with the scope it needs.
 */
public final class OperatorScopes {
    private OperatorScopes() {
    }

    /** Read the federation administration API: hosted entities, trust marks, keys, subordinates. */
    public static final String ADMIN_READ = "oidf.admin.read";
    /** Create, change and remove hosted entities. */
    public static final String ADMIN_ENTITIES = "oidf.admin.entities";
    /** Grant and revoke trust marks. */
    public static final String ADMIN_TRUST_MARKS = "oidf.admin.trust_marks";
    /** Rotate and revoke hosted entities' keys. */
    public static final String ADMIN_KEYS = "oidf.admin.keys";
    /** Manage subordinate statements. */
    public static final String ADMIN_SUBORDINATES = "oidf.admin.subordinates";
    /** Approve a pending subordinate: kept apart from {@link #ADMIN_SUBORDINATES}, so the two can be held by two people. */
    public static final String ADMIN_SUBORDINATES_APPROVE = "oidf.admin.subordinates.approve";
    /** Read the registered clients. */
    public static final String ADMIN_CLIENTS_READ = "oidf.admin.clients.read";
    /** The Shared Signals transmitter's administration. */
    public static final String SSF_ADMIN = "ssf.admin";
    /** Read /metrics. */
    public static final String METRICS_READ = "oidf.metrics.read";
    /** Read the health detail and /agentic-identity/info. */
    public static final String HEALTH_READ = "oidf.health.read";

    /** Every scope above, in that order. */
    public static final List<String> ALL = List.of(ADMIN_READ, ADMIN_ENTITIES, ADMIN_TRUST_MARKS, ADMIN_KEYS,
            ADMIN_SUBORDINATES, ADMIN_SUBORDINATES_APPROVE, ADMIN_CLIENTS_READ, SSF_ADMIN, METRICS_READ, HEALTH_READ);
}
