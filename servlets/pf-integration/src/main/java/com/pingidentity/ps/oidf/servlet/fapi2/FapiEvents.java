/*
 * The refusals of the two FAPI filters, as events.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.platform.events.Events;
import jakarta.servlet.http.HttpServletRequest;

/**
 * {@code fapi.request.refused} (plan item O-2, the programme's decision 7), in pf-integration's {@code fapi}
 * catalogue: a request one of the FAPI filters refused before PingFederate saw it. The event names the filter, the
 * rule, the client the request was attributed to (its subject; unverified, as the filters read it) and the endpoint,
 * and is written to PingFederate's audit log with the caller's address. Platform's {@link Events} counts it in
 * {@code oidf_events_total}.
 */
public final class FapiEvents {
    static final String COMPONENT = "fapi";
    public static final String REFUSED = "fapi.request.refused";

    /** The {@code filter} field: which filter refused. */
    public static final String PROFILE_FILTER = "fapi2_profile";
    public static final String RESOURCE_SERVER_FILTER = "fapi_resource_server";

    private FapiEvents() {
    }

    /** {@code request}, attributed to {@code clientId} (null when it could not be told), refused by {@code filter}. */
    @SuppressWarnings("removal")
    public static void refused(HttpServletRequest request, String filter, String rule, String error, String clientId) {
        // The first emitter in this classloader installs PingFederate's audit sink; after that this is one check.
        com.pingidentity.ps.oidf.pf.PfAuditEventSink.install();
        PfRequestScope.Context outer = PfRequestScope.enter(request);
        try {
            Events.event(COMPONENT, REFUSED).failure(error).subject(clientId).audit()
                    .field("filter", filter).field("rule", rule).field("endpoint", endpoint(request)).emit();
        } finally {
            PfRequestScope.exit(outer);
        }
    }

    /** The endpoint's path, without the query: the request URI is what PingFederate's mapping matched. */
    static String endpoint(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri == null || uri.isBlank() ? "unknown" : uri;
    }
}
