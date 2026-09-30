package com.pingidentity.ps.oidf.jose;

import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;

/**
 * Minimal HTTP GET abstraction used to fetch federation artifacts (entity
 * configurations, subordinate statements, resolve responses). Kept as an
 * interface so the transport can be swapped out in tests.
 */
public interface HttpGetClient {

    /**
     * Performs an HTTP GET.
     *
     * @param url          the absolute URL to fetch
     * @param acceptHeader the value to send in the {@code Accept} header
     * @return the response body
     * @throws Exception if the request fails or returns a non-2xx status
     */
    String get(String url, String acceptHeader) throws Exception;

    /**
     * Performs an HTTP GET that ends by {@code deadline}, the body included: a caller with a budget for several
     * requests (a trust chain resolution, plan item S5b) passes what is left of it, so a slow peer spends the
     * caller's time rather than a fresh timeout of its own. An implementation that sends through platform's
     * {@code OutboundHttp} ({@link JdkHttpClient}) holds the whole exchange to the sooner of this and its own
     * request timeout. This default, for an implementation that cannot bound a request (a test's fake), refuses to
     * start once the deadline has passed and otherwise makes the unbounded request.
     *
     * @throws OutboundHttpException with {@link OutboundHttpException.Reason#DEADLINE} when the deadline has passed
     */
    default String get(String url, String acceptHeader, Deadline deadline) throws Exception {
        if (deadline.expired()) {
            throw new OutboundHttpException(OutboundHttpException.Reason.DEADLINE,
                    "not fetching " + url + ": the deadline has already passed");
        }
        return get(url, acceptHeader);
    }
}
