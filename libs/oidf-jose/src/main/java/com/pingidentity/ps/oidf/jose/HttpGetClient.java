package com.pingidentity.ps.oidf.jose;

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
}
