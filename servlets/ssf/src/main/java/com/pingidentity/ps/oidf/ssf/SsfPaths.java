/*
 * The paths the SSF servlets are mapped to, for the URLs the transmitter advertises.
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * Where the SSF servlets answer, below the issuer: every URL the transmitter hands a receiver or a provisioner - the
 * metadata's endpoints, a poll stream's {@code endpoint_url}, a SCIM user's {@code meta.location} - is the issuer and
 * one of these. They are the servlets' {@code @WebServlet} paths, which are fixed when the module is built, so they
 * are constants and not a setting: {@code OIDF_SSF_BASE_PATH} changed the URLs the transmitter advertised and not the
 * paths that answer them, and was removed in 0.6.0 (plan item H-SSF-3). {@code SsfPathsTest} holds each to a mapped
 * pattern.
 */
public final class SsfPaths {

    /** The prefix of every SSF path but the metadata's {@code /.well-known/ssf-configuration}. */
    public static final String BASE = "/ssf";
    public static final String STREAMS = BASE + "/streams";
    public static final String STATUS = BASE + "/status";
    public static final String SUBJECTS_ADD = BASE + "/subjects:add";
    public static final String SUBJECTS_REMOVE = BASE + "/subjects:remove";
    public static final String VERIFY = BASE + "/verify";
    public static final String POLL = BASE + "/poll";
    public static final String SCIM_USERS = BASE + "/scim/v2/Users";

    private SsfPaths() {
    }
}
