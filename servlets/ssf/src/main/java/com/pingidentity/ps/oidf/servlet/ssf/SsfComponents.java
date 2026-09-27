/*
 * The SSF transmitter's and receiver's component states, from what SsfHttp.bootstrap left behind.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import jakarta.servlet.ServletConfig;
import java.util.List;
import java.util.Objects;

/**
 * What the SSF servlets' {@code init} tells health (plan item O-4) after {@link SsfHttp#bootstrap}, which never
 * throws and answers only whether the transmitter started. The states follow today's behaviour, which
 * {@code bootstrap} already decides; nothing here changes it:
 *
 * <ul>
 *   <li>SSF: started is ready. Not started with settings that do not parse - no issuer, or any other setting
 *       {@link SsfConfiguration#fromServletConfig} refuses - is disabled, because {@code bootstrap} reads every such
 *       refusal as "not configured" and disables the endpoints (finding F-0191). Not started with settings that
 *       parse means the store or publisher could not be built: failed on a dependency, and ready again once
 *       {@code SsfSupport}'s boot retry has configured the transmitter.</li>
 *   <li>SSF_RECEIVER: disabled when SSF is, or when no receiver issuer is set; failed on its configuration when
 *       the receiver audience or endpoint token is missing, which {@code SsfSupport} refuses to start without;
 *       failed on a dependency, with the same probe, when the transmitter did not start; otherwise ready.</li>
 * </ul>
 */
final class SsfComponents {

    static final String NOT_STARTED = "the SSF transmitter could not be configured (server.log has the cause); it is retried";

    private SsfComponents() {
    }

    /** The transmitter's part, from whether {@code bootstrap} started it. */
    static void transmitter(ComponentParts.Part part, boolean started, ServletConfig config) {
        if (started) {
            part.ready();
        } else if (settings(config) == null) {
            part.disabled();
        } else {
            part.failedDependency(NOT_STARTED, SsfSupport::configuration);
        }
    }

    /** The receiver's part, from whether {@code bootstrap} started the transmitter. */
    static void receiver(ComponentParts.Part part, boolean started, ServletConfig config) {
        SsfConfiguration settings = settings(config);
        if (settings == null || !settings.receiverConfigured()) {
            part.disabled();
            return;
        }
        List<String> missing = settings.receiverMissingRequirements();
        if (!missing.isEmpty()) {
            part.failedConfig("the SSF receiver is not started: " + missing + " must be set");
        } else if (!started) {
            part.failedDependency(NOT_STARTED, () -> Objects.requireNonNull(SsfSupport.receiverService(), "receiver"));
        } else {
            part.ready();
        }
    }

    /** The SSF settings as {@code bootstrap} reads them, or null where it finds SSF not configured. */
    static SsfConfiguration settings(ServletConfig config) {
        try {
            return SsfConfiguration.fromServletConfig(config);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
