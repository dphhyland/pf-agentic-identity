/*
 * The SSF receiver's own stream at its transmitter, set up at start-up.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.events.LogSafe;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The receiver's stream at the transmitter it names in {@code OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL} (plan
 * item H-SSF-1): created or found, and brought into step with the receiver's settings, by {@link #ensure} - which the
 * {@code SSF_RECEIVER} component's start runs, and platform's supervisor runs again while the transmitter cannot be
 * reached or refuses. What it learns is recorded here: the stream id, the URL a poll stream is polled at (the poll
 * loop polls nothing until it is known), and the critical subject members, handed to the receiver.
 */
public final class ReceiverStream {

    private static final Log LOGGER = LogFactory.getLog(ReceiverStream.class);

    private final ReceiverStreamClient.HttpJson http;
    private final ReceiverStreamClient.Plan plan;
    private final SsfReceiverService receiver;
    private volatile ReceiverStreamClient.Setup setup;

    public ReceiverStream(ReceiverStreamClient.HttpJson http, ReceiverStreamClient.Plan plan, SsfReceiverService receiver) {
        this.http = Objects.requireNonNull(http, "http");
        this.plan = Objects.requireNonNull(plan, "plan");
        this.receiver = Objects.requireNonNull(receiver, "receiver");
    }

    /** The plan the receiver's settings make: its issuer, audience, events and, for push, its endpoint and token. */
    static ReceiverStreamClient.Plan plan(SsfConfiguration config) {
        return new ReceiverStreamClient.Plan(config.receiverTransmitterConfigurationUrl(), config.receiverExpectedIssuer(),
                config.receiverAudience(), config.receiverEventsRequested(), config.receiverPushEndpointUrl(),
                config.receiverEndpointAuthToken());
    }

    /**
     * Sets up the stream, once: a later call, after one has succeeded, does nothing.
     *
     * @throws ReceiverStreamClient.Misconfigured when the transmitter does not match the receiver's settings
     * @throws Exception                          when it cannot be reached or refuses
     */
    public synchronized ReceiverStreamClient.Setup ensure() throws Exception {
        if (this.setup != null) {
            return this.setup;
        }
        ReceiverStreamClient.Setup done = ReceiverStreamClient.ensure(this.http, this.plan);
        this.receiver.criticalSubjectMembers(done.criticalSubjectMembers());
        this.setup = done;
        LOGGER.info((Object) ("SSF receiver: stream " + LogSafe.value(done.streamId()) + " at " + this.plan.expectedIssuer()
                + " is set up ("
                + (done.pollUrl() == null ? "push to " + this.plan.pushEndpointUrl() : "poll") + ", "
                + this.plan.events().size() + " event type(s) requested)"));
        return done;
    }

    /** The stream once it is set up; null before. */
    public ReceiverStreamClient.Setup setup() {
        return this.setup;
    }

    /** The URL to poll: the stream's, once it is set up and polled; null before, and for a push stream. */
    public String pollUrl() {
        ReceiverStreamClient.Setup local = this.setup;
        return local == null ? null : local.pollUrl();
    }
}
