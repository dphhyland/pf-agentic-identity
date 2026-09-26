package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A PingFederate that has not been told about this module's extended properties keeps a client without them - silently -
 * and a federation client without {@code status} looks like one an administrator made. Found by the conformance suite's
 * OP plan: after the first registration, every request from the RP went unchecked. Registration now reads the client
 * back, and refuses - disabling it - when the marks did not survive.
 */
class RegistrationExtendedParamsTest {
    private static final String TA = "https://ta.example.com";
    private static final String AGENT = "https://agent.example.com";
    private static final String OP = "https://op.example.com";

    private final MutableClock clock = MutableClock.startingNow();
    private final Federation federation = Federation.builder(this.clock).anchor(TA).leaf(AGENT, TA)
            .metadata(AGENT, "oauth_client", RegistrationFixtures.agentMetadata("automatic", "explicit")).build();
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.of(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, "false")::get,
                name -> null));
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        FederationRuntimeConfig.resetForTests();
    }

    private RegistrationService service(FakeClientStore store) throws Exception {
        return new RegistrationService(new RegistrationConfiguration(TA, false),
                this.federation.validator(ValidatorOptions.defaults().withClock(this.clock), TA), store, RegistrationFixtures.signer(),
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no fetch expected: " + url);
                }, this.clock), RegistrationService.coordinatorFor(AutoRegistrationSettings.DEFAULTS));
    }

    @Test
    void aClientPingFederateKeptWithoutItsMarksIsDisabledAndTheRegistrationRefused() throws Exception {
        FakeClientStore store = new FakeClientStore().droppingExtendedParams();

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class,
                () -> this.service(store).admit(AGENT, this.federation.chain(AGENT, TA), OP));

        assertEquals(500, refused.status());
        assertEquals("server_error", refused.error());
        assertEquals(RegistrationRejectedException.Kind.INTERNAL, refused.kind());
        assertEquals(List.of("add " + AGENT, "disable " + AGENT), store.writes());
        assertFalse(store.get(AGENT).isEnabled(), "an unmanaged client nobody expires or checks is not left usable");
        assertEquals("extended_properties_undeclared", this.events.only(FederationEvents.REGISTRATION_REFUSED).reason());
    }

    @Test
    void explicitRegistrationIsRefusedTheSameWay() throws Exception {
        FakeClientStore store = new FakeClientStore().droppingExtendedParams();

        assertThrows(RegistrationRejectedException.class, () -> this.service(store).explicitRegister(new ExplicitRegistrationRequest(AGENT,
                AGENT, this.federation.chain(AGENT, TA), Map.of()), OP));

        assertFalse(store.get(AGENT).isEnabled());
    }
}
