package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The out-of-band binding notification (NIST SP 800-63B §6.1.2.1).
 *
 * <p>The property that matters is that a failing channel does not fail the enrolment. Refusing to bind
 * because email is down is a worse outcome than binding without the message — but the default
 * implementation is loud, so an unwired deployment cannot stay quietly non-compliant.
 */
class NotifierTest {

    @Test
    void theDefaultDoesNotThrowSoAnUnwiredDeploymentStillEnrols() {
        // It logs a warning naming the requirement; the point here is that it returns normally.
        BindingNotifier.logOnly().authenticatorBound("pingone|alice", "iPhone16,2 (ios 18.5)", "inst-1");
    }

    @Test
    void aWiredNotifierReceivesTheOwnerDeviceAndInstance() {
        List<String> sent = new ArrayList<>();
        BindingNotifier notifier = (subject, device, instanceId) ->
                sent.add(subject + "|" + device + "|" + instanceId);

        notifier.authenticatorBound("pingone|alice", "iPhone16,2 (ios 18.5)", "inst-1");

        assertEquals(1, sent.size());
        assertTrue(sent.get(0).startsWith("pingone|alice|"), sent.get(0));
        assertTrue(sent.get(0).endsWith("|inst-1"), sent.get(0));
    }
}
