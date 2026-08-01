/*
 * Seam: tells the subscriber, out of band, that an authenticator was bound to their account.
 */
package com.pingidentity.ps.oidf.enrolment;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Notifies the account owner when a new device key is bound to them.
 *
 * <p>Required, not optional. NIST SP 800-63B §6.1.2.1: the CSP <em>"SHOULD send a notification to the
 * subscriber via a mechanism that is independent of the transaction binding the new authenticator"</em>.
 * Independent is the operative word — a notification delivered through the same session that performed
 * the binding tells an attacker who already controls that session precisely nothing.
 *
 * <p>This is the control that catches the case nothing else does: an attacker who has somehow obtained
 * a valid passkey authentication binds their own device. Every cryptographic check passes, because
 * cryptographically it is a legitimate enrolment. Only the real owner receiving a message they did not
 * expect surfaces it.
 *
 * <p>It exists as a seam rather than a README note so the gap is visible in the code and in the logs
 * of any deployment that has not wired a channel.
 */
public interface BindingNotifier {

    /**
     * Tells the owner that a device key was bound.
     *
     * @param pingOneSubject the IdP subject to reach — resolved to a channel by the implementation,
     *                       because this service holds no contact details and should not start
     * @param deviceSummary  a human-readable description, e.g. {@code iPhone16,2 (iOS 18.5)}
     * @param instanceId     the opaque instance identifier, so a support conversation can reference it
     */
    void authenticatorBound(String pingOneSubject, String deviceSummary, String instanceId);

    /**
     * The default when no channel is configured: log loudly, every time.
     *
     * <p>It deliberately does not fail the enrolment. Refusing to bind because email is down would be
     * a worse outcome than binding without a notification — but a silent omission would be worse still,
     * so it is noisy by design and the message names the requirement it is failing.
     */
    static BindingNotifier logOnly() {
        final Log log = LogFactory.getLog(BindingNotifier.class);
        return (subject, device, instanceId) -> log.warn((Object) (
                "NO OUT-OF-BAND NOTIFICATION CHANNEL IS CONFIGURED. A device key was just bound to "
                        + subject + " (" + device + ", instance " + instanceId + ") and the owner has "
                        + "not been told. NIST SP 800-63B 6.1.2.1 requires notification through a "
                        + "channel independent of the binding transaction; wire a BindingNotifier."));
    }
}
