/*
 * A CIBA authentication device that is a directory: it answers what an operator recorded there.
 */
package com.pingidentity.ps.oidf.cibasim;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.oobauth.OOBAuthGeneralException;
import com.pingidentity.sdk.oobauth.OOBAuthPlugin;
import com.pingidentity.sdk.oobauth.OOBAuthRequestContext;
import com.pingidentity.sdk.oobauth.OOBAuthResultContext;
import com.pingidentity.sdk.oobauth.OOBAuthTransactionContext;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;

/**
 * PingFederate's CIBA flow hands the user's authentication to an {@link OOBAuthPlugin}: {@code initiate}
 * when the client's backchannel request arrives, {@code check} each time the client polls the token
 * endpoint (or, in ping mode, on PingFederate's own timer), {@code finished} when the transaction ends.
 * The only such plugin that ships wants a PingOne tenant and a phone. This one wants a
 * {@link DecisionStore}: it answers {@code IN_PROGRESS} until an operator has recorded {@code allow} or
 * {@code deny} for the request through {@link CibaSimDecisionServlet}, and then {@code SUCCESS} or
 * {@code FAILURE}, which PingFederate renders as a token or as {@code access_denied}.
 *
 * <p>Nothing is approved by default, and nothing is approved by time. The conformance suite polls the
 * token endpoint expecting {@code authorization_pending} before it approves, two of its modules never
 * approve at all, and a device that says yes when nobody asked is not a simulation of anything.
 *
 * <p>The transaction id is {@link DecisionStore#txIdFor} of the {@code auth_req_id} PingFederate passes
 * to {@code initiate} as {@code ciba.auth_req_id}. {@code check} gets the transaction id and, in ping
 * mode, nothing else - so the id carries everything the lookup needs.
 */
public class SimOobAuthenticator implements OOBAuthPlugin {

    static final String AUTH_REQ_ID_PARAM = "ciba.auth_req_id";
    private static final Log LOGGER = LogFactory.getLog(SimOobAuthenticator.class);

    private final DecisionStore store;

    public SimOobAuthenticator() {
        this(DecisionStore.fromEnvironment(System::getenv));
    }

    SimOobAuthenticator(DecisionStore store) {
        this.store = store;
    }

    @Override
    public void configure(Configuration configuration) {
        // nothing to configure: the directory comes from OIDF_CIBA_SIM_DIR, see DecisionStore
    }

    @Override
    public PluginDescriptor getPluginDescriptor() {
        GuiConfigDescriptor gui = new GuiConfigDescriptor("Conformance CIBA simulator: approves or denies a "
                + "backchannel request when an operator records a decision at /ciba-sim/decision. Not an "
                + "authenticator - a stand-in for one, for conformance runs.");
        PluginDescriptor descriptor = new PluginDescriptor("Conformance CIBA simulator", this, gui, "1.0");
        descriptor.setAttributeContractSet(Collections.emptySet());
        return descriptor;
    }

    @Override
    public OOBAuthTransactionContext initiate(OOBAuthRequestContext context, Map<String, Object> inParameters)
            throws OOBAuthGeneralException {
        Object authReqId = inParameters == null ? null : inParameters.get(AUTH_REQ_ID_PARAM);
        if (!(authReqId instanceof String) || ((String) authReqId).isBlank()) {
            throw new OOBAuthGeneralException("no " + AUTH_REQ_ID_PARAM + " in the initiate parameters; this "
                    + "authenticator keys its decisions by it");
        }
        String txId = DecisionStore.txIdFor((String) authReqId);
        LOGGER.info((Object) ("CIBA simulator: transaction " + txId.substring(0, 12) + "… initiated; binding message "
                + (context == null ? null : context.getUserAuthBindingMessage()) + ", scope "
                + (context == null ? null : context.getRequestedScope())));
        OOBAuthTransactionContext tx = new OOBAuthTransactionContext();
        tx.setTransactionIdentifier(txId);
        tx.setStatusChangeCallbackCapable(false);
        return tx;
    }

    @Override
    public OOBAuthResultContext check(String transactionId, Map<String, Object> inParameters)
            throws OOBAuthGeneralException {
        Optional<DecisionStore.Decision> decision;
        try {
            decision = this.store.lookup(transactionId);
        } catch (IOException e) {
            throw new OOBAuthGeneralException("could not read the decision for " + transactionId, e);
        }
        OOBAuthResultContext result = new OOBAuthResultContext();
        if (decision.isEmpty()) {
            result.setStatus(OOBAuthResultContext.Status.IN_PROGRESS);
        } else if (decision.get() == DecisionStore.Decision.ALLOW) {
            result.setStatus(OOBAuthResultContext.Status.SUCCESS); // approved scope null = as requested
        } else {
            result.setStatus(OOBAuthResultContext.Status.FAILURE);
            result.setStatusMessage("the user denied the request");
        }
        return result;
    }

    @Override
    public void finished(String transactionId) throws OOBAuthGeneralException {
        try {
            this.store.forget(transactionId);
        } catch (IOException e) {
            throw new OOBAuthGeneralException("could not forget the decision for " + transactionId, e);
        }
    }
}
