/*
 * The RFC 9396 containment models this classloader enforces, read once from the environment.
 */
package com.pingidentity.ps.oidf.clientattestation;

import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The model set every containment decision in this classloader uses: the built-in types and whatever
 * {@value RarModels#ENV_MODELS_FILE} or {@value RarModels#ENV_MODELS} adds, read through
 * {@link RarModels#fromEnvironment(Map)} the first time anything asks and kept for as long as the classloader
 * lives. The environment is the only source, so the RAR plugin, which reads the same variables through its own
 * shaded copy of the library, arrives at the same set; the attestation context carries this set's
 * {@link RarModels#fingerprint()} so the plugin can tell when it has not.
 *
 * <p>PingFederate loads this module twice - in {@code pf-runtime.war}, where the token-endpoint filter and the
 * attester live, and in {@code server/default/deploy}, where the OGNL issuance criterion runs - so there are two
 * of these, each loaded once. The webapp's is loaded when the filter or the attester starts; the engine's on the
 * criterion's first call, the first moment anything there runs.
 *
 * <p>A document the library refuses is refused here on every call after, with the reason logged once: a
 * component that asks at start-up refuses to start, and one that asks per request refuses every request rather
 * than enforce a model it could not read. Plan item S-9 (Phase 3) replaces the refusal to start with a
 * component that starts and refuses only its own traffic.
 */
public final class AttestationRarModels {
    private static final Log LOGGER = LogFactory.getLog(AttestationRarModels.class);
    private static final Object LOCK = new Object();
    private static RarModels loaded;
    private static RarModelException refusal;
    /** The environment to read; {@code null} is the process environment. Only tests change it. */
    private static Map<String, String> environment;

    private AttestationRarModels() {
    }

    /**
     * The models, loading them on the first call in this classloader.
     *
     * @throws RarModelException {@link RarModelException.Reason#MODEL_INVALID} when the environment names a
     *                           document the library refuses - on this call and every one after it
     */
    public static RarModels get() throws RarModelException {
        // One uncontended lock per call; the filter and the attester hold the answer they got at start-up, so
        // only the criterion and a configuration parse come back here per request.
        synchronized (LOCK) {
            if (loaded == null && refusal == null) {
                load();
            }
            if (refusal != null) {
                throw new RarModelException(refusal.reason(), refusal.getMessage());
            }
            return loaded;
        }
    }

    /**
     * {@link #get()} for a caller with no checked exception to throw: a constructor, a test harness.
     *
     * @throws IllegalStateException when the models could not be loaded, naming why
     */
    public static RarModels require() {
        try {
            return get();
        } catch (RarModelException e) {
            throw new IllegalStateException("the RAR containment models could not be loaded: " + e.getMessage(), e);
        }
    }

    private static void load() {
        try {
            RarModels models = RarModels.fromEnvironment(environment == null ? System.getenv() : environment);
            LOGGER.info((Object) ("RAR containment models loaded: fingerprint=" + models.fingerprint()
                    + " types=" + models.types()
                    + (models.commonFieldsFallback()
                            ? " (development profile: a type no model names falls back to the common fields)" : "")));
            loaded = models;
        } catch (RarModelException e) {
            refusal = e;
            LOGGER.error((Object) ("RAR containment models could not be loaded, so nothing in this classloader that "
                    + "checks authorization_details will serve: " + e.getMessage() + ". Fix "
                    + RarModels.ENV_MODELS_FILE + " or " + RarModels.ENV_MODELS + " and restart PingFederate."));
        }
    }

    /** Test seam: forgets what was loaded, and reads {@code env} (null: the process environment) next time. */
    static void resetForTest(Map<String, String> env) {
        synchronized (LOCK) {
            loaded = null;
            refusal = null;
            environment = env;
        }
    }
}
