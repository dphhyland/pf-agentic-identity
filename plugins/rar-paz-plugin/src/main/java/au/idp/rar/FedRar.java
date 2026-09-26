package au.idp.rar;

import com.pingidentity.ps.oidf.rar.AttestationAwareRarProcessor;

/**
 * The same processor under a short class name. PingFederate uses a plugin's class name as its plugin id,
 * and 13.1 refuses to create an instance of a plugin whose id is longer than 32 characters - which
 * {@code com.pingidentity.ps.oidf.rar.AttestationAwareRarProcessor} is. Deployments that already hold an
 * instance under the long name keep it; new ones use this.
 */
public class FedRar extends AttestationAwareRarProcessor {
}
