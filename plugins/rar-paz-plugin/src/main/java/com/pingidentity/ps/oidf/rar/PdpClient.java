/*
 * The PDP seam: one decision call, two wire dialects (PingAuthorize governance engine / OpenID AuthZEN).
 */
package com.pingidentity.ps.oidf.rar;

import java.io.IOException;
import java.util.Map;

/**
 * A policy decision point the processor can ask about one {@code authorization_details} entry.
 * Implementations own their wire dialect: {@link GovernanceEngineClient} speaks the native
 * PingAuthorize governance-engine JSON API; {@link AuthZenPdpClient} speaks the OpenID AuthZEN
 * 1.0 evaluation API ({@code /access/v1/evaluation}). Both return the same parsed
 * {@link DecisionResponse}, so enforcement and statement application are dialect-independent.
 *
 * @param resourceOwner the authenticated principal's {@code sub} (may be {@code null}); the
 *                      attestation subject is the delegated agent, never the principal
 */
public interface PdpClient {

    DecisionResponse decide(String type, Map<String, Object> detail, AttestationSubject subject,
                            String resourceOwner, String fallbackClientId) throws IOException;
}
