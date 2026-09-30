/*
 * A compile-time stand-in for a PingFederate SAML binding type this module's test classpath does not have.
 */
package org.sourceid.saml20.xmlbinding.assertion;

/**
 * {@code AuditLoggerService.setUserName(NameIDType)} names this type, from a PingFederate jar outside
 * pf-protocolengine and the SDK, so a test implementation of the service cannot compile or load without it. Nothing
 * here ever makes one; the real type is never on this test classpath to clash with it.
 */
public interface NameIDType {
}
