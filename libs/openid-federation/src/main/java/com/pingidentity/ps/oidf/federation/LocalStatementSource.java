/*
 * Statements this deployment can produce itself.
 */
package com.pingidentity.ps.oidf.federation;

/**
 * The Entity Statements this deployment issues, produced in-process for its own resolver. Each method
 * answers {@code null} for a statement that is not its to issue, so the caller goes to the network.
 */
public interface LocalStatementSource {

    /** The Entity Configuration of {@code entityId} when this deployment is, or hosts, that entity. */
    String entityConfiguration(String entityId) throws Exception;

    /** The statement {@code issuer} makes about {@code subject} when this deployment is {@code issuer}. */
    String subordinateStatement(String issuer, String subject) throws Exception;
}
