/*
 * A registry-level failure — never thrown for "this instance has no agent_id yet" (resolveOrMint mints
 * one instead), only for a genuine fault resolving or minting one.
 */
package com.pingidentity.ps.oidf.agent;

public final class AgentRegistryException extends Exception {

    public static final String STORAGE_FAILURE = "storage_failure";
    public static final String MINT_COLLISION = "mint_collision";

    private final String code;

    public AgentRegistryException(String code, String message) {
        super(message);
        this.code = code;
    }

    public AgentRegistryException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return this.code;
    }
}
