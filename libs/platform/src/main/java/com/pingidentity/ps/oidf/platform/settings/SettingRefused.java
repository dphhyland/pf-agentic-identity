/*
 * A setting whose value is refused.
 */
package com.pingidentity.ps.oidf.platform.settings;

/**
 * A setting's value refused: the message names the setting and, unless it is a secret, the value refused.
 *
 * <p>An {@link IllegalStateException}, as every refusal of {@code FederationRuntimeConfig} was before these
 * parsers moved here, so a caller that caught that still catches this. {@link #setting()} names the setting,
 * so a start-up audit can collect refusals and name each one's setting without parsing the message.
 */
public final class SettingRefused extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    private final String setting;

    /**
     * @param setting the setting's name, as the operator sets it
     * @param message the whole message, naming the setting
     */
    public SettingRefused(String setting, String message) {
        super(message);
        this.setting = setting;
    }

    /** The name of the setting refused. */
    public String setting() {
        return this.setting;
    }
}
