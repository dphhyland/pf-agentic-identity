/*
 * What happens when a setting is wrong.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;

/**
 * What happens when a setting is wrong, in the style guide's vocabulary (docs/development/style-guide.md,
 * "Settings"): the effect, and the sentence a configuration reference prints.
 *
 * @param effect when the failure shows
 * @param detail the sentence, for example "Anything but true or false"
 */
public record WhenWrong(Effect effect, String detail) {

    /** When a wrong value shows. */
    public enum Effect {
        /** The component fails at deploy, and the log names the setting ("PingFederate doesn't start"). */
        DOESNT_START("doesnt-start"),
        /** A servlet that starts lazily fails on its first request, and only its paths. */
        FIRST_REQUEST("first-request"),
        /** Nothing at start-up; the requests that need it fail. */
        PER_REQUEST("per-request"),
        /** Nothing checks it: the detail says what a wrong value does instead. */
        NOT_CHECKED("not-checked");

        private final String id;

        Effect(String id) {
            this.id = id;
        }

        /** The catalogue's spelling. */
        public String id() {
            return this.id;
        }

        static Effect byId(String id) {
            for (Effect effect : values()) {
                if (effect.id.equals(id)) {
                    return effect;
                }
            }
            return null;
        }
    }

    public WhenWrong {
        Objects.requireNonNull(effect, "effect");
        Objects.requireNonNull(detail, "detail");
    }
}
