/*
 * One thing that happened in the federation subsystem, recorded once.
 */
package com.pingidentity.ps.oidf.federation.event;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * A decision or action worth recording: a chain validated or refused, a client registered, a statement
 * served, a PDP consulted.
 *
 * <p>{@code code} is a stable, dotted machine code ({@code federation.registration.created}) - the
 * contract a log consumer branches on, never prose. {@code outcome} is success or failure, and a failure
 * carries a short {@code reason} code. {@code subject} is who the event is about (an entity id or client
 * id), {@code partner} the other party (the trust anchor, the attester). {@code audit} marks events that
 * also belong in PingFederate's security audit log. Every value is passed through {@link LogSafe} by the
 * sinks, so a caller cannot put a token or a forged line into a log through an event.
 *
 * <p>Privacy rule (from {@code libs/agent-registry}): an instance's subject is never recorded beside its
 * {@code agent_id}. The builder drops {@code instance_subject} and {@code spiffe_id} from any event that
 * carries {@code agent_id}.
 */
public record FederationEvent(String code, Outcome outcome, String reason, String subject, String partner,
                              String role, String description, Map<String, String> fields, String requestJti,
                              boolean audit, String category) {

    /** Fields the privacy rule removes when {@code agent_id} is present. */
    static final List<String> NEVER_BESIDE_AGENT_ID = List.of("instance_subject", "spiffe_id");

    public enum Outcome {
        SUCCESS, FAILURE;

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

    public FederationEvent {
        Objects.requireNonNull(code, "code");
        outcome = outcome == null ? Outcome.SUCCESS : outcome;
        fields = fields == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        category = category == null || category.isBlank() ? categoryOf(code) : category;
    }

    /**
     * The logger family of a code: the second segment of a {@code federation.*} code
     * ({@code federation.registration.created} → {@code registration}), otherwise the first
     * ({@code attestation.client.verified} → {@code attestation}).
     */
    static String categoryOf(String code) {
        String[] parts = code.split("\\.");
        return parts.length >= 3 && "federation".equals(parts[0]) ? parts[1] : parts[0];
    }

    public boolean isFailure() {
        return this.outcome == Outcome.FAILURE;
    }

    public static Builder builder(String code) {
        return new Builder(code);
    }

    /** Fluent construction; {@link #emit()} hands the event to {@link FederationEvents}. */
    public static final class Builder {
        private final String code;
        private Outcome outcome = Outcome.SUCCESS;
        private String reason;
        private String subject;
        private String partner;
        private String role;
        private String description;
        private final Map<String, String> fields = new LinkedHashMap<>();
        private String requestJti;
        private boolean audit;
        private String category;

        private Builder(String code) {
            this.code = Objects.requireNonNull(code, "code");
        }

        public Builder success() {
            this.outcome = Outcome.SUCCESS;
            this.reason = null;
            return this;
        }

        /** Marks the event a failure with a short machine {@code reason} ({@code signature}, {@code no_route_to_anchor}). */
        public Builder failure(String reasonCode) {
            this.outcome = Outcome.FAILURE;
            this.reason = reasonCode;
            return this;
        }

        public Builder subject(String value) {
            this.subject = value;
            return this;
        }

        public Builder partner(String value) {
            this.partner = value;
            return this;
        }

        /** PingFederate's audit {@code role} column: {@code OP}, {@code TA}, {@code ATTESTER}, ... */
        public Builder role(String value) {
            this.role = value;
            return this;
        }

        public Builder description(String value) {
            this.description = value;
            return this;
        }

        /** Adds a field; a {@code null} value is skipped, a collection is joined with spaces. */
        public Builder field(String name, Object value) {
            if (name != null && value != null) {
                String rendered;
                if (value instanceof Iterable<?> iterable) {
                    StringBuilder joined = new StringBuilder();
                    for (Object item : iterable) {
                        if (joined.length() > 0) {
                            joined.append(' ');
                        }
                        joined.append(item);
                    }
                    rendered = joined.toString();
                } else {
                    rendered = String.valueOf(value);
                }
                this.fields.put(name, rendered);
            }
            return this;
        }

        public Builder requestJti(String value) {
            this.requestJti = value;
            return this;
        }

        /** Marks the event as belonging in PingFederate's security audit log as well as the server log. */
        public Builder audit() {
            this.audit = true;
            return this;
        }

        public Builder category(String value) {
            this.category = value;
            return this;
        }

        public FederationEvent build() {
            Map<String, String> safeFields = new LinkedHashMap<>(this.fields);
            if (safeFields.containsKey("agent_id")) {
                for (String forbidden : NEVER_BESIDE_AGENT_ID) {
                    safeFields.remove(forbidden);
                }
            }
            return new FederationEvent(this.code, this.outcome, this.reason, this.subject, this.partner, this.role,
                    this.description, safeFields, this.requestJti, this.audit, this.category);
        }

        /** Builds the event and hands it to the configured sink. */
        public FederationEvent emit() {
            FederationEvent event = this.build();
            FederationEvents.emit(event);
            return event;
        }
    }
}
