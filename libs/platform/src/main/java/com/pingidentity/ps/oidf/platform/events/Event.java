/*
 * One thing that happened in a component, recorded once.
 */
package com.pingidentity.ps.oidf.platform.events;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * A decision or action worth recording: a chain validated or refused, a client registered, a key revoked.
 *
 * <p>{@code code} is a stable, dotted machine code ({@code federation.registration.created}) - the contract a log
 * consumer branches on, never prose - and is declared, with every field it may carry, in its component's
 * catalogue ({@link EventCatalogue}). {@code outcome} is success or failure, and a failure carries a short
 * {@code reason} code. {@code subject} is who the event is about (an entity id or client id), {@code partner}
 * the other party (the trust anchor, the attester). {@code audit} marks events that also belong in PingFederate's
 * security audit log. {@code component} names the catalogue the code is declared in, which says where the event
 * is logged and what the audit log's {@code protocol} column says. Every value is passed through {@link LogSafe}
 * by the sinks, so a caller cannot put a token or a forged line into a log through an event.
 *
 * <p>Privacy rule (from {@code libs/agent-registry}): an instance's subject is never recorded beside its
 * {@code agent_id}. The builder drops {@code instance_subject} and {@code spiffe_id} from any event that carries
 * {@code agent_id}.
 */
public record Event(String code, Outcome outcome, String reason, String subject, String partner, String role,
                    String description, Map<String, String> fields, String requestJti, boolean audit, String category,
                    String component) {

    /** Fields the privacy rule removes when {@code agent_id} is present. */
    public static final List<String> NEVER_BESIDE_AGENT_ID = List.of("instance_subject", "spiffe_id");

    /** An event whose component nobody named and no catalogue declares is recorded as this component's. */
    public static final String DEFAULT_COMPONENT = "federation";

    public enum Outcome {
        SUCCESS, FAILURE;

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

    public Event {
        Objects.requireNonNull(code, "code");
        outcome = outcome == null ? Outcome.SUCCESS : outcome;
        fields = fields == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        category = category == null || category.isBlank() ? categoryOf(code) : category;
        component = component == null || component.isBlank() ? DEFAULT_COMPONENT : component;
    }

    /**
     * The logger family of a code: the second segment of a {@code federation.*} code
     * ({@code federation.registration.created} → {@code registration}), otherwise the first
     * ({@code attestation.client.verified} → {@code attestation}).
     */
    public static String categoryOf(String code) {
        String[] parts = code.split("\\.");
        return parts.length >= 3 && "federation".equals(parts[0]) ? parts[1] : parts[0];
    }

    public boolean isFailure() {
        return this.outcome == Outcome.FAILURE;
    }

    /** The same event with other fields; everything else is kept. */
    public Event withFields(Map<String, String> replaced) {
        return new Event(this.code, this.outcome, this.reason, this.subject, this.partner, this.role, this.description,
                replaced, this.requestJti, this.audit, this.category, this.component);
    }

    /** The same event with another subject and partner; everything else is kept. */
    public Event withParties(String newSubject, String newPartner) {
        return new Event(this.code, this.outcome, this.reason, newSubject, newPartner, this.role, this.description,
                this.fields, this.requestJti, this.audit, this.category, this.component);
    }

    /** {@code fields} with the privacy rule applied: no {@code instance_subject} or {@code spiffe_id} beside {@code agent_id}. */
    static Map<String, String> withoutInstanceBesideAgent(Map<String, String> fields) {
        Map<String, String> safe = new LinkedHashMap<>(fields);
        if (safe.containsKey("agent_id")) {
            for (String forbidden : NEVER_BESIDE_AGENT_ID) {
                safe.remove(forbidden);
            }
        }
        return safe;
    }

    /** The component named, else the one whose catalogue declares {@code code}, else {@link #DEFAULT_COMPONENT}. */
    static String resolve(String component, String code, EventCatalogues catalogues) {
        if (component != null) {
            return component;
        }
        return catalogues.componentOf(code).orElse(DEFAULT_COMPONENT);
    }

    /**
     * Starts an event of {@code code} for {@code component}. A {@code null} component is resolved from this
     * loader's catalogues when the event is built: the component whose catalogue declares the code, or
     * {@link #DEFAULT_COMPONENT}.
     */
    public static Builder builder(String component, String code) {
        return new Builder(component, code);
    }

    /** Fluent construction; {@link #emit()} hands the event to {@link Events}. */
    public static final class Builder {
        private final String component;
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

        private Builder(String component, String code) {
            this.component = component;
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

        /** Adds a field; a {@code null} name or value is skipped, a collection is joined with spaces. */
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

        /** The event, with the privacy rule applied and its component resolved. */
        public Event build() {
            return new Event(this.code, this.outcome, this.reason, this.subject, this.partner, this.role,
                    this.description, withoutInstanceBesideAgent(this.fields), this.requestJti, this.audit, this.category,
                    resolve(this.component, this.code, EventCatalogues.current()));
        }

        /** Builds the event and hands it to this loader's sink. */
        public Event emit() {
            Event event = this.build();
            Events.emit(event);
            return event;
        }
    }
}
