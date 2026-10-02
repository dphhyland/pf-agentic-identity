/*
 * One thing that happened in the federation subsystem, recorded once - a façade over platform's Event.
 */
package com.pingidentity.ps.oidf.federation.event;

import com.pingidentity.ps.oidf.platform.events.Event;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A decision or action worth recording: a chain validated or refused, a client registered, a statement
 * served, a PDP consulted. The same record as {@link Event} in {@code platform.events}, where events now live
 * (plan item O-1): this façade keeps every emitter compiling unchanged, and converts both ways without loss.
 *
 * <p>{@code code} is a stable, dotted machine code ({@code federation.registration.created}) - the
 * contract a log consumer branches on, never prose - declared with its fields in
 * {@code META-INF/oidf-events/federation.json}. {@code outcome} is success or failure, and a failure
 * carries a short {@code reason} code. {@code subject} is who the event is about (an entity id or client
 * id), {@code partner} the other party (the trust anchor, the attester). {@code audit} marks events that
 * also belong in PingFederate's security audit log. {@code component} is the catalogue the code is declared in.
 * Every value is passed through {@link LogSafe} by the sinks, so a caller cannot put a token or a forged line
 * into a log through an event.
 *
 * <p>Privacy rule (from {@code libs/agent-registry}): an instance's subject is never recorded beside its
 * {@code agent_id}. The builder drops {@code instance_subject} and {@code spiffe_id} from any event that
 * carries {@code agent_id}.
 *
 * @deprecated Emit through {@link com.pingidentity.ps.oidf.platform.events.Events}. Kept while federation code
 *     still emits through it (plan item H-FED-10, checked 2026-10-01); removed at 1.0.0.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
public record FederationEvent(String code, Outcome outcome, String reason, String subject, String partner,
                              String role, String description, Map<String, String> fields, String requestJti,
                              boolean audit, String category, String component) {

    /** Fields the privacy rule removes when {@code agent_id} is present. */
    static final List<String> NEVER_BESIDE_AGENT_ID = Event.NEVER_BESIDE_AGENT_ID;

    public enum Outcome {
        SUCCESS, FAILURE;

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }

        Event.Outcome platform() {
            return this == SUCCESS ? Event.Outcome.SUCCESS : Event.Outcome.FAILURE;
        }

        static Outcome of(Event.Outcome outcome) {
            return outcome == Event.Outcome.SUCCESS ? SUCCESS : FAILURE;
        }
    }

    public FederationEvent {
        Event normalised = new Event(code, outcome == null ? null : outcome.platform(), reason, subject, partner, role,
                description, fields, requestJti, audit, category, component);
        outcome = Outcome.of(normalised.outcome());
        fields = normalised.fields();
        category = normalised.category();
        component = normalised.component();
    }

    /** The record as it was before events had a component: the component is {@link Event#DEFAULT_COMPONENT}'s. */
    public FederationEvent(String code, Outcome outcome, String reason, String subject, String partner, String role,
                           String description, Map<String, String> fields, String requestJti, boolean audit,
                           String category) {
        this(code, outcome, reason, subject, partner, role, description, fields, requestJti, audit, category, null);
    }

    /** See {@link Event#categoryOf}. */
    static String categoryOf(String code) {
        return Event.categoryOf(code);
    }

    public boolean isFailure() {
        return this.outcome == Outcome.FAILURE;
    }

    /** This event as platform's. */
    public Event toEvent() {
        return new Event(this.code, this.outcome.platform(), this.reason, this.subject, this.partner, this.role,
                this.description, this.fields, this.requestJti, this.audit, this.category, this.component);
    }

    /** Platform's event as this façade's. */
    public static FederationEvent from(Event event) {
        return new FederationEvent(event.code(), Outcome.of(event.outcome()), event.reason(), event.subject(),
                event.partner(), event.role(), event.description(), event.fields(), event.requestJti(), event.audit(),
                event.category(), event.component());
    }

    /** Starts an event of {@code code}; its component is the catalogue's that declares the code. */
    public static Builder builder(String code) {
        return new Builder(code);
    }

    /** Fluent construction over platform's builder; {@link #emit()} hands the event to {@link FederationEvents}. */
    public static final class Builder {
        private final Event.Builder delegate;

        private Builder(String code) {
            this.delegate = Event.builder(null, code);
        }

        public Builder success() {
            this.delegate.success();
            return this;
        }

        /** Marks the event a failure with a short machine {@code reason} ({@code signature}, {@code no_route_to_anchor}). */
        public Builder failure(String reasonCode) {
            this.delegate.failure(reasonCode);
            return this;
        }

        public Builder subject(String value) {
            this.delegate.subject(value);
            return this;
        }

        public Builder partner(String value) {
            this.delegate.partner(value);
            return this;
        }

        /** PingFederate's audit {@code role} column: {@code OP}, {@code TA}, {@code ATTESTER}, ... */
        public Builder role(String value) {
            this.delegate.role(value);
            return this;
        }

        public Builder description(String value) {
            this.delegate.description(value);
            return this;
        }

        /** Adds a field; a {@code null} value is skipped, a collection is joined with spaces. */
        public Builder field(String name, Object value) {
            this.delegate.field(name, value);
            return this;
        }

        public Builder requestJti(String value) {
            this.delegate.requestJti(value);
            return this;
        }

        /** Marks the event as belonging in PingFederate's security audit log as well as the server log. */
        public Builder audit() {
            this.delegate.audit();
            return this;
        }

        public Builder category(String value) {
            this.delegate.category(value);
            return this;
        }

        public FederationEvent build() {
            return from(this.delegate.build());
        }

        /** Builds the event and hands it to the configured sink. */
        public FederationEvent emit() {
            FederationEvent event = this.build();
            FederationEvents.emit(event);
            return event;
        }
    }
}
