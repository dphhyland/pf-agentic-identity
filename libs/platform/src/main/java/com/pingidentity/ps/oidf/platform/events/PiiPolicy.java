/*
 * What each class of personal data may do in each log.
 */
package com.pingidentity.ps.oidf.platform.events;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * For each log an event reaches ({@link Destination}) and each {@link PiiClass}, what happens to a value of that
 * class: kept, replaced by a digest, or dropped. A sink applies it after {@link EventCatalogues#admit}, so every
 * field it sees has a class.
 *
 * <p>The subject and partner columns are classed here, not in the catalogues: both hold the identifier of a
 * party - a client id, an entity identifier - so both are {@link PiiClass#PSEUDONYMOUS_ID}. The reason, role and
 * request {@code jti} are {@link PiiClass#OPERATIONAL} - codes, constants and a token's identifier - and never
 * removed. The caller's address, which platform-pf's audit sink writes in the audit log's {@code ip} column, is
 * {@link PiiClass#NETWORK}, through {@link #treat}.
 *
 * <p>The description is free text and has no class: emitters put in it the free-text {@code reason} of an
 * administrator's request, an external policy decision point's {@code reason_admin}, exception messages, and
 * client ids and key thumbprints (checked 2026-09-28 against the emitters). It can therefore carry a value of any
 * class, a direct identifier included, so it has its own treatment per log ({@link #withDescription}), which a
 * policy that digests or drops a class must set as well (finding F-0166).
 *
 * <p>{@link #DEFAULT} keeps every class, and the description, in both logs, which is what reached them before the
 * catalogues existed (2026-09-28): O-1 classifies and does not yet change a line. Whether a direct identifier -
 * the self-declared name in an administrator's {@code actor}, or a name in free text - should be digested or
 * dropped in server.log is left to the PII policy of plan item D-6 (findings F-0165 and F-0166);
 * {@link Treatment#DIGEST} and {@link Treatment#DROP} are the mechanisms it would use.
 */
public final class PiiPolicy {
    /** The logs an event can reach. */
    public enum Destination {
        /** server.log, through {@link LoggingSink}. */
        SERVER_LOG,
        /** PingFederate's security audit log, through platform-pf's audit sink. */
        AUDIT_LOG
    }

    /** What happens to a value. */
    public enum Treatment {
        /** Written as it is, through {@link LogSafe}. */
        KEEP,
        /**
         * Replaced by {@code sha256:<12 hex>} of the value, so lines about one party still correlate. An unkeyed
         * digest of a guessable value (an e-mail address) can be reversed by guessing: it hides a value from a
         * casual reader, not from a determined one.
         */
        DIGEST,
        /** Left out of the line. */
        DROP
    }

    /** Every class, and the description, kept in both logs: what reached them before the catalogues existed. */
    public static final PiiPolicy DEFAULT = new PiiPolicy(Map.of(), Map.of());

    private final Map<Destination, Map<PiiClass, Treatment>> rules;
    private final Map<Destination, Treatment> descriptions;

    private PiiPolicy(Map<Destination, Map<PiiClass, Treatment>> rules, Map<Destination, Treatment> descriptions) {
        Map<Destination, Map<PiiClass, Treatment>> copy = new EnumMap<>(Destination.class);
        Map<Destination, Treatment> descriptionCopy = new EnumMap<>(Destination.class);
        for (Destination destination : Destination.values()) {
            Map<PiiClass, Treatment> perClass = new EnumMap<>(PiiClass.class);
            for (PiiClass pii : PiiClass.values()) {
                Treatment treatment = rules.getOrDefault(destination, Map.of()).get(pii);
                perClass.put(pii, treatment == null ? Treatment.KEEP : treatment);
            }
            copy.put(destination, perClass);
            descriptionCopy.put(destination, descriptions.getOrDefault(destination, Treatment.KEEP));
        }
        this.rules = copy;
        this.descriptions = descriptionCopy;
    }

    /** This policy with {@code pii} treated as {@code treatment} in {@code destination}. */
    public PiiPolicy with(Destination destination, PiiClass pii, Treatment treatment) {
        Map<Destination, Map<PiiClass, Treatment>> changed = new EnumMap<>(Destination.class);
        for (Map.Entry<Destination, Map<PiiClass, Treatment>> entry : this.rules.entrySet()) {
            changed.put(entry.getKey(), new EnumMap<>(entry.getValue()));
        }
        changed.get(Objects.requireNonNull(destination, "destination"))
                .put(Objects.requireNonNull(pii, "pii"), Objects.requireNonNull(treatment, "treatment"));
        return new PiiPolicy(changed, this.descriptions);
    }

    /**
     * This policy with the free-text description treated as {@code treatment} in {@code destination}: kept,
     * replaced by a digest (which still tells two lines' descriptions apart), or dropped.
     */
    public PiiPolicy withDescription(Destination destination, Treatment treatment) {
        Map<Destination, Treatment> changed = new EnumMap<>(this.descriptions);
        changed.put(Objects.requireNonNull(destination, "destination"), Objects.requireNonNull(treatment, "treatment"));
        return new PiiPolicy(this.rules, changed);
    }

    public Treatment treatment(Destination destination, PiiClass pii) {
        return this.rules.get(destination).get(pii);
    }

    /** What happens to the description in {@code destination}. */
    public Treatment descriptionTreatment(Destination destination) {
        return this.descriptions.get(destination);
    }

    /**
     * The event as {@code destination} may carry it. A field's class comes from the event's component's catalogue;
     * a field the catalogue does not classify - which {@link EventCatalogues#admit} has already dropped - is dropped
     * here too. The subject and partner are treated as {@link PiiClass#PSEUDONYMOUS_ID}, and the description by its
     * own treatment.
     */
    public Event apply(Event event, Destination destination, EventCatalogues catalogues) {
        EventCatalogue catalogue = catalogues.component(event.component()).orElse(null);
        Map<String, String> fields = new LinkedHashMap<>();
        for (Map.Entry<String, String> field : event.fields().entrySet()) {
            PiiClass pii = catalogue == null ? null : catalogue.classOf(field.getKey()).orElse(null);
            String value = pii == null ? null : this.treat(destination, pii, field.getValue());
            if (value != null) {
                fields.put(field.getKey(), value);
            }
        }
        String subject = this.treat(destination, PiiClass.PSEUDONYMOUS_ID, event.subject());
        String partner = this.treat(destination, PiiClass.PSEUDONYMOUS_ID, event.partner());
        String description = treat(this.descriptionTreatment(destination), event.description());
        if (fields.equals(event.fields()) && Objects.equals(subject, event.subject())
                && Objects.equals(partner, event.partner()) && Objects.equals(description, event.description())) {
            return event;
        }
        return event.withFields(fields).withParties(subject, partner).withDescription(description);
    }

    /**
     * {@code value} as {@code destination} may carry a value of class {@code pii}; {@code null} when dropped. A sink
     * uses it for a value that is not an event's field, such as the caller's address ({@link PiiClass#NETWORK}).
     */
    public String treat(Destination destination, PiiClass pii, String value) {
        return treat(this.treatment(destination, pii), value);
    }

    private static String treat(Treatment treatment, String value) {
        if (value == null) {
            return null;
        }
        return switch (treatment) {
            case KEEP -> value;
            case DIGEST -> "sha256:" + LogSafe.sha256Hex12(value);
            case DROP -> null;
        };
    }
}
