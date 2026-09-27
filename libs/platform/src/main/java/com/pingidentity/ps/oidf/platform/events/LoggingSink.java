/*
 * The default event sink: one line per event in the server log.
 */
package com.pingidentity.ps.oidf.platform.events;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Writes each event as one line through {@link PlatformLog}, which in PingFederate is commons-logging, routed
 * to log4j2 and so to {@code server.log} (where PingFederate's own pattern adds the timestamp and its
 * {@code trackingid}):
 *
 * <pre>event=federation.registration.created outcome=success subject=https://rp.example partner=https://ta.example type=automatic desc="registered from trust chain"</pre>
 *
 * <p>The logger is the event's component's {@code logger} from its catalogue, a dot and the event's category -
 * {@code com.pingidentity.ps.oidf.federation.event.registration} - so an operator can raise or lower one family
 * without touching the rest; an event no catalogue declares is written under {@link #FALLBACK_LOGGER}. A code its
 * catalogue marks {@code debug} (a chatty one) is written at DEBUG; otherwise a failure that belongs in the audit
 * log is written at WARN and everything else, an uncatalogued code included, at INFO.
 *
 * <p>Before writing, the event is admitted by its catalogue ({@link EventCatalogues#admit}: an undeclared field
 * is dropped and counted) and passed through the {@link PiiPolicy} for {@link PiiPolicy.Destination#SERVER_LOG}.
 * Every value then goes through {@link LogSafe}.
 */
public final class LoggingSink implements EventSink {
    /** The logger prefix of an event no catalogue declares. */
    public static final String FALLBACK_LOGGER = "com.pingidentity.ps.oidf.federation.event";

    /** The three levels an event line is written at. */
    enum Level { DEBUG, INFO, WARN }

    /** Writes one line at one level on one logger; the production one is {@link PlatformLog}. */
    interface Writer {
        boolean isDebugEnabled(String logger);

        void write(String logger, Level level, String line);
    }

    private final Supplier<EventCatalogues> catalogues;
    private final PiiPolicy policy;
    private final Writer writer;

    /** This loader's catalogues and {@link PiiPolicy#DEFAULT}. */
    public LoggingSink() {
        this(EventCatalogues::current, PiiPolicy.DEFAULT);
    }

    public LoggingSink(Supplier<EventCatalogues> catalogues, PiiPolicy policy) {
        this(catalogues, policy, new PlatformLogWriter());
    }

    LoggingSink(Supplier<EventCatalogues> catalogues, PiiPolicy policy, Writer writer) {
        this.catalogues = Objects.requireNonNull(catalogues, "catalogues");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    @Override
    public void emit(Event event) {
        try {
            EventCatalogues known = this.catalogues.get();
            Event admitted = known.admit(event);
            EventCatalogue.Code declared = known.code(admitted.code()).orElse(null);
            String logger = known.component(admitted.component()).map(EventCatalogue::logger).orElse(FALLBACK_LOGGER)
                    + "." + admitted.category();
            Level level = level(admitted, declared);
            if (level == Level.DEBUG && !this.writer.isDebugEnabled(logger)) {
                return;
            }
            Event written = this.policy.apply(admitted, PiiPolicy.Destination.SERVER_LOG, known);
            this.writer.write(logger, level, format(written));
        } catch (RuntimeException ignored) {
            // Recording an event never fails the request it describes.
        }
    }

    /**
     * DEBUG for a code its catalogue marks {@code debug}, whatever its outcome (a chatty family stays quiet, as the
     * fetches always were); otherwise WARN for a failure that belongs in the audit log, and INFO for the rest.
     */
    static Level level(Event event, EventCatalogue.Code declared) {
        if (declared != null && declared.level() == EventCatalogue.Level.DEBUG) {
            return Level.DEBUG;
        }
        return event.isFailure() && event.audit() ? Level.WARN : Level.INFO;
    }

    /** The line this sink writes for {@code event}, every field it carries included. */
    public static String format(Event event) {
        StringBuilder line = new StringBuilder(160);
        line.append("event=").append(LogSafe.quoted(event.code()));
        line.append(" outcome=").append(event.outcome().code());
        if (event.reason() != null) {
            line.append(" reason=").append(LogSafe.quoted(event.reason()));
        }
        if (event.subject() != null) {
            line.append(" subject=").append(LogSafe.quoted(event.subject()));
        }
        if (event.partner() != null) {
            line.append(" partner=").append(LogSafe.quoted(event.partner()));
        }
        for (Map.Entry<String, String> field : event.fields().entrySet()) {
            line.append(' ').append(LogSafe.value(field.getKey()).replace(' ', '_').replace('=', '_'))
                    .append('=').append(LogSafe.quoted(field.getValue()));
        }
        if (event.requestJti() != null) {
            line.append(" request_jti=").append(LogSafe.quoted(event.requestJti()));
        }
        if (event.description() != null) {
            line.append(" desc=").append(LogSafe.quoted(event.description()));
        }
        return line.toString();
    }

    /** Lines through {@link PlatformLog}, one logger per name, the first {@link #MAX_CACHED} names kept. */
    static final class PlatformLogWriter implements Writer {
        static final int MAX_CACHED = 256;

        private final Map<String, PlatformLog> logs = new ConcurrentHashMap<>();

        PlatformLog log(String logger) {
            PlatformLog log = this.logs.get(logger);
            if (log == null) {
                log = PlatformLog.get(logger);
                if (this.logs.size() < MAX_CACHED) {
                    this.logs.put(logger, log);
                }
            }
            return log;
        }

        @Override
        public boolean isDebugEnabled(String logger) {
            return this.log(logger).isDebugEnabled();
        }

        @Override
        public void write(String logger, Level level, String line) {
            PlatformLog log = this.log(logger);
            switch (level) {
                case DEBUG -> log.debug(line);
                case INFO -> log.info(line);
                case WARN -> log.warn(line);
            }
        }
    }
}
