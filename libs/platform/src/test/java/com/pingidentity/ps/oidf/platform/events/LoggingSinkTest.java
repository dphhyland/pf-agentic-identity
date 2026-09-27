/*
 * The server-log sink: which logger, which level, and what the line holds.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class LoggingSinkTest {

    private record Line(String logger, LoggingSink.Level level, String text) {
    }

    /** A writer that keeps what it is given, with DEBUG on or off. */
    private static final class Lines implements LoggingSink.Writer {
        final List<Line> lines = new ArrayList<>();
        final boolean debug;

        Lines(boolean debug) {
            this.debug = debug;
        }

        @Override
        public boolean isDebugEnabled(String logger) {
            return this.debug;
        }

        @Override
        public void write(String logger, LoggingSink.Level level, String line) {
            this.lines.add(new Line(logger, level, line));
        }
    }

    @AfterEach
    void reset() {
        Events.reset();
    }

    private static LoggingSink sink(Lines lines, PiiPolicy policy) {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        return new LoggingSink(() -> catalogues, policy, lines);
    }

    @Test
    void theLoggerIsTheCataloguesPrefixAndTheCategory() {
        Lines lines = new Lines(false);
        LoggingSink sink = sink(lines, PiiPolicy.DEFAULT);

        sink.emit(Event.builder(null, "shop.order.placed").field("item", "tea").build());
        sink.emit(Event.builder(null, "nobody.declares.this").field("item", "tea").build());

        assertEquals(new Line("com.example.shop.event.shop", LoggingSink.Level.INFO,
                "event=shop.order.placed outcome=success item=tea"), lines.lines.get(0));
        assertEquals(new Line(LoggingSink.FALLBACK_LOGGER + ".nobody", LoggingSink.Level.INFO,
                "event=nobody.declares.this outcome=success"), lines.lines.get(1));
    }

    @Test
    void aSecurityRefusalIsWarnAndADebugCodeIsWrittenOnlyWhenDebugIsOn() {
        Lines off = new Lines(false);
        LoggingSink quiet = sink(off, PiiPolicy.DEFAULT);
        quiet.emit(Event.builder(null, "shop.order.refused").failure("no_stock").audit().build());
        quiet.emit(Event.builder(null, "shop.order.refused").failure("no_stock").build());
        quiet.emit(Event.builder(null, "shop.stock.checked").build());
        assertEquals(List.of(LoggingSink.Level.WARN, LoggingSink.Level.INFO), off.lines.stream().map(Line::level).toList());

        Lines on = new Lines(true);
        sink(on, PiiPolicy.DEFAULT).emit(Event.builder(null, "shop.stock.checked").failure("x").audit().build());
        sink(on, PiiPolicy.DEFAULT).emit(Event.builder(null, "shop.stock.checked").build());
        assertEquals(List.of(LoggingSink.Level.WARN, LoggingSink.Level.DEBUG), on.lines.stream().map(Line::level).toList());
    }

    @Test
    void theServerLogPolicyIsAppliedAfterTheCatalogue() {
        Lines lines = new Lines(false);
        PiiPolicy digest = PiiPolicy.DEFAULT.with(PiiPolicy.Destination.SERVER_LOG, PiiClass.DIRECT_ID, PiiPolicy.Treatment.DIGEST);

        sink(lines, digest).emit(Event.builder(null, "shop.order.placed").field("buyer", "jane@example.com")
                .field("secret", "hunter2").build());

        String line = lines.lines.get(0).text();
        assertFalse(line.contains("jane@example.com"), line);
        assertFalse(line.contains("hunter2"), line);
        assertTrue(line.contains("buyer=sha256:"), line);
    }

    @Test
    void aSinkThatFailsInsideNeverThrows() {
        new LoggingSink(() -> {
            throw new IllegalStateException("no catalogues");
        }, PiiPolicy.DEFAULT, new Lines(false)).emit(Event.builder("shop", "a.b").build());
    }

    @Test
    void theLevelRule() {
        Event refused = Event.builder("shop", "a.b").failure("r").audit().build();
        Event failed = Event.builder("shop", "a.b").failure("r").build();
        Event audited = Event.builder("shop", "a.b").audit().build();
        EventCatalogue.Code debug = TestCatalogues.shop().code("shop.stock.checked").orElseThrow();
        EventCatalogue.Code info = TestCatalogues.shop().code("shop.order.placed").orElseThrow();
        assertEquals(LoggingSink.Level.WARN, LoggingSink.level(refused, debug));
        assertEquals(LoggingSink.Level.DEBUG, LoggingSink.level(failed, debug));
        assertEquals(LoggingSink.Level.DEBUG, LoggingSink.level(audited, debug));
        assertEquals(LoggingSink.Level.INFO, LoggingSink.level(failed, info));
        assertEquals(LoggingSink.Level.INFO, LoggingSink.level(failed, null));
    }

    @Test
    void theLineIsKeyValueWithQuotingWhereNeeded() {
        Event event = Event.builder("shop", "federation.registration.created").subject("https://rp.example")
                .partner("https://ta.example").field("scope", "openid email").field("odd key=", "v").requestJti("j")
                .description("registered from trust chain").build();

        assertEquals("event=federation.registration.created outcome=success subject=https://rp.example "
                + "partner=https://ta.example scope=\"openid email\" odd_key_=v request_jti=j "
                + "desc=\"registered from trust chain\"", LoggingSink.format(event));
        assertTrue(LoggingSink.format(Event.builder("shop", "a.b.c").failure("r").build()).contains(" reason=r"));
        String forged = LoggingSink.format(Event.builder("shop", "a.b.c")
                .subject("https://rp.example\nevent=federation.registration.created outcome=success").build());
        assertEquals(1, forged.lines().count(), forged);
    }

    @Test
    void theProductionWriterLogsThroughPlatformLogAndKeepsItsLoggers() {
        Logger jul = Logger.getLogger("com.example.writer.test");
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        jul.addHandler(handler);
        jul.setLevel(Level.ALL);
        try {
            LoggingSink.PlatformLogWriter writer = new LoggingSink.PlatformLogWriter();
            assertSame(writer.log("com.example.writer.test"), writer.log("com.example.writer.test"));
            assertTrue(writer.isDebugEnabled("com.example.writer.test"));
            writer.write("com.example.writer.test", LoggingSink.Level.DEBUG, "d");
            writer.write("com.example.writer.test", LoggingSink.Level.INFO, "i");
            writer.write("com.example.writer.test", LoggingSink.Level.WARN, "w");
            assertEquals(List.of("d", "i", "w"), records.stream().map(LogRecord::getMessage).toList());
            for (int i = 0; i < LoggingSink.PlatformLogWriter.MAX_CACHED + 1; i++) {
                writer.log("com.example.writer.many" + i);
            }
            assertTrue(writer.log("com.example.writer.one.more") != writer.log("com.example.writer.one.more"),
                    "past the cap a logger is made each time, not kept");
        } finally {
            jul.removeHandler(handler);
            jul.setLevel(null);
        }
        new LoggingSink().emit(Event.builder("shop", "a.b").build());
    }
}
