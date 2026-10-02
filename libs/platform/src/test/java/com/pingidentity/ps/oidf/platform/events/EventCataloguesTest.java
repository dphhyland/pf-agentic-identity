/*
 * Loading a loader's catalogues, and admitting events through them.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EventCataloguesTest {

    @TempDir
    Path dir;

    @AfterEach
    void reset() {
        Events.reset();
    }

    /** A module directory holding an index and the named catalogue documents. */
    private Path module(String name, String index, Map<String, String> documents) throws IOException {
        Path root = this.dir.resolve(name);
        Path catalogues = root.resolve(EventCatalogue.DIRECTORY);
        Files.createDirectories(catalogues);
        Files.writeString(root.resolve(EventCatalogue.INDEX), index, StandardCharsets.UTF_8);
        for (Map.Entry<String, String> document : documents.entrySet()) {
            Files.writeString(catalogues.resolve(document.getKey() + ".json"), document.getValue(), StandardCharsets.UTF_8);
        }
        return root;
    }

    private static EventCatalogues load(Path... roots) throws IOException {
        URL[] urls = new URL[roots.length];
        for (int i = 0; i < roots.length; i++) {
            urls[i] = roots[i].toUri().toURL();
        }
        try (URLClassLoader loader = new URLClassLoader(urls, null)) {
            return EventCatalogues.load(loader);
        }
    }

    @Test
    void everyIndexedCatalogueIsReadAndTheSameModuleTwiceIsReadOnce() throws IOException {
        Path shop = this.module("shop", "# the shop\n\nshop\n", Map.of("shop", TestCatalogues.SHOP));
        Path again = this.module("again", "shop\n", Map.of("shop", TestCatalogues.SHOP));
        Path bank = this.module("bank", "bank", Map.of("bank", TestCatalogues.BANK));

        EventCatalogues loaded = load(shop, again, bank);

        assertEquals(List.of(), loaded.problems());
        assertEquals(List.of("shop", "bank"), List.copyOf(loaded.components().keySet()));
        assertEquals(Optional.of("bank"), loaded.componentOf("bank.transfer.made"));
        assertEquals(Optional.empty(), loaded.componentOf("nothing.here"));
        assertEquals("Shop", loaded.component("shop").orElseThrow().auditProtocol());
        assertEquals(Optional.empty(), loaded.component("nobody"));
        assertTrue(loaded.code("shop.order.placed").isPresent());
    }

    @Test
    void whatCannotBeReadIsLeftOutAndReported() throws IOException {
        Path broken = this.module("broken", "Bad_Name\nmissing\ninvalid\nnamed\nshop\n",
                Map.of("invalid", "{", "named", TestCatalogues.BANK, "shop", TestCatalogues.SHOP));
        Path different = this.module("different", "shop\n",
                Map.of("shop", TestCatalogues.SHOP.replace("A shop.", "Another shop.")));
        Path clash = this.module("clash", "clash\n", Map.of("clash", TestCatalogues.BANK
                .replace("\"component\": \"bank\"", "\"component\": \"clash\"")
                .replace("\"bank.transfer.made\"", "\"shop.order.placed\"")));

        EventCatalogues loaded = load(broken, different, clash);

        assertEquals(List.of("shop"), List.copyOf(loaded.components().keySet()));
        List<String> problems = loaded.problems();
        assertEquals(6, problems.size(), problems.toString());
        assertTrue(problems.get(0).contains("lists Bad_Name, which is not a component name"), problems.get(0));
        assertTrue(problems.get(1).contains("the catalogue of missing beside"), problems.get(1));
        assertTrue(problems.get(2).contains("the catalogue of invalid beside"), problems.get(2));
        assertTrue(problems.get(3).contains("named.json beside"), problems.get(3));
        assertTrue(problems.get(4).contains("a second, different catalogue of shop"), problems.get(4));
        assertTrue(problems.get(5).contains("clash declares shop.order.placed, which shop declares"), problems.get(5));
        assertEquals("A shop.", loaded.component("shop").orElseThrow().description(), "the first is kept");
    }

    @Test
    void cataloguesPassedInFollowTheSameRules() {
        EventCatalogues twice = EventCatalogues.of(List.of(TestCatalogues.shop(), TestCatalogues.shop()));
        assertEquals(1, twice.problems().size());
        assertEquals(1, twice.components().size());
    }

    @Test
    void aLoaderThatCannotListOrAnIndexThatCannotBeReadIsAProblemNotAFailure() {
        ClassLoader cannotList = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                throw new IOException("no listing");
            }
        };
        assertTrue(EventCatalogues.load(cannotList).problems().get(0).contains("could not be listed: no listing"));

        URLStreamHandler failing = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                throw new IOException("unreadable");
            }
        };
        ClassLoader unreadable = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                return Collections.enumeration(List.of(new URL("test", "host", 0, "/index.txt", failing)));
            }
        };
        List<String> problems = EventCatalogues.load(unreadable).problems();
        assertTrue(problems.get(0).contains("could not be read: unreadable"), problems.toString());
    }

    @Test
    void theCurrentCataloguesAreThisLoadersUntilATestInstallsOthers() {
        EventCatalogues first = EventCatalogues.current();
        assertSame(first, EventCatalogues.current());
        assertEquals(List.of("platform"), List.copyOf(first.components().keySet()),
                "platform's test classpath carries platform's own catalogue only (PR-5)");
        EventCatalogues installed = TestCatalogues.shopAndBank();
        EventCatalogues.install(installed);
        assertSame(installed, EventCatalogues.current());
        EventCatalogues.forget();
        assertTrue(EventCatalogues.current() != installed);
    }

    // ---- admission ---------------------------------------------------------------------------------

    @Test
    void aDeclaredFieldIsKeptAndAnUndeclaredOneDroppedAndCounted() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        Event event = Event.builder("wrong", "shop.order.placed").field("item", "tea").field("card_number", "4111")
                .field("pin", "1234").build();

        Event admitted = catalogues.admit(event);

        assertEquals(Map.of("item", "tea"), admitted.fields());
        assertEquals("shop", admitted.component(), "the catalogue that declares the code decides the component");
        assertEquals(2, catalogues.droppedFields());
        assertSame(admitted, catalogues.admit(admitted), "admitting an admitted event changes nothing");
        assertEquals(2, catalogues.droppedFields());
        catalogues.admit(event);
        assertEquals(4, catalogues.droppedFields());
        assertEquals(0, catalogues.uncataloguedEvents());
    }

    @Test
    void anUncataloguedEventKeepsItsHeadAndLosesItsFields() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        Event event = Event.builder("shop", "nobody.declares.this").failure("r").subject("s").field("a", "1").build();

        Event admitted = catalogues.admit(event);

        assertEquals(Map.of(), admitted.fields());
        assertEquals("s", admitted.subject());
        assertEquals("r", admitted.reason());
        assertEquals("shop", admitted.component());
        assertEquals(1, catalogues.uncataloguedEvents());
        assertEquals(1, catalogues.droppedFields());
        Event bare = Event.builder("shop", "nobody.declares.this").build();
        assertSame(bare, catalogues.admit(bare));
        assertEquals(2, catalogues.uncataloguedEvents());
    }

    @Test
    void readmittingAppliesTheSameRuleAndCountsNothing() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        Event declared = Event.builder("wrong", "shop.order.placed").field("item", "tea").field("pin", "1234").build();
        Event uncatalogued = Event.builder("shop", "nobody.declares.this").field("a", "1").build();

        Event readmitted = catalogues.readmit(declared);

        assertEquals(Map.of("item", "tea"), readmitted.fields());
        assertEquals("shop", readmitted.component());
        assertEquals(Map.of(), catalogues.readmit(uncatalogued).fields());
        assertEquals(0, catalogues.droppedFields());
        assertEquals(0, catalogues.uncataloguedEvents());
        Event admitted = catalogues.admit(uncatalogued);
        assertSame(admitted, catalogues.readmit(admitted), "readmitting an admitted event changes nothing");
        assertEquals(1, catalogues.uncataloguedEvents());
        assertEquals(1, catalogues.droppedFields());
    }

    @Test
    void onlyTheFirstDropsOfEachPairAreLoggedAndThoseUpToACap() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        for (int i = 0; i < EventCatalogues.MAX_WARNED + 10; i++) {
            catalogues.admit(Event.builder(null, "shop.order.placed").field("f" + i, "v").build());
            catalogues.admit(Event.builder(null, "shop.order.placed").field("f" + i, "v").build());
        }
        assertEquals(2L * (EventCatalogues.MAX_WARNED + 10), catalogues.droppedFields());
    }
}
