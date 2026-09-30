/*
 * Collects event catalogues, and the problems met on the way.
 */
package com.pingidentity.ps.oidf.platform.events;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an {@link EventCatalogues}: reads each catalogue an index lists, from the index's own jar, and applies
 * the duplicate rules - the same document twice is read once; a second, different document for a component, or a
 * code a second component declares, is set aside and reported, the first kept.
 */
final class CatalogueCollector {
    private final Map<String, EventCatalogue> components = new LinkedHashMap<>();
    private final Map<String, String> sources = new LinkedHashMap<>();
    private final Map<String, EventCatalogue.Code> codes = new LinkedHashMap<>();
    private final List<String> problems = new ArrayList<>();

    void read(URL index, String name) {
        if (!EventCatalogue.COMPONENT.matcher(name).matches()) {
            this.problems.add(index + " lists " + LogSafe.quoted(name) + ", which is not a component name");
            return;
        }
        String text;
        EventCatalogue catalogue;
        try {
            text = EventCatalogues.read(new URL(index, name + ".json"));
            catalogue = EventCatalogue.parse(text);
        } catch (IOException | IllegalArgumentException e) {
            this.problems.add("the catalogue of " + name + " beside " + index + " was left out: " + e.getMessage());
            return;
        }
        if (!catalogue.component().equals(name)) {
            this.problems.add(name + ".json beside " + index + " names the component " + catalogue.component()
                    + "; it was left out");
            return;
        }
        this.add(catalogue, text, index.toString());
    }

    void add(EventCatalogue catalogue, String text, String where) {
        String name = catalogue.component();
        if (this.components.containsKey(name)) {
            if (text == null || !text.equals(this.sources.get(name))) {
                this.problems.add("a second, different catalogue of " + name + " (" + where + ") was set aside");
            }
            return;
        }
        for (String code : catalogue.codes().keySet()) {
            EventCatalogue.Code other = this.codes.get(code);
            if (other != null) {
                this.problems.add(name + " declares " + code + ", which " + other.component()
                        + " declares; the catalogue of " + name + " was set aside");
                return;
            }
        }
        this.components.put(name, catalogue);
        this.sources.put(name, text);
        this.codes.putAll(catalogue.codes());
    }

    EventCatalogues build() {
        return new EventCatalogues(this.components, this.codes, this.problems);
    }

    void problem(String problem) {
        this.problems.add(problem);
    }
}
