package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** DefaultComponents holds the table docs/development/settings-catalogue.md prints, line for line. */
class DefaultComponentsTest {

    private static final Path DOC = Path.of("..", "..", "docs", "development", "settings-catalogue.md");
    private static final Pattern ROW = Pattern.compile("\\|\\s*`([a-z0-9-]+)`\\s*\\|(.*)\\|");
    private static final Pattern NAME = Pattern.compile("`([^`]+)`");

    @Test
    void theTableInTheDocIsTheTableInTheCode() throws IOException {
        String doc = Files.readString(DOC, StandardCharsets.UTF_8);
        String table = doc.split(Pattern.quote("<!-- components table: tools/settings-scan.py and DefaultComponentsTest read it -->"), 2)[1]
                .split(Pattern.quote("<!-- end components table -->"), 2)[0];
        Map<String, List<String>> rows = new LinkedHashMap<>();
        for (String line : table.split("\n")) {
            Matcher row = ROW.matcher(line.strip());
            if (row.matches()) {
                List<String> components = new ArrayList<>();
                Matcher name = NAME.matcher(row.group(2));
                while (name.find()) {
                    components.add(name.group(1));
                }
                rows.put(row.group(1), components);
            }
        }
        assertEquals(DefaultComponents.TABLE, rows);
        assertTrue(rows.size() >= 27, "every catalogue of 0.6.0: " + rows.keySet());
    }
}
