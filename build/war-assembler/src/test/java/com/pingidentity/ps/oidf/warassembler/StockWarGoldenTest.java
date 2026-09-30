package com.pingidentity.ps.oidf.warassembler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The assembler against PingFederate's own war, compared with what the shell assembler made of it. Ping's
 * descriptor is not in this repository, so this runs only when it is given:
 *
 * <pre>
 * docker create --name stock pingidentity/pingfederate@$PF_IMAGE_DIGEST
 * docker cp stock:/opt/server/server/default/deploy/pf-runtime.war /tmp/stock.war
 * mvn verify -pl build/war-assembler -DwarAssembler.stockWar=/tmp/stock.war \
 *     [-DwarAssembler.goldenWebXml=web.xml as the shell assembler wrote it]
 * </pre>
 *
 * <p>The golden result was taken on 2026-09-28: the shell assembler (as of 276bcd6) run against 13.1.3's
 * stock war (the image build/pf-version.env pins by digest), for the production and the conformance stage -
 * the same descriptor for both. Only its digest and our additions to it
 * (golden/shell-assembler-additions.txt) are recorded here. The shipped filters.xml has since declared F-2's
 * lifecycle listener, which the shell assembler never registered: the test checks the listener's block is there once,
 * after the filters, and compares what is left.
 */
class StockWarGoldenTest {
    /** sha256 of WEB-INF/web.xml in 13.1.3's stock pf-runtime.war (2026-09-28). */
    static final String STOCK_13_1_3_WEB_XML = "955d503e3820540c89b846d49ce10c3a87a15cc16d15a7cb3e74f16d14ae81f5";
    /** sha256 of the WEB-INF/web.xml the shell assembler wrote from it, for either profile (2026-09-28). */
    static final String SHELL_ASSEMBLED_WEB_XML = "b0674250dca975b5a1046554ccb14440054bb5b66c4c8f500bc7f9d07e1ff50f";

    @TempDir
    Path dir;

    @Test
    void theAssemblerWritesTheShellAssemblersDescriptorByteForByte() throws IOException, Refusal {
        String stock = System.getProperty("warAssembler.stockWar", "");
        assumeFalse(stock.isBlank(), "set -DwarAssembler.stockWar to PingFederate's stock pf-runtime.war");
        Path stockWar = Path.of(stock);
        Path web = dir.resolve("stock-web.xml");
        Files.write(web, Fixtures.entry(stockWar, "WEB-INF/web.xml"));
        assertEquals(STOCK_13_1_3_WEB_XML, StagedManifest.sha256(web),
                "not 13.1.3's stock war: re-take the golden result from the shell assembler at 276bcd6 before comparing");

        Path out = dir.resolve("out.war");
        Fixtures.Run r = Fixtures.run("--filters", Fixtures.shippedFilters().toString(), stock, Fixtures.stage(dir).toString(),
                "-", out.toString());
        assertEquals(0, r.exit(), r.err());
        String withListener = new String(Fixtures.entry(out, "WEB-INF/web.xml"), StandardCharsets.UTF_8);
        int at = withListener.indexOf(Fixtures.LIFECYCLE_LISTENER_BLOCK);
        assertTrue(at > withListener.lastIndexOf("</filter-mapping>") && at == withListener.lastIndexOf(Fixtures.LIFECYCLE_LISTENER_BLOCK),
                "the listener registered once, after the filters");
        Path merged = dir.resolve("merged-web.xml");
        Files.writeString(merged, withListener.replace(Fixtures.LIFECYCLE_LISTENER_BLOCK, ""), StandardCharsets.UTF_8);
        assertEquals(SHELL_ASSEMBLED_WEB_XML, StagedManifest.sha256(merged));

        String golden = System.getProperty("warAssembler.goldenWebXml", "");
        if (!golden.isBlank()) {
            assertEquals(SHELL_ASSEMBLED_WEB_XML, StagedManifest.sha256(Path.of(golden)));
            WebXml expected = WebXml.parse(Files.readAllBytes(Path.of(golden)), "golden");
            WebXml actual = WebXml.parse(Files.readAllBytes(merged), "merged");
            assertEquals(expected.filters, actual.filters, "the same filters, in the same order");
            assertEquals(expected.filterMappings, actual.filterMappings, "the same mappings, in the same order");
            assertEquals(List.copyOf(expected.servletMappings), List.copyOf(actual.servletMappings));
        }
    }
}
