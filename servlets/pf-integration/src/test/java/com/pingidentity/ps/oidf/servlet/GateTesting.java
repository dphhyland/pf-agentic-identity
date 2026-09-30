/*
 * Test helpers for the component parts and the gate: a part's state, a component made healthy again, a gate's answer.
 */
package com.pingidentity.ps.oidf.servlet;

import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The parts live in this loader's {@link Startup}, which every test in the module shares; a test that calls a
 * servlet's or filter's {@code init} and then serves a request first makes the component's other parts, left by
 * earlier tests, ready again ({@link #healthy}).
 */
public final class GateTesting {

    private GateTesting() {
    }

    /** The part registered under {@code name}. */
    public static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    /** Every part of {@code component} registered afresh and made ready, so an earlier test's failure is not this one's. */
    public static void healthy(String component) {
        List<PartStatus> parts = Startup.parts().parts();
        for (PartStatus p : parts) {
            if (p.component().equals(component)) {
                Startup.begin(component, p.part()).ready();
            }
        }
    }

    /** Where {@code response}'s output stream writes, as text. */
    public static ByteArrayOutputStream body(HttpServletResponse response) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                out.write(b);
            }
        });
        return out;
    }

    /** What {@code out} holds. */
    public static String text(ByteArrayOutputStream out) {
        return out.toString(StandardCharsets.UTF_8);
    }
}
