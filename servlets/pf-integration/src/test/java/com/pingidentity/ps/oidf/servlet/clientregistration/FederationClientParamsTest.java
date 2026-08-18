package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * PF rejects an extended-property name it has not been told about, and the deploy tree is where it is
 * told. This asserts the Java list and the Terraform declaration agree - the drift that made
 * federation registration depend on a name PF would have refused.
 */
class FederationClientParamsTest {

    private static final Path TF = Path.of("../../deploy/pingfederate/terraform/extended-properties.tf");

    @Test
    void everyParamThisModuleWritesIsDeclaredInTerraform() throws Exception {
        Assumptions.assumeTrue(Files.exists(TF), "deploy tree not present in this checkout");
        String tf = Files.readString(TF);

        List<String> missing = new ArrayList<>();
        for (String name : FederationClientParams.EXTENDED_PARAM_NAMES) {
            if (!tf.contains("name = \"" + name + "\"")) {
                missing.add(name);
            }
        }

        assertTrue(missing.isEmpty(),
                "these are written onto clients but not declared in extended-properties.tf, so PF would "
                        + "reject or drop them: " + missing);
    }
}
