package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.EntryKind;
import com.pingidentity.ps.oidf.platform.settings.Setting;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * PF drops an extended-property name it has not been told about, so every deployment running these modules must
 * declare all of them. This pins the names this module writes onto a client to the catalogue that declares them.
 *
 * <p>The check first read {@code ../../deploy/pingfederate/terraform/extended-properties.tf} behind an {@code
 * assumeTrue(Files.exists(...))} guard, which would have skipped forever once the deploy tree moved out; then it held
 * {@code docs/extended-properties.json} to this constant. Now the catalogue is the source: {@code client-properties}
 * in this module's {@code META-INF/oidf-settings} declares every extended property the module reads or writes,
 * {@code tools/config-reference.py} generates {@code docs/extended-properties.json} from every catalogue and CI fails
 * when the file is not current, and consuming repos diff their own Terraform against that file. A name written here
 * but not catalogued would be missing from the published contract, so this test fails first.
 */
class FederationClientParamsTest {

    /** The component that declares this module's extended properties, loaded as PingFederate would load it. */
    private static final Catalogue CATALOGUE = Catalogue.load(FederationClientParams.class.getClassLoader(),
            "client-properties");

    private static List<String> catalogued() {
        return CATALOGUE.settings().stream()
                .filter(s -> s.kind() == EntryKind.EXTENDED_PROPERTY)
                .map(Setting::name)
                .toList();
    }

    @Test
    void everyNameThisModuleWritesIsACataloguedExtendedProperty() {
        List<String> missing = FederationClientParams.EXTENDED_PARAM_NAMES.stream()
                .filter(name -> !catalogued().contains(name))
                .toList();

        assertEquals(List.of(), missing, "FederationClientParams.EXTENDED_PARAM_NAMES writes names the client-properties"
                + " catalogue does not declare as extended properties, so docs/extended-properties.json would not ask a"
                + " deployment to declare them and PF would drop them. Catalogue them, then run"
                + " python3 tools/config-reference.py.");
    }

    /** {@code status} is what distinguishes a module-registered client from an administrator's. */
    @Test
    void statusIsCataloguedAndBearsOnSecurity() {
        Setting status = CATALOGUE.setting(FederationClientParams.STATUS);

        assertEquals(EntryKind.EXTENDED_PROPERTY, status.kind());
        assertTrue(status.security(), "both registration paths refuse to touch a client without 'status'; a deployment"
                + " that does not declare it cannot register anything");
        assertEquals(List.of(RegistrationService.STATUS_REGISTERED, RegistrationService.STATUS_AUTO), status.choices());
    }
}
