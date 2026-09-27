/*
 * OIDF_* names under a family prefix that no catalogue declares.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The {@code OIDF_*} environment variables set under a family prefix that no loaded catalogue declares - a
 * misspelt name, or one read by nothing, which today is silently ignored.
 *
 * <p>A mechanism only, in Phase 2 (plan item ST-2; Phase 2 plan decision 7): nothing calls it at run time and
 * nothing is refused for it. Refusing before every module is catalogued (ST-3) would stop working
 * deployments; the start-up audit (PR-5) and the reader conversion (ST-5) wire it in, in Phase 3.
 */
public final class UnknownKeys {

    private UnknownKeys() {
    }

    /**
     * The names in {@code environment} that start with a family prefix of any of {@code catalogues} and that
     * none of them declares ({@link Catalogue#declaredEnvironmentNames()}: entries, aliases, {@code _FILE}
     * variants and removed names), sorted. Names outside every family are not this function's business: another
     * component may own them.
     *
     * @param environment the process environment, for example {@link System#getenv()}
     * @param catalogues  every catalogue loaded
     */
    public static List<String> find(Map<String, String> environment, Collection<Catalogue> catalogues) {
        Set<String> families = new HashSet<>();
        Set<String> declared = new HashSet<>();
        for (Catalogue catalogue : catalogues) {
            families.addAll(catalogue.families());
            declared.addAll(catalogue.declaredEnvironmentNames());
        }
        Set<String> unknown = new TreeSet<>();
        for (String name : environment.keySet()) {
            if (!declared.contains(name) && underAFamily(name, families)) {
                unknown.add(name);
            }
        }
        return new ArrayList<>(unknown);
    }

    private static boolean underAFamily(String name, Set<String> families) {
        for (String family : families) {
            if (name.startsWith(family)) {
                return true;
            }
        }
        return false;
    }
}
