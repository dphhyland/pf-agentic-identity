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
 * <p>Built in Phase 2 (plan item ST-2) and refused from 0.6.0: the start-up sweep ({@link ProfileAudit}) makes each
 * name a violation that refuses the components of the catalogues whose family it falls under (Phase 3 plan,
 * decision 5).
 */
public final class UnknownKeys {

    private UnknownKeys() {
    }

    /**
     * The names in {@code environment} that start with a family prefix of any of {@code catalogues} and that
     * none of them declares ({@link Catalogue#declaredEnvironmentNames()}: entries, aliases, {@code _FILE}
     * variants and removed names), sorted. Names outside every family are not this function's business: another
     * component may own them. A removed name is declared, not unknown: its catalogue refuses it with a better
     * message, naming what replaces it ({@link Catalogue#refuseRemoved}, which {@link Settings} calls on every read).
     *
     * @param environment the process environment, for example {@link System#getenv()}
     * @param catalogues  every catalogue loaded
     */
    public static List<String> find(Map<String, String> environment, Collection<Catalogue> catalogues) {
        return find(environment.keySet(), catalogues);
    }

    /** As {@link #find(Map, Collection)}, for the environment's names. */
    public static List<String> find(Set<String> names, Collection<Catalogue> catalogues) {
        Set<String> families = new HashSet<>();
        Set<String> declared = new HashSet<>();
        for (Catalogue catalogue : catalogues) {
            families.addAll(catalogue.families());
            declared.addAll(catalogue.declaredEnvironmentNames());
        }
        Set<String> unknown = new TreeSet<>();
        for (String name : names) {
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
