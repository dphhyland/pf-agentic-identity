/*
 * Coarse RFC 9396 containment check for refresh-time authorization_details narrowing.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Set-containment over the common RFC 9396 fields, used by the processor's {@code isEqualOrSubset} to decide
 * whether a (refresh) request stays within a previously-granted detail. Mirrors the semantics of
 * {@code com.pingidentity.ps.oidf.common.RarEntitlement} in {@code pf-oidf-modules}; kept local so this plugin
 * builds standalone. TODO: consolidate the two into a shared library.
 */
public final class RarContainment {

    private RarContainment() { }

    private static final String[] SET_FIELDS = {"actions", "locations", "datatypes", "privileges", "sales_regions"};

    /**
     * @return {@code true} when {@code requested} is equal to or a subset of {@code accepted}: same {@code type}
     *         (when both present) and, for every set-valued field the {@code accepted} detail constrains, the
     *         requested values are a subset. Fields {@code accepted} omits are unconstrained.
     */
    public static boolean isSubset(Map<String, Object> requested, Map<String, Object> accepted) {
        if (requested == null) {
            return true;
        }
        if (accepted == null) {
            return false;
        }
        Object reqType = requested.get("type");
        Object accType = accepted.get("type");
        if (reqType != null && accType != null && !reqType.equals(accType)) {
            return false;
        }
        for (String field : SET_FIELDS) {
            if (accepted.containsKey(field) && !asStrings(accepted.get(field)).containsAll(asStrings(requested.get(field)))) {
                return false;
            }
        }
        return true;
    }

    private static List<String> asStrings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof Collection<?> c) {
            for (Object o : c) {
                if (o != null) {
                    out.add(String.valueOf(o));
                }
            }
        } else if (value != null) {
            out.add(String.valueOf(value));
        }
        return out;
    }
}
