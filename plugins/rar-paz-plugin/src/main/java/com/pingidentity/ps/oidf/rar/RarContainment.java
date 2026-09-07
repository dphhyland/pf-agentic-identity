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
 * {@code com.pingidentity.ps.oidf.clientattestation.RarEntitlement} in {@code pf-oidf-modules}; kept local so this plugin
 * builds standalone. TODO: consolidate the two into a shared library.
 */
public final class RarContainment {

    private RarContainment() { }

    /**
     * The RFC 9396 set-valued fields containment compares, plus this deployment's {@code sales_regions}.
     *
     * <p>Must stay identical to {@code RarEntitlement.SET_FIELDS} in {@code libs/client-attestation};
     * {@code RarContainmentContractTest} reads that file and fails if they diverge. Add a field to one
     * and not the other and the PDP sees a constraint containment does not enforce, or the reverse.
     */
    static final String[] SET_FIELDS = {"actions", "locations", "datatypes", "privileges", "sales_regions"};

    /**
     * @return {@code true} when {@code requested} is equal to or a subset of {@code accepted}: the same
     *         {@code type}, and for every set-valued field the {@code accepted} detail constrains, the
     *         requested values are a subset. Fields {@code accepted} omits are unconstrained.
     *
     * <p>Type handling matches {@code RarEntitlement} in {@code libs/client-attestation} deliberately.
     * This method previously skipped the type comparison whenever <em>either</em> side lacked a type,
     * which made a typeless requested detail a subset of any accepted one — while the same detail was
     * refused outright at the token endpoint as {@code invalid_authorization_details}. Two answers to
     * one question, and the permissive one was on the refresh path. A detail with no type is not
     * containable here either.
     */
    public static boolean isSubset(Map<String, Object> requested, Map<String, Object> accepted) {
        if (requested == null) {
            // Nothing requested is within anything. RarEntitlement.authorize says the same by returning
            // an empty grant rather than denying.
            return true;
        }
        if (accepted == null) {
            return false;
        }
        String reqType = str(requested.get("type"));
        if (reqType == null) {
            return false;
        }
        if (!reqType.equals(str(accepted.get("type")))) {
            return false;
        }
        for (String field : SET_FIELDS) {
            if (accepted.containsKey(field) && !asStrings(accepted.get(field)).containsAll(asStrings(requested.get(field)))) {
                return false;
            }
        }
        return true;
    }

    /**
     * "Absent" the way {@code RarEntitlement} decides it: its {@code str} is
     * {@code o == null ? null : String.valueOf(o)}, and {@code authorize} then refuses a type that is
     * null or blank. Both halves are folded in here so a non-String type stringifies identically on
     * both sides rather than one being stricter than the other.
     */
    private static String str(Object value) {
        if (value == null) {
            return null;
        }
        String s = String.valueOf(value);
        return s.isBlank() ? null : s;
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
