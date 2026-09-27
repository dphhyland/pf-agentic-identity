/*
 * The three types this repo's deployments use, modelled from RFC 9396 and the code and tests here.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The built-in models. Every type starts from the RFC 9396 §2.2 common data fields ({@code actions},
 * {@code locations}, {@code datatypes}, {@code privileges} as sets, {@code identifier} a string) plus
 * three names seen in this repo. {@code purpose} is a string the RAR plugin's and pf-integration's tests
 * send and the plugin's consent text drops. The other two are markers, and forbidden here:
 * {@code _principal_sub} is the client-asserted principal a BFF folds into a detail, which the RAR plugin
 * reads only when "Trust a client-asserted principal" is on (off by default; plan item S2b makes it
 * development-only) and always strips; {@code _agent_id} is the marker the client-attestation filter
 * writes into every detail of a request it verified, over whatever a client wrote under that name. The
 * wiring (S1b, S1c) must strip both before it asks the model: a detail that reaches the model still
 * carrying one is refused as malformed, with a message that says so.
 *
 * <ul>
 *   <li>{@code sales_agent}: {@code sales_regions} (set) and {@code max_txn_eur} (limit, the unit in
 *       the name), the example the CAS specification and this repo's demos use.</li>
 *   <li>{@code payment_initiation}: RFC 9396 Figure 2 - {@code instructedAmount} (amount),
 *       {@code creditorName} and {@code remittanceInformationUnstructured} (string), {@code creditorAccount}
 *       (equal) - plus {@code debtorAccount} (equal), which the RAR plugin's consent text prints and RFC
 *       9396 Figures 20 and 21 show, and the flat {@code amount} (limit, paired with {@code currency}) and
 *       {@code currency} (string) that the consent text reads and the plugin's tests send. The amount has
 *       two spellings, {@code instructedAmount} or the flat pair, so they are alternatives: a detail uses
 *       one, and a ceiling that uses one holds the request to it.</li>
 *   <li>{@code account_information}: {@code accounts} (set of values, account objects included),
 *       {@code validUntil} (instant limit) and {@code recurringIndicator} (equal). RFC 9396 §7.1's
 *       {@code access} object is not here: its example sends empty arrays, which the plan's rules refuse,
 *       it reads a member it leaves out as "no access" where a ceiling here reads it as unconstrained, and
 *       it names accounts a second way beside {@code accounts}. A deployment that uses it adds it with a
 *       models document that forbids {@code accounts}.</li>
 * </ul>
 *
 * <p>The common-fields fallback, allowed in the development profile only, is the common set above
 * and nothing else; it applies to any type no model names.
 */
final class BuiltIn {

    /** The name the fallback model reports as its type: it stands for any type no model names. */
    static final String COMMON_FIELDS = "common-fields";

    private BuiltIn() {
    }

    static Map<String, TypeModel> models() {
        Map<String, TypeModel> out = new LinkedHashMap<>();

        Map<String, FieldRule> sales = common();
        sales.put("sales_regions", FieldRule.of(Rule.SET));
        sales.put("max_txn_eur", FieldRule.of(Rule.LIMIT));
        out.put("sales_agent", new TypeModel("sales_agent", sales));

        Map<String, FieldRule> payment = common();
        payment.put("instructedAmount", FieldRule.of(Rule.AMOUNT));
        payment.put("amount", FieldRule.limit("currency"));
        payment.put("currency", FieldRule.of(Rule.STRING));
        payment.put("creditorName", FieldRule.of(Rule.STRING));
        payment.put("creditorAccount", FieldRule.of(Rule.EQUAL));
        payment.put("debtorAccount", FieldRule.of(Rule.EQUAL));
        payment.put("remittanceInformationUnstructured", FieldRule.of(Rule.STRING));
        out.put("payment_initiation", new TypeModel("payment_initiation", payment,
                List.of(List.of(List.of("instructedAmount"), List.of("amount", "currency")))));

        Map<String, FieldRule> accounts = common();
        accounts.put("accounts", FieldRule.of(Rule.SET_OF_VALUES));
        accounts.put("validUntil", FieldRule.of(Rule.INSTANT_LIMIT));
        accounts.put("recurringIndicator", FieldRule.of(Rule.EQUAL));
        out.put("account_information", new TypeModel("account_information", accounts));

        return out;
    }

    /** The fallback for unmodelled types: the common fields and nothing else. */
    static TypeModel commonFields() {
        return new TypeModel(COMMON_FIELDS, common());
    }

    private static Map<String, FieldRule> common() {
        Map<String, FieldRule> out = new LinkedHashMap<>();
        out.put("actions", FieldRule.of(Rule.SET));
        out.put("locations", FieldRule.of(Rule.SET));
        out.put("datatypes", FieldRule.of(Rule.SET));
        out.put("privileges", FieldRule.of(Rule.SET));
        out.put("identifier", FieldRule.of(Rule.STRING));
        out.put("purpose", FieldRule.of(Rule.STRING));
        out.put("_principal_sub", FieldRule.of(Rule.FORBIDDEN));
        out.put("_agent_id", FieldRule.of(Rule.FORBIDDEN));
        return out;
    }
}
