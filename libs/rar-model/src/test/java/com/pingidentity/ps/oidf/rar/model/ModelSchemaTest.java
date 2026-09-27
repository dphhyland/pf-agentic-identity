/*
 * What a models document may say, and every way it is refused.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ModelSchemaTest {

    private static Map<String, TypeModel> parse(String json) throws RarModelException {
        return ModelSchema.parse(json, BuiltIn.models());
    }

    private static String refused(String json) {
        RarModelException e = assertThrows(RarModelException.class, () -> parse(json));
        assertEquals(RarModelException.Reason.MODEL_INVALID, e.reason(), e.getMessage());
        return e.getMessage();
    }

    @Test
    void aTypeWithEveryRuleShape() throws Exception {
        Map<String, TypeModel> models = parse("{\"types\":{\"x\":{\"fields\":{"
                + "\"a\":\"set\",\"b\":\"set_of_values\",\"c\":\"limit\",\"d\":{\"rule\":\"limit\"},"
                + "\"e\":{\"rule\":\"limit\",\"unit_field\":\"u\"},\"u\":\"equal\",\"f\":\"amount\",\"g\":\"instant_limit\","
                + "\"h\":{\"rule\":\"equal\"},\"i\":{\"rule\":\"object\",\"fields\":{\"n\":{\"rule\":\"object\",\"fields\":{\"m\":\"set\"}}}},"
                + "\"j\":\"forbidden\"}}}}");
        TypeModel x = models.get("x");
        assertEquals("x", x.type());
        assertEquals(List.of("a", "b", "c", "d", "e", "u", "f", "g", "h", "i", "j"), new ArrayList<>(x.fields().keySet()));
        assertEquals(Rule.LIMIT, x.fields().get("d").rule());
        assertEquals("u", x.fields().get("e").unitField());
        assertEquals(Rule.SET, x.fields().get("i").nested().fields().get("n").nested().fields().get("m").rule());
        assertEquals(List.of("sales_agent", "payment_initiation", "account_information", "x"), new ArrayList<>(models.keySet()));
    }

    @Test
    void documentShape() {
        assertTrue(refused("not json").startsWith("models document: JSON:"));
        assertEquals("models document must be a JSON object", refused("[]"));
        assertTrue(refused("{\"types\":{},\"version\":1}").contains("unknown key 'version'"));
        assertEquals("models document has no 'types'", refused("{}"));
        assertEquals("'types' must be a JSON object", refused("{\"types\":[]}"));
        assertEquals("a type name is blank", refused("{\"types\":{\" \":{\"fields\":{}}}}"));
        assertEquals("type 'x' must be a JSON object", refused("{\"types\":{\"x\":\"set\"}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{},\"rules\":{}}}}").contains("unknown key 'rules'"));
        assertEquals("type 'x' has no 'fields'", refused("{\"types\":{\"x\":{}}}"));
        assertEquals("type 'x' 'fields' must be a JSON object", refused("{\"types\":{\"x\":{\"fields\":[]}}}"));
    }

    @Test
    void extendsRules() throws Exception {
        assertEquals("type 'x': 'extends' must name a type", refused("{\"types\":{\"x\":{\"extends\":1,\"fields\":{}}}}"));
        assertEquals("type 'x': 'extends' must name a type", refused("{\"types\":{\"x\":{\"extends\":\"\",\"fields\":{}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"extends\":\"y\",\"fields\":{}}}}").contains("neither built in nor declared before it"));
        assertTrue(refused("{\"types\":{\"x\":{\"extends\":\"y\",\"fields\":{}},\"y\":{\"fields\":{}}}}")
                .contains("neither built in nor declared before it"), "a later type cannot be extended");
        assertTrue(refused("{\"types\":{\"sales_agent\":{\"fields\":{}}}}").contains("add fields to it with \"extends\": \"sales_agent\""));
        assertTrue(refused("{\"types\":{\"x\":{\"extends\":\"sales_agent\",\"fields\":{\"sales_regions\":\"equal\"}}}}")
                .contains("redefines inherited field 'sales_regions'"));
        Map<String, TypeModel> models = parse("{\"types\":{\"x\":{\"extends\":\"sales_agent\",\"fields\":{\"sales_regions\":\"forbidden\",\"extra\":\"set\"}},"
                + "\"sales_agent\":{\"extends\":\"sales_agent\",\"fields\":{\"more\":\"equal\"}},"
                + "\"y\":{\"extends\":\"x\",\"fields\":{}}}}");
        assertEquals(Rule.FORBIDDEN, models.get("x").fields().get("sales_regions").rule());
        assertEquals(Rule.LIMIT, models.get("x").fields().get("max_txn_eur").rule());
        assertEquals(Rule.SET, models.get("x").fields().get("extra").rule());
        assertEquals(Rule.EQUAL, models.get("sales_agent").fields().get("more").rule(), "the built-in is replaced by its extension");
        assertEquals(Rule.SET, models.get("sales_agent").fields().get("actions").rule());
        assertEquals(models.get("x").fields(), models.get("y").fields());
        assertEquals(List.of("sales_agent", "payment_initiation", "account_information", "x", "y"), new ArrayList<>(models.keySet()),
                "an extended built-in keeps its place");
    }

    /** A built-in's name may extend that built-in and nothing else, so no document replaces it with another type's fields. */
    @Test
    void aBuiltInExtendsOnlyItself() throws Exception {
        assertEquals("type 'payment_initiation' is built in and may extend only itself, not 'sales_agent'",
                refused("{\"types\":{\"payment_initiation\":{\"extends\":\"sales_agent\",\"fields\":{\"amount\":\"limit\",\"currency\":\"equal\"}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"extends\":\"payment_initiation\",\"fields\":{\"instructedAmount\":\"forbidden\"}},"
                + "\"payment_initiation\":{\"extends\":\"x\",\"fields\":{}}}}").contains("may extend only itself, not 'x'"),
                "not through a type of the document's own either");
        assertEquals(Rule.FORBIDDEN, parse("{\"types\":{\"payment_initiation\":{\"extends\":\"payment_initiation\","
                + "\"fields\":{\"instructedAmount\":\"forbidden\"}}}}").get("payment_initiation").fields().get("instructedAmount").rule(),
                "tightening a built-in in place is still allowed");
    }

    /** An extension keeps its base's alternatives, and a unit it adds must sit in the same spelling as its limit. */
    @Test
    void extensionsInheritAlternatives() throws Exception {
        Map<String, TypeModel> models = parse("{\"types\":{\"payment_initiation\":{\"extends\":\"payment_initiation\","
                + "\"fields\":{\"remittanceInformationStructured\":\"string\"}},\"y\":{\"extends\":\"payment_initiation\",\"fields\":{}}}}");
        List<List<List<String>>> expected = List.of(List.of(List.of("instructedAmount"), List.of("amount", "currency")));
        assertEquals(expected, models.get("payment_initiation").alternatives());
        assertEquals(expected, models.get("y").alternatives());
        assertEquals(List.of(), models.get("sales_agent").alternatives());
        assertEquals("type 'x': field 'fee' and its unit_field 'currency' must be in the same spelling",
                refused("{\"types\":{\"x\":{\"extends\":\"payment_initiation\",\"fields\":{\"fee\":{\"rule\":\"limit\",\"unit_field\":\"currency\"}}}}}"));
    }

    /** A name UTF-8 cannot carry is refused by the reader, so no two documents hash alike and compare apart. */
    @Test
    void halfASurrogatePairIsRefused() {
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"\\ud800\":\"set\"}}}}").contains("half a surrogate pair"));
    }

    @Test
    void fieldRuleShapes() {
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":\"subset\"}}}}").contains("unknown rule 'subset'"));
        assertEquals("type 'x' field 'f': an object rule needs its 'fields'", refused("{\"types\":{\"x\":{\"fields\":{\"f\":\"object\"}}}}"));
        assertEquals("type 'x' field 'f' must be a JSON object", refused("{\"types\":{\"x\":{\"fields\":{\"f\":1}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"set\",\"min\":1}}}}}").contains("unknown key 'min'"));
        assertEquals("type 'x' field 'f' has no 'rule'", refused("{\"types\":{\"x\":{\"fields\":{\"f\":{}}}}}"));
        assertEquals("type 'x' field 'f' has no 'rule'", refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":1}}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"nope\"}}}}}").contains("unknown rule 'nope'"));
        assertEquals("type 'x' field 'f': 'fields' belongs to the object rule",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"limit\",\"fields\":{}}}}}}"));
        assertEquals("type 'x' field 'f': 'unit_field' must name a field",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"limit\",\"unit_field\":1}}}}}"));
        assertEquals("type 'x' field 'f': 'unit_field' must name a field",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"limit\",\"unit_field\":\" \"}}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"limit\",\"unit_field\":\"u\"}}}}}")
                .contains("must be a field of the same object with rule equal"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"limit\",\"unit_field\":\"u\"},\"u\":\"set\"}}}}")
                .contains("must be a field of the same object with rule equal"));
        assertEquals("type 'x' field 'f': 'unit_field' belongs to the limit rule",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"object\",\"unit_field\":\"u\",\"fields\":{\"a\":\"set\"}}}}}}"));
        assertEquals("type 'x' field 'f' 'fields' must be a JSON object",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"object\"}}}}}"));
        assertEquals("type 'x' field 'f': an object rule needs at least one field",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"object\",\"fields\":{}}}}}}"));
        assertEquals("type 'x' field 'f': rule 'set' takes no options",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"set\",\"unit_field\":\"u\"}}}}}"));
        assertEquals("type 'x' field 'f': rule 'equal' takes no options",
                refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"equal\",\"fields\":{}}}}}}"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"type\":\"set\"}}}}").contains("'type' is implicit"));
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":{\"rule\":\"object\",\"fields\":{\"type\":\"set\"}}}}}}")
                .contains("'type' is implicit"));
    }

    @Test
    void nestedObjectsStopBeforeTheDepthLimit() throws Exception {
        String inner = "\"set\"";
        for (int i = 0; i < Limits.MAX_DEPTH - 2; i++) {
            inner = "{\"rule\":\"object\",\"fields\":{\"n\":" + inner + "}}";
        }
        parse("{\"types\":{\"x\":{\"fields\":{\"f\":" + inner + "}}}}");
        String deeper = "{\"rule\":\"object\",\"fields\":{\"n\":" + inner + "}}";
        assertTrue(refused("{\"types\":{\"x\":{\"fields\":{\"f\":" + deeper + "}}}}")
                .endsWith(": a models document nests objects at most 7 deep (the detail is depth 1), one short of the value depth limit"));
        // The message says "one short" because it is: the value limit takes an object at depth 8 that holds
        // only scalars, which the schema refuses to declare.
        Object value = Map.of("s", 1);
        for (int i = 0; i < Limits.MAX_DEPTH - 2; i++) {
            value = Map.of("n", value);
        }
        Limits.check(List.of(Map.of("type", "x", "f", value)), "candidate");
    }
}
