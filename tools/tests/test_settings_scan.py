"""tools/settings-scan.py on made-up reactors: what counts as a read and what does not, the helpers it finds, both
directions of the check, the once rule and its per-module scope for init-params, the catalogue's own shape, the
exemption file's rules, and the repository as it is."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

scan = load("settings-scan.py")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def reads_of(sources):
    """{(kind, name)} read by the Java sources given as {path: text}, all in one module."""
    reactor = scan.Reactor("/nowhere")
    for path, text in sources.items():
        reactor.add("m", path, text)
    reads, unresolved = reactor.reads()
    return {(kind, name) for kind, name, _jf, _line in reads}, [text for _jf, _line, text in unresolved]


def java(body, cls="A", package="x"):
    return f"package {package};\nclass {cls} {{\n{body}\n}}\n"


def entry(name, kind="env", sources=None, **over):
    e = {"name": name, "kind": kind, "type": "string", "default": None, "description": "d",
         "when_wrong": {"effect": "not-checked", "detail": "d"}, "profile": "any", "security": False,
         "sources": [{"from": kind, "name": name}] if sources is None and kind in scan.SOURCE_KINDS else (sources or []),
         "aliases": [], "file": False}
    e.update(over)
    return e


def catalogue(component, module, package, settings, removed=()):
    return {"format": 1, "component": component, "module": module, "package": package, "families": [],
            "settings": settings, "removed": list(removed)}


class Tree:
    """A reactor on disk: a root pom, modules with main sources and catalogues, an exemption file."""

    def __init__(self, test):
        self.dir = tempfile.TemporaryDirectory()
        test.addCleanup(self.dir.cleanup)
        self.root = self.dir.name
        self.modules = []

    def module(self, path, sources=None, catalogues=()):
        self.modules.append(path)
        for rel, text in (sources or {}).items():
            self.write(os.path.join(path, "src/main/java", rel), text)
        for doc in catalogues:
            self.write(os.path.join(path, scan.CATALOGUE_DIR, doc["component"] + ".json"), json.dumps(doc))
        return self

    def write(self, rel, text):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    def problems(self):
        self.write("pom.xml", "<project><modules>" + "".join(f"<module>{m}</module>" for m in self.modules)
                   + "</modules></project>")
        problems, _reads, _notes, unreadable = scan.scan(self.root)
        assert not unreadable, unreadable
        return problems


class WhatIsAReadTest(unittest.TestCase):
    def test_a_whole_oidf_literal_is_an_environment_read(self):
        found, _ = reads_of({"A.java": java('static final String X = "OIDF_PDP_MODE";\nvoid f() { use("OIDF_FETCH_ALLOW_HTTP"); }')})
        self.assertEqual({("env", "OIDF_PDP_MODE"), ("env", "OIDF_FETCH_ALLOW_HTTP")}, found)

    def test_a_message_a_prefix_and_a_comment_are_not_reads(self):
        found, _ = reads_of({"A.java": java(
            'void f() {\n  log("set OIDF_PDP_URL to an https URL");\n  String p = "OIDF_SSF_";\n'
            '  // System.getenv("OIDF_IN_A_LINE_COMMENT")\n  /* "OIDF_IN_A_BLOCK_COMMENT" */\n'
            '  log("OIDF_A " + "is not one name");\n  String q = "oidf.pdp.mode";\n}\n'
            '/** {@code OIDF_IN_JAVADOC} and "OIDF_QUOTED_IN_JAVADOC" */\nvoid g() {}')})
        self.assertEqual(set(), found)

    def test_read_calls_with_a_literal(self):
        found, unresolved = reads_of({"A.java": java(
            'void f(javax.servlet.ServletConfig config) {\n  System.getenv("IDM_DATABASE_URL");\n'
            '  System.getProperty("oidf.x.y", "d");\n  Boolean.getBoolean("oidf.flag");\n  Integer.getInteger("oidf.n");\n'
            '  Long.getLong("oidf.l");\n  config.getInitParameter("corsMaxAge");\n  getInitParameter("bare");\n}')})
        self.assertEqual({("env", "IDM_DATABASE_URL"), ("system-property", "oidf.x.y"), ("system-property", "oidf.flag"),
                          ("system-property", "oidf.n"), ("system-property", "oidf.l"), ("init-param", "corsMaxAge"),
                          ("init-param", "bare")}, found)
        self.assertEqual([], unresolved)

    def test_a_method_of_the_same_name_on_another_receiver_is_not_a_read(self):
        found, unresolved = reads_of({"A.java": java('void f(java.util.Properties p, String k) { p.getProperty(k); map.getenv(k); }')})
        self.assertEqual(set(), found)
        self.assertEqual([], unresolved)

    def test_constants_are_followed_in_the_class_across_classes_and_through_static_imports(self):
        found, unresolved = reads_of({
            "B.java": java('public static final String PROP = "oidf.b.prop";\n'
                           'public static final String ALIAS = C.NAME;', cls="B"),
            "C.java": java('static final String NAME = "OIDF_C_NAME";\nprivate final static String OWN = "oidf.c.own";\n'
                           'void f() { System.getProperty(OWN); }', cls="C"),
            "A.java": "package x;\nimport static x.B.PROP;\nclass A {\n"
                      "void f() { System.getProperty(PROP); System.getenv(B.ALIAS); System.getProperty(x.B.PROP); }\n}\n",
        })
        self.assertEqual({("system-property", "oidf.b.prop"), ("env", "OIDF_C_NAME"), ("system-property", "oidf.c.own")}, found)
        self.assertEqual([], unresolved)

    def test_a_read_the_scan_cannot_name_is_reported(self):
        _found, unresolved = reads_of({"A.java": java(
            'void f(String suffix) { String name = "OIDF_" + suffix; System.getenv(name); System.getProperty("oidf." + suffix); }')})
        self.assertEqual(['getenv(name)', 'getProperty("oidf." + suffix)'], unresolved)

    def test_a_name_built_from_a_prefix_that_names_no_settings_is_excused_and_no_other(self):
        _found, unresolved = reads_of({"A.java": java(
            'static final String OWNER_PREFIX = "oidf.exec.owner.";\n'
            'void f(String name) {\n  System.getProperty(OWNER_PREFIX + name);\n  System.getProperty("oidf.exec.owner." + name);\n'
            '  System.getProperty("oidf.exec.other." + name);\n  System.getenv(OWNER_PREFIX + name);\n}')})
        self.assertEqual(['getProperty("oidf.exec.other." + name)', 'getenv(OWNER_PREFIX + name)'], unresolved)

    def test_a_settings_accessor_reads_the_entry_it_names(self):
        imports = "package x;\nimport com.pingidentity.ps.oidf.platform.settings.Settings;\nclass A {\n"
        found, unresolved = reads_of({"A.java": imports +
            'static final String URL = "OIDF_R_URL";\n'
            'void f(Settings settings) {\n  String local = pick();\n  settings.secret(URL);\n  settings.duration("OIDF_R_WAIT");\n'
            '  settings.parse("peerName", "raw");\n  Settings.of("r").path("OIDF_R_CA");\n  Json.path("NOT_A_READ");\n  settings.string(local);\n'
            '  settings.string("TWO", "args");\n}\n}\n'})
        self.assertEqual({("setting", "OIDF_R_URL"), ("env", "OIDF_R_URL"), ("setting", "OIDF_R_WAIT"), ("env", "OIDF_R_WAIT"),
                          ("setting", "peerName"), ("setting", "OIDF_R_CA"), ("env", "OIDF_R_CA")}, found)
        self.assertEqual(["string(local)"], unresolved)
        found, unresolved = reads_of({"A.java": java('void f(Json json) { json.string("REDIS_URL"); json.path(local); }')})
        self.assertEqual((set(), []), (found, unresolved))

    def test_an_apply_or_a_helper_whose_argument_the_scan_cannot_name_is_reported(self):
        _found, unresolved = reads_of({"A.java": java(
            'private static String setting(java.util.function.Function<String, String> env, String var) {\n'
            '  return env.apply(var);\n}\n'
            'void f(java.util.function.Function<String, String> env, java.util.List<String> names) {\n'
            '  String local = pick();\n  env.apply(local);\n  setting(env, local);\n'
            '  for (String each : names) { setting(env, each); }\n}')})
        self.assertEqual(['apply(local)', 'setting(local)', 'setting(each)'], unresolved)

    def test_a_loop_over_an_inline_list_reads_each_name(self):
        found, unresolved = reads_of({"A.java": java(
            'static final String URL = "OIDF_PDP_URL";\n'
            'private static String setting(java.util.function.Function<String, String> env, String var) {\n'
            '  return env.apply(var);\n}\n'
            'void f(java.util.function.Function<String, String> env) {\n'
            '  for (String v : List.of(URL, "NEW_UNCATALOGUED_VAR")) { setting(env, v); }\n'
            '  for (final String p : java.util.Set.of("oidf.a", "oidf.b")) { System.getProperty(p); }\n}')})
        self.assertEqual({("env", "OIDF_PDP_URL"), ("env", "NEW_UNCATALOGUED_VAR"), ("system-property", "oidf.a"),
                          ("system-property", "oidf.b")}, found)
        self.assertEqual([], unresolved)
        _found, unresolved = reads_of({"A.java": java(
            'void f(String other) {\n  for (String v : List.of("OIDF_X", other)) { System.getenv(v); }\n}')})
        self.assertEqual(['getenv(v)'], unresolved)

    def test_a_statically_imported_read_call_counts_and_a_literal_on_another_receiver_does_not(self):
        found, unresolved = reads_of({"A.java": "package x;\nimport static java.lang.System.getenv;\nclass A {\n"
                                                'void f(java.util.Properties p) { getenv("PLAIN_ENV"); p.getProperty("not.a.read"); }\n}\n'})
        self.assertEqual({("env", "PLAIN_ENV")}, found)
        self.assertEqual([], unresolved)

    def test_a_derived_system_property_read_directly(self):
        found, unresolved = reads_of({"A.java": java('void f() { System.getProperty(Parsers.systemPropertyName("OIDF_X_Y")); }')})
        self.assertEqual({("system-property", "oidf.x.y"), ("env", "OIDF_X_Y")}, found)
        self.assertEqual([], unresolved)

    def test_a_helper_is_found_and_its_arguments_are_reads(self):
        found, unresolved = reads_of({"A.java": java(
            'private static String setting(java.util.function.Function<String, String> initParams, String initParam,'
            ' String sysProp, String envVar) {\n'
            '  String v = initParams.apply(initParam);\n  if (v == null) v = System.getProperty(sysProp);\n'
            '  if (v == null) v = System.getenv(envVar);\n  return v;\n}\n'
            'void init(javax.servlet.ServletConfig config) {\n'
            '  setting(config::getInitParameter, "openBaoUrl", "oidf.openbao.url", "OPENBAO_URL_NOT_OIDF");\n}')})
        self.assertEqual({("init-param", "openBaoUrl"), ("system-property", "oidf.openbao.url"), ("env", "OPENBAO_URL_NOT_OIDF")},
                         found)
        self.assertEqual([], unresolved)

    def test_a_public_helper_is_matched_by_class_and_arity_from_another_file(self):
        found, _ = reads_of({
            "Bearer.java": java('public static String resolveToken(Object config, String initParam, String sysProp, String envVar) {\n'
                                '  String v = ((javax.servlet.ServletConfig) config).getInitParameter(initParam);\n'
                                '  if (v == null) v = System.getProperty(sysProp);\n  if (v == null) v = System.getenv(envVar);\n'
                                '  return v;\n}\n'
                                'public static String resolveToken(String a, String b) { return a + b; }', cls="Bearer"),
            "A.java": java('void f(Object c) {\n  Bearer.resolveToken(c, "adminToken", "oidf.admin.token", "ADMIN_TOKEN");\n'
                           '  Bearer.resolveToken("not", "reads");\n  other.resolveToken(c, "no", "no.no", "NO");\n}'),
        })
        self.assertEqual({("init-param", "adminToken"), ("system-property", "oidf.admin.token"), ("env", "ADMIN_TOKEN")}, found)

    def test_helpers_are_found_to_a_fixpoint_with_varargs_and_derived_properties(self):
        found, unresolved = reads_of({"A.java": java(
            'private static String setting(java.util.function.Function<String, String> env,'
            ' java.util.function.Function<String, String> props, String prop, String var) {\n'
            '  String v = props.apply(prop);\n  return v != null ? v : env.apply(var);\n}\n'
            'private static String prop(String var) { return Parsers.systemPropertyName(var); }\n'
            'private static boolean bool(java.util.function.Function<String, String> env,'
            ' java.util.function.Function<String, String> props, String var, boolean fallback) {\n'
            '  return Boolean.parseBoolean(setting(env, props, prop(var), var));\n}\n'
            'private static String first(String sysProp, String... envVars) {\n'
            '  String v = System.getProperty(sysProp);\n  for (String each : envVars) { v = System.getenv(each); }\n  return v;\n}\n'
            'void load(java.util.function.Function<String, String> e, java.util.function.Function<String, String> p) {\n'
            '  bool(e, p, "PLAIN_SWITCH", false);\n  first("oidf.bao.url", "BAO_ADDR", "VAULT_ADDR");\n}')})
        self.assertEqual({("env", "PLAIN_SWITCH"), ("system-property", "plain.switch"), ("system-property", "oidf.bao.url"),
                          ("env", "BAO_ADDR"), ("env", "VAULT_ADDR")}, found)
        self.assertEqual([], unresolved)

    def test_extended_properties_and_plugin_fields(self):
        found, _ = reads_of({
            "FederationClientParams.java": java('static final String STATUS = "status";\n'
                                                'static final java.util.List<String> EXTENDED_PARAM_NAMES = java.util.List.of(\n'
                                                '    STATUS,\n    "trust_chain",\n);', cls="FederationClientParams"),
            "A.java": java('void f(java.util.Map m, Configuration configuration) {\n'
                           '  m.get("extproperties.attestation_pop_max_age");\n  String s = "extproperties.";\n'
                           '  configuration.getFieldValue("PDP URL");\n  configuration.getBooleanFieldValue(FAIL_OPEN, true);\n'
                           '  gui.addField(new TextFieldDescriptor("JDBC URL", "the label"));\n}\n'
                           'static final String FAIL_OPEN = "Fail open";'),
        })
        self.assertEqual({("extended-property", "status"), ("extended-property", "trust_chain"),
                          ("extended-property", "attestation_pop_max_age"), ("plugin-field", "PDP URL"),
                          ("plugin-field", "Fail open"), ("plugin-field", "JDBC URL")}, found)

    def test_line_numbers_survive_comments_and_text_blocks(self):
        reactor = scan.Reactor("/nowhere")
        jf = reactor.add("m", "A.java", 'package x;\n/*\n two\n*/\nclass A {\n  String t = """\n    x\n    """;\n'
                                        '  String e = System.getenv("OIDF_ON_NINE");\n}\n')
        reads, _ = reactor.reads()
        self.assertEqual({("env", "OIDF_ON_NINE", 9)}, {(k, n, line) for k, n, _jf, line in reads})


VALID = catalogue("thing", "libs/a", "x", [entry("OIDF_THING")])
READS_THING = {"x/A.java": java('static final String X = "OIDF_THING";')}


class BothWaysTest(unittest.TestCase):
    def test_clean(self):
        self.assertEqual([], Tree(self).module("libs/a", READS_THING, [VALID]).problems())

    def test_an_uncatalogued_read(self):
        problems = Tree(self).module("libs/a", {"x/A.java": java('void f() { System.getenv("OIDF_OTHER"); }')}, []).problems()
        self.assertEqual(1, len(problems))
        self.assertIn("env OIDF_OTHER is read but no catalogue declares it", problems[0])

    def test_a_catalogued_name_nothing_reads(self):
        problems = Tree(self).module("libs/a", READS_THING, [catalogue("thing", "libs/a", "x", [
            entry("OIDF_THING"), entry("OIDF_GONE", sources=[{"from": "system-property", "name": "oidf.gone"},
                                                           {"from": "env", "name": "OIDF_GONE"}])])]).problems()
        self.assertEqual(2, len(problems), problems)
        self.assertTrue(all("is catalogued but nothing reads it" in p for p in problems))

    def test_a_name_read_only_in_another_module(self):
        problems = (Tree(self).module("libs/a", READS_THING, [catalogue("thing", "libs/a", "x", [entry("OIDF_THING"), entry("OIDF_B")])])
                    .module("libs/b", {"y/B.java": java('static final String B = "OIDF_B";', package="y")}).problems())
        self.assertEqual(1, len(problems), problems)
        self.assertIn("env OIDF_B (OIDF_B) is read only in libs/b, not in libs/a", problems[0])

    def test_a_name_read_in_two_modules_is_catalogued_once(self):
        tree = (Tree(self).module("libs/a", READS_THING, [VALID])
                .module("libs/b", {"y/B.java": java('static final String B = "OIDF_THING";', package="y")}))
        self.assertEqual([], tree.problems())
        tree.module("libs/c", READS_THING, [catalogue("other", "libs/c", "x", [entry("OIDF_THING")])])
        problems = tree.problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("env OIDF_THING is declared by", problems[0])

    def test_an_init_param_belongs_to_its_module(self):
        reads_sa = {"x/A.java": java('void f(javax.servlet.ServletConfig c) { c.getInitParameter("signingAlgorithm"); }')}
        a = catalogue("a", "libs/a", "x", [entry("signingAlgorithm", kind="init-param")])
        b = catalogue("b", "libs/b", "x", [entry("signingAlgorithm", kind="init-param")])
        self.assertEqual([], Tree(self).module("libs/a", reads_sa, [a]).module("libs/b", reads_sa, [b]).problems())
        problems = Tree(self).module("libs/a", reads_sa, [a]).module("libs/b", reads_sa, []).problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("libs/b/src/main/java/x/A.java:3: init-param signingAlgorithm is read but no catalogue declares it", problems[0])

    def test_aliases_and_removed_names_are_declared(self):
        doc = catalogue("thing", "libs/a", "x", [entry("OIDF_THING", aliases=[{"name": "OIDF_OLD", "sources": [
            {"from": "env", "name": "OIDF_OLD"}]}])], removed=[
            {"name": "OIDF_REMOVED", "from": "env", "replacement": "OIDF_THING", "release": "0.1.2"}])
        reads = {"x/A.java": java('static final String X = "OIDF_THING";\nstatic final String O = "OIDF_OLD";\n'
                                  'static final String R = "OIDF_REMOVED";')}
        self.assertEqual([], Tree(self).module("libs/a", reads, [doc]).problems())
        problems = Tree(self).module("libs/a", READS_THING, [doc]).problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("env OIDF_OLD (OIDF_THING) is catalogued but nothing reads it", problems[0])

    def test_an_extended_property_read_through_a_constant_counts_from_the_catalogue(self):
        doc = catalogue("props", "libs/a", "x", [entry("attestation_issuer", kind="extended-property")])
        reads = {"x/A.java": java('public static final String P_ISSUER = "attestation_issuer";')}
        self.assertEqual([], Tree(self).module("libs/a", reads, [doc]).problems())

    def test_the_owning_package_reads_the_catalogue(self):
        problems = Tree(self).module("libs/a", READS_THING, [catalogue("thing", "libs/a", "x.other", [entry("OIDF_THING")])]).problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("package x.other reads none of its settings; the owning package is one of x", problems[0])
        self.assertEqual([], Tree(self).module("libs/a", {"x/sub/A.java": java('static final String X = "OIDF_THING";', package="x.sub")},
                                               [VALID]).problems())

    def test_a_read_the_scan_cannot_name_is_a_problem(self):
        problems = Tree(self).module("libs/a", {"x/A.java": java(
            'static final String X = "OIDF_THING";\nvoid f(java.util.function.Function<String, String> env) {\n'
            '  String n = name();\n  env.apply(n);\n}')}, [VALID]).problems()
        self.assertEqual(["libs/a/src/main/java/x/A.java:6: apply(n) is a read the scan cannot name: read it by a constant,"
                          " or through a helper whose parameter carries it"], problems)

    def test_a_component_is_catalogued_by_one_file(self):
        problems = (Tree(self).module("libs/a", READS_THING, [VALID])
                    .module("libs/b", {"x/B.java": java('static final String B = "OIDF_B";', cls="B")},
                            [catalogue("thing", "libs/b", "x", [entry("OIDF_B")])]).problems())
        self.assertEqual(1, len(problems), problems)
        self.assertIn("component thing is catalogued by", problems[0])

    def test_a_secrets_file_variant_needs_no_read(self):
        doc = catalogue("thing", "libs/a", "x", [entry("OIDF_THING", type="secret", security=True, file=True)])
        self.assertEqual([], Tree(self).module("libs/a", READS_THING, [doc]).problems())

    def test_an_accepted_risk_is_one_the_registry_holds(self):
        registry = java('NO_METADATA_POLICY("no-metadata-policy", false, "why"),\nPKCE_OFF("pkce-off", false, "why");',
                        cls="AcceptedRisk")
        for profile, expected in (("accepted-risk:pkce-off", 0), ("accepted-risk:not-registered", 1)):
            with self.subTest(profile):
                tree = Tree(self).module("libs/a", READS_THING, [
                    catalogue("thing", "libs/a", "x", [entry("OIDF_THING", profile=profile)])])
                tree.write(scan.ACCEPTED_RISKS, registry)
                problems = tree.problems()
                self.assertEqual(expected, len(problems), problems)
                if expected:
                    self.assertIn("names accepted risk not-registered", problems[0])

    def test_a_settings_read_reads_the_entrys_sources_and_aliases(self):
        doc = catalogue("r", "libs/a", "x", [
            entry("OIDF_R_URL", sources=[{"from": "system-property", "name": "oidf.r.url"}, {"from": "env", "name": "OIDF_R_URL"}],
                  aliases=[{"name": "LEGACY_URL", "sources": [{"from": "env", "name": "LEGACY_URL"}]}]),
            entry("REDIS_URL"), entry("OIDF_R_UNREAD", sources=[{"from": "system-property", "name": "oidf.r.unread"},
                                                              {"from": "env", "name": "OIDF_R_UNREAD"}])])
        reads = {"x/A.java": "package x;\nimport com.pingidentity.ps.oidf.platform.settings.Settings;\nclass A {\n"
                             'static final String URL = "OIDF_R_URL";\nstatic final String UNREAD = "OIDF_R_UNREAD";\n'
                             'void f(Settings s) { s.secret(URL); s.secret("REDIS_URL"); s.bool("R_MISSING"); }\n}\n'}
        problems = Tree(self).module("libs/a", reads, [doc]).problems()
        self.assertEqual(["libs/a/src/main/java/x/A.java:6: setting R_MISSING is read through platform.settings but no"
                          " catalogue has an entry of that name",
                          "libs/a/src/main/resources/META-INF/oidf-settings/r.json: system-property oidf.r.unread"
                          " (OIDF_R_UNREAD) is catalogued but nothing reads it"], problems)

    def test_a_prefix_that_names_no_settings_is_excused_in_the_scan(self):
        reads = {"x/A.java": java('static final String P = "oidf.exec.owner.";\nvoid f(String n) { System.getProperty(P + n); }')}
        self.assertEqual([], Tree(self).module("libs/a", reads, []).problems())

    def test_not_settings_are_excused(self):
        reads = {"x/A.java": java('void f() { System.getProperty("oidf.registration.sweeper.owner"); }')}
        self.assertEqual([], Tree(self).module("libs/a", reads, []).problems())

    def test_a_catalogue_that_is_not_one(self):
        cases = {
            "unknown member": dict(VALID, extra=1),
            "wrong component": dict(VALID, component="other"),
            "wrong module": dict(VALID, module="libs/b"),
            "switch without a default": catalogue("thing", "libs/a", "x", [entry("OIDF_THING", type="bool")]),
            "env entry not read under its own name": catalogue("thing", "libs/a", "x", [
                entry("OIDF_THING", sources=[{"from": "system-property", "name": "oidf.thing"}])]),
            "plugin field with sources": catalogue("thing", "libs/a", "x", [
                entry("F", kind="plugin-field", sources=[{"from": "env", "name": "F"}])]),
            "ranged type without its range": catalogue("thing", "libs/a", "x", [entry("OIDF_THING", type="int", default=1)]),
            "bad profile": catalogue("thing", "libs/a", "x", [entry("OIDF_THING", profile="sometimes")]),
            "secret with a default": catalogue("thing", "libs/a", "x", [entry("OIDF_THING", type="secret", default="x", security=True)]),
        }
        for name, doc in cases.items():
            with self.subTest(name):
                tree = Tree(self).module("libs/a", READS_THING, [])
                tree.write(os.path.join("libs/a", scan.CATALOGUE_DIR, "thing.json"), json.dumps(doc))
                self.assertTrue(tree.problems(), name)
        self.assertEqual(["x: settings[0] (OIDF_THING): an env entry is read from env under its own name"],
                         scan.check_catalogue(cases["env entry not read under its own name"], "x"))
        tree = Tree(self).module("libs/a", READS_THING, [])
        tree.write(os.path.join("libs/a", scan.CATALOGUE_DIR, "thing.json"), '{"format": 1, "format": 1}')
        self.assertIn("written twice", tree.problems()[0])


class ExemptionsTest(unittest.TestCase):
    def tree(self, exemptions, staged=()):
        tree = (Tree(self).module("libs/a", READS_THING, [VALID])
                .module("libs/b", {"y/B.java": java('static final String B = "OIDF_B_ONLY";', package="y")})
                .module("libs/quiet", {"z/Q.java": java('int x;', package="z")}))
        tree.write(scan.EXEMPTIONS, exemptions)
        tree.write(scan.STAGE_MODULES, "ENTRIES=(\n" + "".join(f'  "libs {m}/target/x-$VERSION.jar"\n' for m in staged) + ")\n")
        return tree

    def test_a_missing_file_means_no_exemptions(self):
        tree = Tree(self).module("libs/b", {"y/B.java": java('static final String B = "OIDF_B_ONLY";', package="y")})
        self.assertEqual(1, len(tree.problems()))

    def test_an_exempt_module_is_not_held_to_its_reads(self):
        self.assertEqual([], self.tree("refuse-shipped-exemptions: no\n# group ST3B: later\nlibs/b\n").problems())

    def test_stale_unknown_quiet_and_ungrouped_lines(self):
        problems = self.tree("libs/b\n# group ST3B\nlibs/a\nlibs/nowhere\nlibs/quiet\nlibs/b\n").problems()
        text = "\n".join(problems)
        self.assertIn("libs/b is under no `# group` line", text)
        self.assertIn("libs/a has a catalogue now; delete its exemption", text)
        self.assertIn("libs/nowhere is not a module of the reactor", text)
        self.assertIn("libs/quiet reads nothing the scan sees", text)
        self.assertIn("libs/b is exempted twice", text)

    def test_the_not_shipped_group(self):
        self.assertEqual([], self.tree("# group not shipped\nlibs/b: test support, never staged\n").problems())
        problems = self.tree("# group not shipped\nlibs/b\n").problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("says why it is not shipped", problems[0])
        problems = self.tree("# group not shipped\nlibs/b: it says so\n", staged=["libs/b"]).problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("is staged by build/pingfederate/stage-modules.sh, so it is shipped", problems[0])

    def test_the_flag_refuses_every_group_but_not_shipped(self):
        problems = self.tree("refuse-shipped-exemptions: yes\n# group ST3C\nlibs/b\n").problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("only the 'not shipped' group may be", problems[0])
        self.assertEqual([], self.tree("refuse-shipped-exemptions: yes\n# group not shipped\nlibs/b: why\n").problems())

    def test_the_repository_file_parses_into_its_groups(self):
        lines, refuse, problems = scan.read_exemptions(os.path.join(REPO, scan.EXEMPTIONS))
        self.assertEqual([], problems)
        groups = {group for _m, group, _r, _n in lines}
        self.assertTrue(groups <= {"ST3B", "ST3C", scan.NOT_SHIPPED}, groups)
        self.assertIn(("libs/testkit", scan.NOT_SHIPPED), {(m, g) for m, g, _r, _n in lines})
        self.assertFalse(refuse and groups - {scan.NOT_SHIPPED})


class RepositoryTest(unittest.TestCase):
    def test_the_repository_passes(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = scan.main(["--root", REPO])
        self.assertEqual(0, status, err.getvalue())
        self.assertIn("clean", out.getvalue())

    def test_the_staged_modules_are_read_from_stage_modules_sh(self):
        staged = scan.staged_modules(REPO)
        self.assertTrue({"libs/platform", "servlets/pf-integration", "servlets/ssf"} <= staged, staged)
        self.assertNotIn("libs/testkit", staged)

    def test_the_list_names_the_federation_settings(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, scan.main(["--root", REPO, "--list"]))
        listed = out.getvalue()
        for line in ("env OIDF_PDP_MODE  servlets/pf-integration/", "system-property oidf.pdp.mode  servlets/pf-integration/",
                     "init-param trustAnchorIssuers  libs/openid-federation/", "extended-property status  servlets/pf-integration/",
                     "setting OIDF_REDIS_URL  libs/platform/", "setting REDIS_URL  libs/platform/"):
            self.assertIn(line, listed)


if __name__ == "__main__":
    unittest.main()
