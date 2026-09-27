"""tools/ci/image-scan-gate.py on grype-shaped reports: what is ours and what is PingFederate's, what fails, what an
accepted finding and an unused rule look like, and a report that is not one."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

gate = load("ci/image-scan-gate.py")


def match(vid, name, version, severity, path, typ="java-archive", fix=None):
    return {"vulnerability": {"id": vid, "severity": severity, "fix": {"versions": fix or []}},
            "artifact": {"name": name, "version": version, "type": typ, "locations": [{"path": path}]}}


def ignored(m, reason, vid=None):
    m = dict(m)
    m["appliedIgnoreRules"] = [{"vulnerability": vid or m["vulnerability"]["id"], "reason": reason,
                                "package": {"name": m["artifact"]["name"], "version": m["artifact"]["version"]}}]
    return m


# PingFederate's netty, in the base image and again in the image built from it, where the assembled war carries it
PF_NETTY = match("GHSA-c4c3", "netty-handler", "4.2.5.Final", "Critical", "/opt/server/server/default/lib/netty-handler.jar")
PF_NETTY_IN_WAR = match("GHSA-c4c3", "netty-handler", "4.2.5.Final", "Critical",
                        "/opt/in/instance/server/default/deploy/pf-runtime.war:WEB-INF/lib/netty-handler.jar")
OUR_JAR = match("CVE-2026-1", "jackson-databind", "2.99.0", "High", "/opt/in/instance/server/default/deploy/platform.jar", fix=["2.99.1"])
OUR_MEDIUM = match("CVE-2026-2", "busybox", "1.37.0-r31", "Medium", "/lib/apk/db/installed", typ="apk")
AGE = match("GHSA-age", "golang.org/x/crypto", "v0.45.0", "Critical", "/usr/bin/age", typ="go-module")


def report(matches, ignored_matches=(), rules=()):
    return {"matches": list(matches), "ignoredMatches": list(ignored_matches),
            "descriptor": {"configuration": {"ignore": list(rules)}}}


class Gate(unittest.TestCase):

    def run_gate(self, image, base, extra=(), manifest=None):
        with tempfile.TemporaryDirectory() as d:
            extra = list(extra)
            if manifest is not None:
                mp = os.path.join(d, "MANIFEST")
                with open(mp, "w", encoding="utf-8") as f:
                    f.write(manifest)
                extra += ["--ours-manifest", mp]
            paths = []
            for name, doc in (("image.json", image), ("base.json", base)):
                p = os.path.join(d, name)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(doc if isinstance(doc, str) else json.dumps(doc))
                paths.append(p)
            summary = os.path.join(d, "summary.md")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = gate.main(["--image", paths[0], "--base", paths[1], "--label", "capability (production)",
                                  "--summary", summary, *extra])
            text = ""
            if os.path.exists(summary):
                with open(summary, encoding="utf-8") as f:
                    text = f.read()
            return code, out.getvalue(), err.getvalue(), text

    def test_pingfederates_findings_are_reported_and_do_not_fail(self):
        code, out, _, summary = self.run_gate(report([PF_NETTY, PF_NETTY_IN_WAR, OUR_MEDIUM]), report([PF_NETTY]))
        self.assertEqual(code, 0, out)
        self.assertIn("**Passed**", out)
        self.assertIn("PingFederate's (the same finding in the pinned base image, outside our jars; reported, not failed", out)
        self.assertIn("1 critical", out)          # the war's copy and the base's are one finding
        self.assertIn("pf-runtime.war:WEB-INF/lib/netty-handler.jar", out)
        self.assertIn("| Medium | CVE-2026-2 | busybox | 1.37.0-r31 | not fixed |", out)
        self.assertEqual(summary.strip(), out.strip())

    def test_a_high_finding_of_ours_fails(self):
        code, out, _, _ = self.run_gate(report([PF_NETTY, OUR_JAR]), report([PF_NETTY]))
        self.assertEqual(code, 1)
        self.assertIn("**Failed**: 1 HIGH or CRITICAL", out)
        self.assertIn("| High | CVE-2026-1 | jackson-databind | 2.99.0 | 2.99.1 |", out)

    def test_the_same_vulnerability_at_another_version_is_ours(self):
        # PingFederate has netty 4.2.5 with it; a jar of ours shading 4.1.0 with the same advisory is ours
        shaded = match("GHSA-c4c3", "netty-handler", "4.1.0.Final", "Critical", "/opt/in/instance/server/default/deploy/ssf.jar")
        code, out, _, _ = self.run_gate(report([PF_NETTY, shaded]), report([PF_NETTY]))
        self.assertEqual(code, 1)
        self.assertIn("4.1.0.Final", out)

    def test_the_same_package_of_another_type_is_ours(self):
        # an Alpine package that happens to share a Java library's name, id and version is not PingFederate's finding
        apk = match("GHSA-c4c3", "netty-handler", "4.2.5.Final", "Critical", "/lib/apk/db/installed", typ="apk")
        code, out, _, _ = self.run_gate(report([PF_NETTY, apk]), report([PF_NETTY]))
        self.assertEqual(code, 1)
        self.assertIn("**Failed**: 1 HIGH or CRITICAL", out)

    def test_pingfederates_finding_inside_one_of_our_jars_is_ours(self):
        # a jar of ours carrying PingFederate's own netty, loose in deploy/ and again inside the war: a PingFederate
        # bump would fix PingFederate's copy and leave these
        loose = match("GHSA-c4c3", "netty-handler", "4.2.5.Final", "Critical",
                      "/opt/in/instance/server/default/deploy/ssf-0.5.0-SNAPSHOT.jar")
        in_war = match("GHSA-c4c3", "netty-handler", "4.2.5.Final", "Critical",
                       "/opt/in/instance/server/default/deploy/pf-runtime.war:WEB-INF/lib/ssf-0.5.0-SNAPSHOT.jar")
        manifest = ("MANIFEST/2 profile=production built=2026-09-28T00:00:00Z commit=abc\n[servlets]\n"
                    + "0" * 64 + "  oidf.jar\n" + "1" * 64 + "  ssf-0.5.0-SNAPSHOT.jar\n")
        image = report([PF_NETTY_IN_WAR, loose, in_war])
        code, out, _, _ = self.run_gate(image, report([PF_NETTY]))
        self.assertEqual(code, 0, out)       # without the MANIFEST the gate cannot tell
        code, out, _, _ = self.run_gate(image, report([PF_NETTY]), manifest=manifest)
        self.assertEqual(code, 1, out)
        self.assertIn("**Failed**: 1 HIGH or CRITICAL", out)
        ours = out.split("### Ours")[1].split("<details>")[0]
        self.assertIn("deploy/ssf-0.5.0-SNAPSHOT.jar`", ours)
        self.assertIn("WEB-INF/lib/ssf-0.5.0-SNAPSHOT.jar`", ours)
        self.assertNotIn("WEB-INF/lib/netty-handler.jar", ours)   # PingFederate's own copy stays PingFederate's
        self.assertIn("WEB-INF/lib/netty-handler.jar", out.split("<details>")[1])

    def test_a_manifest_that_is_not_one(self):
        code, _, err, _ = self.run_gate(report([]), report([]), manifest="[libs]\nplatform.jar\n")
        self.assertEqual(code, 2)
        self.assertIn("not a stage-modules.sh MANIFEST", err)

    def test_an_accepted_finding_passes_and_stays_in_view(self):
        rule = {"vulnerability": "GHSA-age", "reason": "ssh only; F-0221",
                "package": {"name": "golang.org/x/crypto", "version": "v0.45.0", "location": "/usr/bin/age*"}}
        code, out, _, _ = self.run_gate(report([OUR_MEDIUM], [ignored(AGE, "ssh only; F-0221")], [rule]), report([]))
        self.assertEqual(code, 0, out)
        self.assertIn("accepted in .github/grype.yaml: 1", out)
        self.assertIn("| Critical | GHSA-age | golang.org/x/crypto | v0.45.0 | `/usr/bin/age` | ssh only; F-0221 |", out)
        self.assertNotIn("matched nothing", out)   # grype echoes the rule without its location; still the same rule

    def test_a_rule_that_matched_nothing_is_named_and_grypes_own_defaults_are_not(self):
        rules = [{"vulnerability": "CVE-2026-85091", "reason": "zlib; F-0220", "package": {"name": "zlib", "version": "1.3.2-r0"}},
                 {"vulnerability": "", "package": {"name": "kernel-headers"}}]
        code, out, _, _ = self.run_gate(report([], [], rules), report([]))
        self.assertEqual(code, 0)
        self.assertIn("the rule for CVE-2026-85091 in zlib 1.3.2-r0 matched nothing in this image", out)
        self.assertNotIn("kernel-headers", out)

    def test_a_finding_the_base_accepts_is_still_pingfederates(self):
        base = report([], [ignored(PF_NETTY, "base")])
        code, _, _, _ = self.run_gate(report([PF_NETTY_IN_WAR]), base)
        self.assertEqual(code, 0)

    def test_a_report_that_is_not_one(self):
        code, _, err, _ = self.run_gate("{not json", report([]))
        self.assertEqual(code, 2)
        self.assertIn("image.json", err)
        code, _, err, _ = self.run_gate(report([]), {"results": []})
        self.assertEqual(code, 2)
        self.assertIn("not a grype JSON report", err)


if __name__ == "__main__":
    unittest.main()
