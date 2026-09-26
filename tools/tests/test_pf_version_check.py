"""tools/pf-version-check.py on a fixture repo: every consumer of build/pf-version.env in agreement,
then each way one can disagree, and a missing env file."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

check = load("pf-version-check.py")

IMAGE = "pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest"
DIGEST = "sha256:" + "0d55" * 16

ENV = f"""# the one place
PF_VERSION=13.1.3
PF_SDK_MAVEN_VERSION=13.1.3.0
PF_IMAGE={IMAGE}
PF_IMAGE_DIGEST={DIGEST}
PF_TERRAFORM_PRODUCT_VERSION=13.1
"""

FILES = {
    "build/pf-version.env": ENV,
    "bom/pom.xml": "<project><properties><version.pingfederate>13.1.3.0</version.pingfederate></properties></project>\n",
    "services/gm-api/servlet/pom.xml": "<project><properties><pingfederate.version>13.1.3</pingfederate.version></properties></project>\n",
    "build/pingfederate/Dockerfile": f"# header\nFROM {IMAGE}@{DIGEST}\nUSER root\n",
    ".github/actions/pf-provided-jars/action.yml": 'runs:\n  steps:\n    - run: |\n        . "$GITHUB_WORKSPACE/build/pf-version.env"\n        docker create "${PF_IMAGE}@${PF_IMAGE_DIGEST}"\n',
    ".github/workflows/build.yml": 'steps:\n  - run: grep -v \'^#\' build/pf-version.env >> "$GITHUB_ENV"\n',
    ".github/workflows/release.yml": 'steps:\n  - run: grep -v \'^#\' build/pf-version.env >> "$GITHUB_ENV"\n',
    "conformance/author.sh": '. "$HERE/../build/pf-version.env"\nIMAGE="${PF_IMAGE:?}@${PF_IMAGE_DIGEST:?}"\n',
    "conformance/apply.sh": '. "$HERE/../build/pf-version.env"\nexport TF_VAR_pf_product_version="${PF_TERRAFORM_PRODUCT_VERSION:?}"\n',
    "conformance/terraform/provider.tf": 'provider "pingfederate" {\n  product_version = var.pf_product_version\n}\n',
    "conformance/terraform/variables.tf": 'variable "pf_product_version" {\n  type    = string\n  default = "13.1"\n}\n',
    "tools/pf-linkcheck.py": f'"""\n  id=$(docker create {IMAGE})\n"""\n',
    "docs/history.md": "It used to run pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest.\n",
    "showcase/index.html": "<p>pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest</p>\n",
}


def write_repo(root, overrides=None):
    files = dict(FILES)
    files.update(overrides or {})
    for rel, text in files.items():
        if text is None:
            continue
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def run(root):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = check.main(["--root", root])
    return code, out.getvalue(), err.getvalue()


class Agree(unittest.TestCase):

    def test_everything_in_step(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root)
            code, out, err = run(root)
            self.assertEqual(code, 0, err)
            self.assertIn("ok: PingFederate 13.1.3", out)


class Disagree(unittest.TestCase):

    def assert_problem(self, overrides, fragment):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, overrides)
            code, out, err = run(root)
            self.assertEqual(code, 1, "expected a disagreement: " + fragment)
            self.assertIn(fragment, err)
            return err

    def test_bom_sdk_version(self):
        self.assert_problem({"bom/pom.xml": "<project><properties><version.pingfederate>13.0.0.3</version.pingfederate></properties></project>\n"},
                            "bom/pom.xml: <version.pingfederate> is 13.0.0.3, PF_SDK_MAVEN_VERSION is 13.1.3.0")

    def test_gm_api_pin(self):
        self.assert_problem({"services/gm-api/servlet/pom.xml": "<project><properties><pingfederate.version>13.1.0</pingfederate.version></properties></project>\n"},
                            "<pingfederate.version> is 13.1.0, PF_VERSION is 13.1.3")

    def test_dockerfile_digest(self):
        other = "sha256:" + "ab" * 32
        self.assert_problem({"build/pingfederate/Dockerfile": f"FROM {IMAGE}@{other}\n"},
                            f"build/pingfederate/Dockerfile: FROM {IMAGE}@{other} is not {IMAGE}@{DIGEST}")

    def test_dockerfile_without_a_digest(self):
        self.assert_problem({"build/pingfederate/Dockerfile": f"FROM {IMAGE}\n"}, "Dockerfile: FROM")

    def test_action_with_a_literal(self):
        err = self.assert_problem({".github/actions/pf-provided-jars/action.yml": 'runs:\n  steps:\n    - run: mvn install:install-file -Dversion=13.1.3.0\n'},
                                  "action.yml: does not read build/pf-version.env")
        self.assertIn("carries the version literal 13.1.3.0", err)

    def test_workflow_not_reading_the_env_file(self):
        self.assert_problem({".github/workflows/mutation.yml": "env:\n  PF_IMAGE: something\n"},
                            ".github/workflows/mutation.yml: does not append build/pf-version.env to $GITHUB_ENV")

    def test_author_sh(self):
        self.assert_problem({"conformance/author.sh": f'IMAGE="{IMAGE}"\n'}, "conformance/author.sh: does not source")

    def test_apply_sh(self):
        self.assert_problem({"conformance/apply.sh": 'export TF_VAR_pf_admin_host=x\n'}, "conformance/apply.sh: does not export TF_VAR_pf_product_version")

    def test_provider_literal(self):
        self.assert_problem({"conformance/terraform/provider.tf": 'provider "pingfederate" {\n  product_version = "13.0"\n}\n'},
                            "provider.tf: product_version is not var.pf_product_version")

    def test_variables_default(self):
        self.assert_problem({"conformance/terraform/variables.tf": 'variable "pf_product_version" {\n  default = "13.0"\n}\n'},
                            "variables.tf: pf_product_version defaults to 13.0, PF_TERRAFORM_PRODUCT_VERSION is 13.1")

    def test_a_stray_image_reference_outside_markdown(self):
        self.assert_problem({"conformance/up.sh": "docker pull pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest\n"},
                            "conformance/up.sh:1: pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest is not the 13.1.3-alpine_3.24.1-al21-latest")

    def test_a_stray_digest_outside_markdown(self):
        other = "sha256:" + "cd" * 32
        self.assert_problem({"conformance/up.sh": f"docker pull {IMAGE}@{other}\n"}, f"conformance/up.sh:1: digest {other} is not PF_IMAGE_DIGEST")

    def test_markdown_the_showcase_and_the_tools_tests_are_exempt(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, {"README.md": "Was pingidentity/pingfederate:12.2.6-latest once.\n",
                              "showcase/other.html": "pingidentity/pingfederate:12.2.6-latest\n",
                              "tools/tests/test_x.py": "FIXTURE = 'pingidentity/pingfederate:12.2.6-latest'\n"})
            self.assertEqual(run(root)[0], 0)

    def test_a_reference_ending_a_sentence_is_read_without_the_full_stop(self):
        self.assert_problem({"conformance/up.sh": "# it was pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest.\n"},
                            "conformance/up.sh:1: pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest is not")


class EnvFile(unittest.TestCase):

    def test_missing(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, {"build/pf-version.env": None})
            code, out, err = run(root)
            self.assertEqual(code, 2)
            self.assertIn("cannot read build/pf-version.env", err)

    def test_a_missing_key(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, {"build/pf-version.env": ENV.replace("PF_IMAGE_DIGEST=" + DIGEST + "\n", "")})
            code, out, err = run(root)
            self.assertEqual(code, 1)
            self.assertIn("PF_IMAGE_DIGEST is missing", err)

    def test_keys_that_disagree_with_each_other(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, {"build/pf-version.env": ENV.replace("PF_SDK_MAVEN_VERSION=13.1.3.0", "PF_SDK_MAVEN_VERSION=13.1.2.0")
                                                          .replace("PF_TERRAFORM_PRODUCT_VERSION=13.1", "PF_TERRAFORM_PRODUCT_VERSION=13.0")})
            code, out, err = run(root)
            self.assertEqual(code, 1)
            self.assertIn("PF_SDK_MAVEN_VERSION 13.1.2.0 is not PF_VERSION.0", err)
            self.assertIn("PF_TERRAFORM_PRODUCT_VERSION 13.0 is not PF_VERSION's major.minor", err)

    def test_not_key_value(self):
        with tempfile.TemporaryDirectory() as root:
            write_repo(root, {"build/pf-version.env": ENV + "export PF_X\n"})
            code, out, err = run(root)
            self.assertEqual(code, 2)
            self.assertIn("not KEY=VALUE", err)


if __name__ == "__main__":
    unittest.main()
