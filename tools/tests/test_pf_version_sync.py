"""tools/pf-version-sync.py: the env file follows the Dockerfile's FROM after a bump, changing only
the values, and refuses a FROM without a digest."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

sync = load("pf-version-sync.py")

OLD_DIGEST = "sha256:" + "0d55" * 16
NEW_DIGEST = "sha256:" + "9e7a" * 16
ENV = f"""# The one place the PingFederate version is written down.
#
# KEY=VALUE only, no quoting.
PF_VERSION=13.1.3
PF_SDK_MAVEN_VERSION=13.1.3.0
PF_IMAGE=pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest
# The index digest.
PF_IMAGE_DIGEST={OLD_DIGEST}
# major.minor
PF_TERRAFORM_PRODUCT_VERSION=13.1
"""


def write(root, dockerfile, env=ENV):
    for rel, text in (("build/pingfederate/Dockerfile", dockerfile), ("build/pf-version.env", env)):
        if text is None:
            continue
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def read_env(root):
    with open(os.path.join(root, "build/pf-version.env"), encoding="utf-8") as f:
        return f.read()


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = sync.main(argv)
    return code, out.getvalue(), err.getvalue()


class Sync(unittest.TestCase):

    def test_a_bump_rewrites_the_values_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, f"# header\nFROM pingidentity/pingfederate:13.2.0-alpine_3.25.0-al21-latest@{NEW_DIGEST}\nUSER root\n")
            code, out, err = run(["--root", root])
            self.assertEqual(code, 0, err)
            self.assertEqual(read_env(root), ENV
                             .replace("PF_VERSION=13.1.3", "PF_VERSION=13.2.0")
                             .replace("PF_SDK_MAVEN_VERSION=13.1.3.0", "PF_SDK_MAVEN_VERSION=13.2.0.0")
                             .replace("13.1.3-alpine_3.24.1-al21-latest", "13.2.0-alpine_3.25.0-al21-latest")
                             .replace(OLD_DIGEST, NEW_DIGEST)
                             .replace("PF_TERRAFORM_PRODUCT_VERSION=13.1", "PF_TERRAFORM_PRODUCT_VERSION=13.2"))
            for k in ("PF_VERSION=13.2.0", "PF_SDK_MAVEN_VERSION=13.2.0.0", "PF_TERRAFORM_PRODUCT_VERSION=13.2", "PF_IMAGE_DIGEST=" + NEW_DIGEST):
                self.assertIn("set " + k, out)
            self.assertIn("now run tools/pf-version-check.py", out)

    def test_a_digest_only_bump(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, f"FROM pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest@{NEW_DIGEST}\n")
            code, out, err = run(["--root", root])
            self.assertEqual(code, 0)
            self.assertEqual(read_env(root), ENV.replace(OLD_DIGEST, NEW_DIGEST))
            self.assertEqual(out.count("set "), 1)

    def test_already_in_step(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, f"FROM pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest@{OLD_DIGEST}\n")
            code, out, err = run(["--root", root])
            self.assertEqual(code, 0)
            self.assertIn("unchanged", out)
            self.assertEqual(read_env(root), ENV)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, f"FROM pingidentity/pingfederate:13.2.0-alpine_3.25.0-al21-latest@{NEW_DIGEST}\n")
            code, out, err = run(["--root", root, "--dry-run"])
            self.assertEqual(code, 0)
            self.assertIn("would set PF_VERSION=13.2.0", out)
            self.assertEqual(read_env(root), ENV)

    def test_a_from_without_a_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "FROM pingidentity/pingfederate:13.2.0-alpine_3.25.0-al21-latest\n")
            code, out, err = run(["--root", root])
            self.assertEqual(code, 2)
            self.assertIn("the digest is required", err)
            self.assertEqual(read_env(root), ENV)

    def test_an_env_file_missing_a_key_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, f"FROM pingidentity/pingfederate:13.2.0-alpine_3.25.0-al21-latest@{NEW_DIGEST}\n",
                  env=ENV.replace("PF_TERRAFORM_PRODUCT_VERSION=13.1\n", ""))
            code, out, err = run(["--root", root])
            self.assertEqual(code, 2)
            self.assertIn("lacks PF_TERRAFORM_PRODUCT_VERSION", err)

    def test_missing_files(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, None)
            self.assertEqual(run(["--root", root])[0], 2)


if __name__ == "__main__":
    unittest.main()
