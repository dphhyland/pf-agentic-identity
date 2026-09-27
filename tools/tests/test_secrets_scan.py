"""tools/ci/secrets-scan.py on made-up files: every shape of private key is found, the public shapes and the
prose that names them are not, the repository's own JSON fixtures and documents pass, and an excluded path
stays excluded. The keys below are made up here and sign nothing."""
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

scan = load("ci/secrets-scan.py")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg"

PUBLIC_RSA_JWKS = f"""{{
  "keys": [
    {{
      "kty": "RSA",
      "kid": "one",
      "use": "sig",
      "n": "{B64}{B64}",
      "e": "AQAB"
    }}
  ]
}}
"""

PRIVATE_RSA_JWKS = f"""{{
  "keys": [
    {{
      "kty": "RSA",
      "kid": "one",
      "n": "{B64}{B64}",
      "e": "AQAB",
      "d": "{B64}{B64}",
      "p": "{B64}",
      "q": "{B64}"
    }}
  ]
}}
"""

PRIVATE_EC_COMPACT = f'{{"kty":"EC","crv":"P-256","x":"{B64}","y":"{B64}","d":"{B64}"}}\n'
PUBLIC_EC_JAVA = f'    String jwk = "{{\\"kty\\":\\"EC\\",\\"crv\\":\\"P-256\\",\\"x\\":\\"{B64}\\",\\"y\\":\\"{B64}\\"}}";\n'
PRIVATE_EC_JAVA = f'    String jwk = "{{\\"kty\\":\\"EC\\",\\"d\\":\\"{B64}\\",\\"crv\\":\\"P-256\\"}}";\n'
PRIVATE_OKP_YAML_ISH = f'key: {{ "crv": "Ed25519", "d": "{B64}", "kty": "OKP" }}\n'
# RFC 7518 section 6.3.2.7: the private parts of a multi-prime RSA key are in the objects of "oth".
PRIVATE_RSA_MULTI_PRIME = f'{{"kty":"RSA","n":"{B64}","e":"AQAB","oth":[{{"r":"{B64}","d":"{B64}","t":"{B64}"}}]}}\n'
MIXED_JWKS = f"""{{
  "keys": [
    {{ "kty": "EC", "crv": "P-256", "x": "{B64}", "y": "{B64}" }},
    {{ "kty": "EC", "crv": "P-256", "x": "{B64}", "y": "{B64}", "d": "{B64}" }}
  ]
}}
"""

AGE_IDENTITY = "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" + "QPZRY9X8GF2TVDW0S3JN54KHCE6M\n"
AGE_PREFIX_IN_A_COMMENT = "# PF_ARCHIVE_AGE_KEY holds the identity (AGE-SECRET-KEY-1...) that decrypts it.\n"

# Assembled rather than written out, so this file holds no PEM block for gitleaks to find either.
PEM_HEADERS = [f"-----BEGIN {kind}PRIVATE KEY{block}-----"
               for kind, block in [("", ""), ("RSA ", ""), ("EC ", ""), ("DSA ", ""), ("OPENSSH ", ""),
                                   ("ENCRYPTED ", ""), ("SSH2 ENCRYPTED ", ""), ("PGP ", " BLOCK")]]

PROSE = """A JWK's "d" member is the private exponent; a public key has "kty", "n" and "e" and no "d".
The certificate is what -----BEGIN CERTIFICATE----- delimits; a public key is -----BEGIN PUBLIC KEY-----.
"""


def run(root, files=()):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = scan.main(["--root", root, *files])
    return code, out.getvalue(), err.getvalue()


class ScanText(unittest.TestCase):
    def test_a_private_rsa_jwk_in_a_pretty_printed_set_is_found_at_its_kty_line(self):
        self.assertEqual([(4, "private JWK")], scan.scan_text(PRIVATE_RSA_JWKS))

    def test_a_public_rsa_jwk_set_is_clean(self):
        self.assertEqual([], scan.scan_text(PUBLIC_RSA_JWKS))

    def test_a_compact_private_ec_jwk_is_found(self):
        self.assertEqual([(1, "private JWK")], scan.scan_text(PRIVATE_EC_COMPACT))

    def test_a_private_jwk_in_a_java_string_literal_is_found(self):
        self.assertEqual([(1, "private JWK")], scan.scan_text(PRIVATE_EC_JAVA))

    def test_a_public_jwk_in_a_java_string_literal_is_clean(self):
        self.assertEqual([], scan.scan_text(PUBLIC_EC_JAVA))

    def test_the_member_order_does_not_matter(self):
        self.assertEqual([(1, "private JWK")], scan.scan_text(PRIVATE_OKP_YAML_ISH))

    def test_a_multi_prime_rsa_key_whose_d_is_in_its_oth_objects_is_found(self):
        self.assertEqual([(1, "private JWK")], scan.scan_text(PRIVATE_RSA_MULTI_PRIME))

    def test_a_set_of_public_keys_and_one_private_key_is_reported_once_at_the_private_key(self):
        self.assertEqual([(4, "private JWK")], scan.scan_text(MIXED_JWKS))

    def test_a_d_member_outside_any_kty_object_is_clean(self):
        self.assertEqual([], scan.scan_text(f'{{"d": "{B64}"}} and {{"kty": "EC", "x": "{B64}"}}\n'))

    def test_every_pem_private_key_header_is_found(self):
        for header in PEM_HEADERS:
            with self.subTest(header=header):
                self.assertEqual([(2, "PEM private key")], scan.scan_text(f"# a key\n{header}\nMIIE\n"))

    def test_an_age_identity_is_found_and_its_bare_prefix_is_not(self):
        self.assertEqual([(1, "age identity")], scan.scan_text(AGE_IDENTITY))
        self.assertEqual([], scan.scan_text(AGE_PREFIX_IN_A_COMMENT))

    def test_prose_about_keys_is_clean(self):
        self.assertEqual([], scan.scan_text(PROSE))


class ScanFiles(unittest.TestCase):
    def write(self, root, files):
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

    def test_hits_are_listed_by_file_and_line_and_fail(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, {"a/keys.json": PRIVATE_RSA_JWKS, "b/id.txt": AGE_PREFIX_IN_A_COMMENT + AGE_IDENTITY,
                              "c/public.json": PUBLIC_RSA_JWKS})
            code, out, err = run(root, ["a/keys.json", "b/id.txt", "c/public.json"])
        self.assertEqual(1, code)
        self.assertIn("a/keys.json:4: private JWK", err)
        self.assertIn("b/id.txt:2: age identity", err)
        self.assertNotIn("c/public.json", err)
        self.assertIn("::error file=a/keys.json,line=4::private JWK", out)

    def test_clean_files_pass(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, {"c/public.json": PUBLIC_RSA_JWKS, "d/Notes.java": PUBLIC_EC_JAVA})
            code, out, err = run(root, ["c/public.json", "d/Notes.java"])
        self.assertEqual((0, ""), (code, err))
        self.assertIn("ok: no private key in 2 tracked files", out)

    def test_an_excluded_path_is_skipped_and_named(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, {"tools/ci/secrets-scan.py": PRIVATE_EC_COMPACT, "ok.txt": PROSE})
            code, out, err = run(root, ["tools/ci/secrets-scan.py", "ok.txt"])
        self.assertEqual(0, code)
        self.assertIn("1 excluded on purpose: tools/ci/secrets-scan.py", out)

    def test_the_default_file_list_is_git_ls_files(self):
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(["git", "init", "-q", root], check=True)
            self.write(root, {"tracked.json": PRIVATE_EC_COMPACT, "untracked.json": PRIVATE_RSA_JWKS})
            subprocess.run(["git", "-C", root, "add", "tracked.json"], check=True)
            code, out, err = run(root)
        self.assertEqual(1, code)
        self.assertIn("tracked.json:1: private JWK", err)
        self.assertNotIn("untracked.json", err)


class TheRepositoryOwnFixtures(unittest.TestCase):
    """The documents and test fixtures this repository tracks are public material; the patterns must say so."""

    def tracked(self, *patterns):
        try:
            out = subprocess.run(["git", "-C", REPO, "ls-files", "-z", "--", *patterns],
                                 check=True, capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not run from a git checkout")
        return [p.decode("utf-8") for p in out.split(b"\0") if p]

    def test_docs_and_test_resources_are_clean(self):
        files = self.tracked("docs/*.json", "*/src/test/resources/*", "conformance/suite/*.json")
        self.assertTrue(files, "no fixtures found: the patterns above no longer match the tree")
        hits, _ = scan.scan_files(REPO, files)
        self.assertEqual([], hits)

    def test_every_file_that_names_a_jwk_member_is_clean(self):
        files = [f for f in self.tracked("*.java", "*.py", "*.md", "*.json")
                 if f not in scan.EXCLUDED and "kty" in open(os.path.join(REPO, f), encoding="utf-8", errors="replace").read()]
        self.assertTrue(files)
        hits, _ = scan.scan_files(REPO, files)
        self.assertEqual([], hits)


if __name__ == "__main__":
    unittest.main()
