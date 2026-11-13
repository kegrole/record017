"""Unittests for keyaudit, covering the six acceptance criteria.

The fixture mirrors the demo rules:
  main/key.pem    2048-bit PKCS#1 private key, mode 0644
  legacy/key.pem  1024-bit PKCS#1 private key, mode 0600
  web/cert.pem    self-signed X.509 certificate (own 2048-bit key)
  web/key.pem     2048-bit PKCS#1 private key that does NOT match the cert
"""

import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import generate_keys as gen  # noqa: E402
from keyaudit import asn1, cli, der, report  # noqa: E402

SUBJECT_RDNS = [
    (gen.OID_COUNTRY, "CN"),
    (gen.OID_ORGANIZATION, "Keyaudit Demo"),
    (gen.OID_COMMON_NAME, "demo.example.com"),
]
EXPECTED_SUBJECT = "C=CN, O=Keyaudit Demo, CN=demo.example.com"

NOT_BEFORE = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
NOT_AFTER = datetime(2028, 6, 7, 8, 9, 10, tzinfo=timezone.utc)
EXPECTED_NOT_AFTER = "2028-06-07T08:09:10Z"


def _write(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)
    os.chmod(path, mode)


class Fixture:
    """Builds the fixture tree once; RSA generation is the slow part."""

    @classmethod
    def build(cls, root):
        main_key = gen.generate_rsa_key(2048)
        legacy_key = gen.generate_rsa_key(1024)
        cert_key = gen.generate_rsa_key(2048)
        web_key = gen.generate_rsa_key(2048)
        while web_key["n"] == cert_key["n"]:
            web_key = gen.generate_rsa_key(2048)

        _write(os.path.join(root, "main", "key.pem"),
               gen.to_pem("RSA PRIVATE KEY", gen.pkcs1_private_der(main_key)),
               0o644)
        _write(os.path.join(root, "legacy", "key.pem"),
               gen.to_pem("RSA PRIVATE KEY", gen.pkcs1_private_der(legacy_key)),
               0o600)
        cert_der = gen.build_certificate(
            cert_key, SUBJECT_RDNS, SUBJECT_RDNS, serial=0x01020304,
            not_before=NOT_BEFORE, not_after=NOT_AFTER)
        _write(os.path.join(root, "web", "cert.pem"),
               gen.to_pem("CERTIFICATE", cert_der), 0o644)
        _write(os.path.join(root, "web", "key.pem"),
               gen.to_pem("RSA PRIVATE KEY", gen.pkcs1_private_der(web_key)),
               0o600)
        return {
            "main_key": main_key, "legacy_key": legacy_key,
            "cert_key": cert_key, "web_key": web_key,
        }


class KeyauditTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = cls.tmp.name
        cls.keys = Fixture.build(cls.root)
        cls.records = {rec["file"].replace(os.sep, "/"): rec
                       for rec in report.audit_directory(cls.root)}

    def record(self, name):
        return self.records[name]

    def codes(self, name):
        return [issue["code"] for issue in self.record(name)["issues"]]


class TestThreeExpectedIssues(KeyauditTestCase):
    """Criterion 2: the three expected problems are all reported."""

    def test_permission_issue_on_0644_key(self):
        self.assertIn("PERMISSION_TOO_OPEN", self.codes("main/key.pem"))

    def test_weak_key_issue_on_1024_key(self):
        self.assertIn("WEAK_KEY", self.codes("legacy/key.pem"))

    def test_unmatched_issue_on_lonely_key(self):
        self.assertIn("UNMATCHED_KEY", self.codes("web/key.pem"))

    def test_no_other_issues(self):
        self.assertEqual(self.codes("main/key.pem"), ["PERMISSION_TOO_OPEN"])
        self.assertEqual(self.codes("legacy/key.pem"), ["WEAK_KEY"])
        self.assertEqual(self.codes("web/key.pem"), ["UNMATCHED_KEY"])
        self.assertEqual(self.codes("web/cert.pem"), [])


class TestModulusBits(KeyauditTestCase):
    """Criterion 3: bit lengths come from the DER modulus, not the PEM text."""

    def test_bits(self):
        self.assertEqual(self.record("main/key.pem")["bits"], 2048)
        self.assertEqual(self.record("legacy/key.pem")["bits"], 1024)
        self.assertEqual(self.record("web/key.pem")["bits"], 2048)
        self.assertEqual(self.record("web/cert.pem")["bits"], 2048)

    def test_bits_match_actual_moduli(self):
        self.assertEqual(self.record("main/key.pem")["bits"],
                         self.keys["main_key"]["n"].bit_length())
        self.assertEqual(self.record("legacy/key.pem")["bits"],
                         self.keys["legacy_key"]["n"].bit_length())
        self.assertEqual(self.record("web/key.pem")["bits"],
                         self.keys["web_key"]["n"].bit_length())


class TestPermissionFollowsChmod(KeyauditTestCase):
    """Criterion 4: chmod 0600 makes the permission finding disappear."""

    def test_chmod_0600_clears_permission_issue(self):
        path = os.path.join(self.root, "main", "key.pem")
        os.chmod(path, 0o600)
        self.addCleanup(os.chmod, path, 0o644)
        records = {rec["file"].replace(os.sep, "/"): rec
                   for rec in report.audit_directory(self.root)}
        issues = records["main/key.pem"]["issues"]
        self.assertNotIn("PERMISSION_TOO_OPEN", [i["code"] for i in issues])
        self.assertEqual(records["main/key.pem"]["permission"], "0600")
        self.assertEqual(issues, [])


class TestCertificateFields(KeyauditTestCase):
    """Criterion 5: subject and not_after are read back exactly as encoded."""

    def test_subject(self):
        self.assertEqual(self.record("web/cert.pem")["subject"],
                         EXPECTED_SUBJECT)

    def test_not_after(self):
        self.assertEqual(self.record("web/cert.pem")["not_after"],
                         EXPECTED_NOT_AFTER)
        self.assertEqual(self.record("web/cert.pem")["not_after"],
                         asn1.format_time(NOT_AFTER))

    def test_not_before(self):
        self.assertEqual(self.record("web/cert.pem")["not_before"],
                         "2026-01-02T03:04:05Z")


class TestRecordShape(KeyauditTestCase):
    """Criterion 6: every record carries the six mandatory fields."""

    REQUIRED = ("file", "kind", "bits", "encrypted", "permission", "issues")

    def test_all_records_have_required_fields(self):
        self.assertEqual(len(self.records), 4)
        for name, rec in self.records.items():
            for field in self.REQUIRED:
                self.assertIn(field, rec, "%s misses %s" % (name, field))
            self.assertIsInstance(rec["issues"], list)
            for issue in rec["issues"]:
                self.assertIn("code", issue)
                self.assertIn("detail", issue)

    def test_empty_issues_key_present(self):
        rec = self.record("web/cert.pem")
        self.assertIn("issues", rec)
        self.assertEqual(rec["issues"], [])

    def test_kinds(self):
        self.assertEqual(self.record("main/key.pem")["kind"], "private_key")
        self.assertEqual(self.record("legacy/key.pem")["kind"], "private_key")
        self.assertEqual(self.record("web/key.pem")["kind"], "private_key")
        self.assertEqual(self.record("web/cert.pem")["kind"], "certificate")


class TestEncryptionDetection(KeyauditTestCase):
    """Requirement 3: encrypted markers are detected, plaintext reported."""

    def test_fixture_keys_are_plaintext(self):
        for name in ("main/key.pem", "legacy/key.pem", "web/key.pem"):
            self.assertFalse(self.record(name)["encrypted"], name)

    def test_encrypted_private_key_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = der.encode_sequence(
                der.encode_sequence(
                    der.encode_oid("1.2.840.113549.1.5.13"),
                    der.encode_null(),
                ),
                der.encode_octet_string(os.urandom(64)),
            )
            path = os.path.join(tmp, "enc.pem")
            _write(path, gen.to_pem("ENCRYPTED PRIVATE KEY", body), 0o600)
            rec = report.audit_file(path, "enc.pem")
            self.assertEqual(rec["kind"], "private_key")
            self.assertTrue(rec["encrypted"])
            self.assertIsNone(rec["bits"])

    def test_proc_type_encrypted_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            pem_text = (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "Proc-Type: 4,ENCRYPTED\n"
                "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n"
                "\n"
                "AQIDBAUGBwgJCgsMDQ4PEA==\n"
                "-----END RSA PRIVATE KEY-----\n"
            )
            path = os.path.join(tmp, "k.pem")
            _write(path, pem_text, 0o600)
            rec = report.audit_file(path, "k.pem")
            self.assertTrue(rec["encrypted"])
            self.assertIsNone(rec["bits"])


class TestPkcs8AndPublicKeys(KeyauditTestCase):
    """PKCS#8 private keys and both public key armors are understood."""

    def test_pkcs8_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = self.keys["main_key"]
            pkcs8 = der.encode_sequence(
                der.encode_integer(0),
                der.encode_sequence(
                    der.encode_oid(gen.OID_RSA_ENCRYPTION), der.encode_null()),
                der.encode_octet_string(gen.pkcs1_private_der(key)),
            )
            path = os.path.join(tmp, "k8.pem")
            _write(path, gen.to_pem("PRIVATE KEY", pkcs8), 0o600)
            rec = report.audit_file(path, "k8.pem")
            self.assertEqual(rec["kind"], "private_key")
            self.assertFalse(rec["encrypted"])
            self.assertEqual(rec["bits"], 2048)

    def test_public_key_armors(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = self.keys["main_key"]
            pkcs1_path = os.path.join(tmp, "pkcs1.pem")
            _write(pkcs1_path,
                   gen.to_pem("RSA PUBLIC KEY", gen.pkcs1_public_der(key)),
                   0o644)
            spki_path = os.path.join(tmp, "spki.pem")
            _write(spki_path, gen.to_pem("PUBLIC KEY", gen.spki_der(key)),
                   0o644)
            rec1 = report.audit_file(pkcs1_path, "pkcs1.pem")
            rec2 = report.audit_file(spki_path, "spki.pem")
            self.assertEqual(rec1["kind"], "public_key")
            self.assertEqual(rec2["kind"], "public_key")
            self.assertEqual(rec1["bits"], 2048)
            self.assertEqual(rec2["bits"], 2048)


class TestPairing(KeyauditTestCase):
    """Requirement 4: matching cert+key pair up, mismatches are flagged."""

    def test_matching_pair_has_no_unmatched_issue(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = gen.generate_rsa_key(2048)
            cert_der = gen.build_certificate(
                key, SUBJECT_RDNS, SUBJECT_RDNS, serial=7,
                not_before=NOT_BEFORE, not_after=NOT_AFTER)
            _write(os.path.join(tmp, "cert.pem"),
                   gen.to_pem("CERTIFICATE", cert_der), 0o644)
            _write(os.path.join(tmp, "key.pem"),
                   gen.to_pem("RSA PRIVATE KEY", gen.pkcs1_private_der(key)),
                   0o600)
            records = {rec["file"]: rec
                       for rec in report.audit_directory(tmp)}
            self.assertEqual(records["key.pem"]["issues"], [])
            self.assertEqual(records["cert.pem"]["issues"], [])

    def test_dir_without_certificates_skips_pairing(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = gen.generate_rsa_key(2048)
            _write(os.path.join(tmp, "only.pem"),
                   gen.to_pem("RSA PRIVATE KEY", gen.pkcs1_private_der(key)),
                   0o600)
            records = report.audit_directory(tmp)
            self.assertEqual(records[0]["issues"], [])


class TestCli(KeyauditTestCase):
    """Requirement 7/8: CLI writes the report and prints a summary line."""

    def test_cli_summary_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "nested", "report.json")
            stream = io.StringIO()
            rc = cli.main(["--dir", self.root, "--out", out_path],
                          stream=stream)
            self.assertEqual(rc, 0)
            line = stream.getvalue().strip()
            self.assertIn("files=4", line)
            self.assertIn("private_keys=3", line)
            self.assertIn("certificates=1", line)
            self.assertIn("issues=3", line)
            with open(out_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["summary"]["files"], 4)
            self.assertEqual(payload["summary"]["issues"], 3)
            self.assertEqual(len(payload["records"]), 4)


if __name__ == "__main__":
    unittest.main()
