import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from csaf.csaf_import import (
    Change,
    import_keys,
    parse_changes,
    parse_document,
    select_changes,
    verify_sha512,
    verify_signature,
)

FIXTURES = Path(__file__).parent / "fixtures" / "csaf"
DOC_NAME = "ncsc-2026-0438.json"
TRUSTED = {"192C338AA6E59A644DB489AA82EA56A0BD198461"}
HAS_GPG = shutil.which("gpg") is not None


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text)


class ChangeSelectionTests(unittest.TestCase):
    def test_parses_path_and_timestamp_rows(self):
        changes = parse_changes("2026/ncsc-2026-0438.json,2026-10-19T08:08:49.567699+00:00\n")
        self.assertEqual(changes, [Change("2026/ncsc-2026-0438.json", ts("2026-10-19T08:08:49.567699+00:00"))])

    def test_first_run_selects_everything_oldest_first(self):
        changes = [
            Change("2026/b.json", ts("2026-10-02T00:00:00+00:00")),
            Change("2026/a.json", ts("2026-10-01T00:00:00+00:00")),
        ]
        pending = select_changes(changes, stored={})
        self.assertEqual([c.path for c in pending], ["2026/a.json", "2026/b.json"])

    def test_delta_skips_unchanged_and_picks_up_revised_versions(self):
        changes = [
            Change("2026/a.json", ts("2026-10-01T00:00:00+00:00")),   # unchanged
            Change("2026/b.json", ts("2026-10-05T00:00:00+00:00")),   # revised
            Change("2026/c.json", ts("2026-10-06T00:00:00+00:00")),   # new
        ]
        stored = {
            "2026/a.json": ts("2026-10-01T00:00:00+00:00"),
            "2026/b.json": ts("2026-10-02T00:00:00+00:00"),
        }
        pending = select_changes(changes, stored)
        self.assertEqual([c.path for c in pending], ["2026/b.json", "2026/c.json"])


class HashCheckTests(unittest.TestCase):
    def setUp(self):
        self.document = (FIXTURES / DOC_NAME).read_bytes()
        self.sha_file = (FIXTURES / (DOC_NAME + ".sha512")).read_text()

    def test_accepts_matching_hash(self):
        self.assertTrue(verify_sha512(self.document, self.sha_file))

    def test_accepts_hash_file_that_names_the_document_with_a_suffix(self):
        # NCSC writes `ncsc-2025-0050-0.json` next to `ncsc-2025-0050.json`.
        document = (FIXTURES / "ncsc-2025-0050.json").read_bytes()
        sha_file = (FIXTURES / "ncsc-2025-0050.json.sha512").read_text()
        self.assertIn("-0.json", sha_file)
        self.assertTrue(verify_sha512(document, sha_file))

    def test_rejects_tampered_document(self):
        self.assertFalse(verify_sha512(self.document + b" ", self.sha_file))

    def test_rejects_empty_hash_file(self):
        self.assertFalse(verify_sha512(self.document, ""))


@unittest.skipUnless(HAS_GPG, "gpg is required for signature tests")
class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.homedir = Path(tempfile.mkdtemp(prefix="csaf-test-keyring-"))
        self.addCleanup(shutil.rmtree, self.homedir, ignore_errors=True)
        self.document = (FIXTURES / DOC_NAME).read_bytes()
        self.signature = (FIXTURES / (DOC_NAME + ".asc")).read_bytes()
        key = (FIXTURES / "pgp-2026.asc").read_bytes()
        import_keys(self.homedir, [key], TRUSTED)

    def test_accepts_document_signed_by_trusted_key(self):
        self.assertTrue(verify_signature(self.homedir, self.signature, self.document, TRUSTED))

    def test_rejects_tampered_document(self):
        self.assertFalse(verify_signature(self.homedir, self.signature, self.document + b" ", TRUSTED))

    def test_rejects_when_signer_is_not_trusted(self):
        self.assertFalse(verify_signature(self.homedir, self.signature, self.document, {"0" * 40}))

    def test_accepts_signature_made_before_the_key_expired(self):
        # The 2025 key expired on 2026-02-01. The 2025-02-11 signature predates that.
        homedir = Path(tempfile.mkdtemp(prefix="csaf-test-keyring-"))
        self.addCleanup(shutil.rmtree, homedir, ignore_errors=True)
        key_2025 = (FIXTURES / "pgp-2025.asc").read_bytes()
        expected = {"8FD973D54933B8D86D2CE5F9CAD4CEAB247E705F"}
        import_keys(homedir, [key_2025], expected)
        document = (FIXTURES / "ncsc-2025-0050.json").read_bytes()
        signature = (FIXTURES / "ncsc-2025-0050.json.asc").read_bytes()
        self.assertTrue(verify_signature(homedir, signature, document, expected))

    def test_rejects_expired_key_signature_when_document_is_altered(self):
        homedir = Path(tempfile.mkdtemp(prefix="csaf-test-keyring-"))
        self.addCleanup(shutil.rmtree, homedir, ignore_errors=True)
        expected = {"8FD973D54933B8D86D2CE5F9CAD4CEAB247E705F"}
        import_keys(homedir, [(FIXTURES / "pgp-2025.asc").read_bytes()], expected)
        document = (FIXTURES / "ncsc-2025-0050.json").read_bytes()
        signature = (FIXTURES / "ncsc-2025-0050.json.asc").read_bytes()
        self.assertFalse(verify_signature(homedir, signature, document + b" ", expected))

    def test_import_fails_when_keys_do_not_match_metadata(self):
        other = Path(tempfile.mkdtemp(prefix="csaf-test-keyring-"))
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        with self.assertRaises(ValueError):
            import_keys(other, [(FIXTURES / "pgp-2026.asc").read_bytes()], {"0" * 40})


class DocumentParsingTests(unittest.TestCase):
    def test_extracts_tracking_fields_and_cve_ids(self):
        document = json.loads((FIXTURES / DOC_NAME).read_text())
        fields = parse_document(document)
        self.assertEqual(fields["tracking_id"], "NCSC-2026-0438")
        self.assertTrue(fields["title"])
        expected = sorted({v["cve"] for v in document["vulnerabilities"] if v.get("cve")})
        self.assertEqual(fields["cve_ids"], expected)
        self.assertTrue(all(cve.startswith("CVE-") for cve in fields["cve_ids"]))


if __name__ == "__main__":
    unittest.main()
