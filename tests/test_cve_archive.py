import io
import json
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cvelist.affected_products import extract_affected_product_rows
from cvelist.tasks import _ArchiveLimitExceeded, _iter_records


def make_zip(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, contents in entries:
            archive.writestr(name, contents)
    return output.getvalue()


class CveArchiveTests(unittest.TestCase):
    def iter_records(self, contents: bytes) -> list[dict]:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "feed.zip"
            archive_path.write_bytes(contents)
            return list(_iter_records(archive_path))

    def test_reads_only_matching_json_entries(self):
        records = [
            {"cveMetadata": {"cveId": f"CVE-2026-{index}"}}
            for index in range(1, 4)
        ]
        archive = make_zip([
            *[
                (f"2026/cves/{record['cveMetadata']['cveId']}.json", json.dumps(record).encode())
                for record in records
            ],
            ("2026/README.txt", b"not a CVE record"),
        ])
        with patch.dict("os.environ", {"CVE_IMPORT_PARSE_WORKERS": "3"}):
            with patch("cvelist.tasks.ThreadPoolExecutor", wraps=ThreadPoolExecutor) as executor:
                self.assertEqual(self.iter_records(archive), records)
                executor.assert_called_once_with(max_workers=3)

    def test_extracts_affected_products_and_version_ranges(self):
        record = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "Microsoft",
                            "product": ".NET 10.0",
                            "platforms": ["Windows", 1],
                            "versions": [
                                {
                                    "version": "10.0.0",
                                    "lessThan": "10.0.14",
                                    "status": "affected",
                                    "versionType": "custom",
                                },
                                {"version": "10.0.14", "status": "unaffected"},
                            ],
                        }
                    ]
                }
            }
        }

        rows = extract_affected_product_rows("CVE-2026-1", record)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["vendor"], "Microsoft")
        self.assertEqual(rows[0]["platforms"], ["Windows"])
        self.assertEqual(rows[0]["less_than"], "10.0.14")
        self.assertEqual(rows[1]["version_status"], "unaffected")

    def test_keeps_products_without_version_entries(self):
        record = {"containers": {"cna": {"affected": [{"vendor": "Acme", "product": "Widget"}]}}}

        rows = extract_affected_product_rows("CVE-2026-2", record)

        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["version"])
        self.assertEqual(rows[0]["platforms"], [])

    def test_rejects_parse_worker_count_above_limit(self):
        archive = make_zip([])
        with patch.dict("os.environ", {"CVE_IMPORT_PARSE_WORKERS": "9"}):
            with self.assertRaises(ValueError):
                self.iter_records(archive)

    def test_reads_records_from_nested_zip_without_extracting_archive_tree(self):
        record = {"cveMetadata": {"cveId": "CVE-2026-2"}}
        nested = make_zip([
            ("2026/cves/CVE-2026-2.json", json.dumps(record).encode()),
            ("2026/README.txt", b"ignore this file"),
        ])
        outer = make_zip([("2026/cves.zip", nested)])
        self.assertEqual(self.iter_records(outer), [record])

    def test_rejects_oversized_record(self):
        archive = make_zip([("2026/cves/CVE-2026-3.json", b"12345678901")])
        with patch("cvelist.tasks.MAX_CVE_RECORD_BYTES", 10):
            with self.assertRaises(_ArchiveLimitExceeded):
                self.iter_records(archive)

    def test_rejects_total_expansion_over_limit(self):
        record = {"cveMetadata": {"cveId": "CVE-2026-4"}}
        archive = make_zip([
            ("2026/cves/CVE-2026-4.json", json.dumps(record).encode()),
        ])
        with patch("cvelist.tasks.MAX_EXPANDED_ARCHIVE_BYTES", 10):
            with self.assertRaises(_ArchiveLimitExceeded):
                self.iter_records(archive)

    def test_rejects_excessive_nested_archive_depth(self):
        record = {"cveMetadata": {"cveId": "CVE-2026-5"}}
        innermost = make_zip([
            ("2026/cves/CVE-2026-5.json", json.dumps(record).encode()),
        ])
        nested = make_zip([("cves.zip", innermost)])
        outer = make_zip([("year.zip", nested)])
        with patch("cvelist.tasks.MAX_NESTED_ARCHIVE_DEPTH", 1):
            with self.assertRaises(_ArchiveLimitExceeded):
                self.iter_records(outer)


if __name__ == "__main__":
    unittest.main()