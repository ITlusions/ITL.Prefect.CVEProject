import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cvelist import tasks


class CommitPerBatchTests(unittest.TestCase):
    def _run(self, record_count: int, batch_size: int):
        conn = MagicMock()
        connect = MagicMock()
        connect.return_value.__enter__.return_value = conn
        records = [{"n": i} for i in range(record_count)]

        with patch.object(tasks, "BATCH_SIZE", batch_size), \
             patch.object(tasks.psycopg, "connect", connect), \
             patch.object(tasks, "get_run_logger", MagicMock()), \
             patch.object(tasks, "_iter_records", return_value=iter(records)), \
             patch.object(tasks, "_summarize", side_effect=lambda r: {"cve_id": f"CVE-{r['n']}"}), \
             patch.object(tasks, "extract_cwe_associations", return_value=[]), \
             patch.object(tasks, "extract_affected_product_rows", return_value=[]), \
             patch.dict("os.environ", {"CVE_DATABASE_URL": "postgresql://test"}):
            result = tasks.process_archive.fn(Path("delta.zip"))
        return conn, result

    def test_commits_after_each_full_batch_and_the_remainder(self):
        conn, _ = self._run(record_count=5, batch_size=2)
        # One commit after schema setup, then one per batch: 2 full batches and 1 partial.
        self.assertEqual(conn.commit.call_count, 4)

    def test_returns_total_record_count(self):
        _, result = self._run(record_count=5, batch_size=2)
        self.assertEqual(result, 5)


if __name__ == "__main__":
    unittest.main()
