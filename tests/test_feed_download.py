import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from feed_download import (
    FeedDownloadLimitExceeded,
    download_bytes,
    download_to_tempfile,
)


class FakeResponse:
    def __init__(self, chunks: list[bytes], content_length: str | None = None):
        self.chunks = chunks
        self.headers = {} if content_length is None else {"Content-Length": content_length}
        self.iterated = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size: int):
        self.iterated = True
        yield from self.chunks


class FeedDownloadTests(unittest.TestCase):
    def test_rejects_declared_oversize_before_reading(self):
        response = FakeResponse([b"ignored"], content_length="11")
        with patch("feed_download.requests.get", return_value=response):
            with self.assertRaises(FeedDownloadLimitExceeded):
                download_bytes("https://example.test/feed", max_bytes=10, timeout=1)
        self.assertFalse(response.iterated)

    def test_rejects_actual_stream_over_limit(self):
        response = FakeResponse([b"123456", b"78901"])
        with patch("feed_download.requests.get", return_value=response):
            with self.assertRaises(FeedDownloadLimitExceeded):
                download_bytes("https://example.test/feed", max_bytes=10, timeout=1)

    def test_accepts_exact_limit(self):
        response = FakeResponse([b"12345", b"67890"], content_length="10")
        with patch("feed_download.requests.get", return_value=response):
            result = download_bytes("https://example.test/feed", max_bytes=10, timeout=1)
        self.assertEqual(result, b"1234567890")

    def test_removes_partial_tempfile_after_limit_exceeded(self):
        response = FakeResponse([b"123456", b"78901"])
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "feed_download.tempfile.gettempdir", return_value=temp_dir
        ), patch("feed_download.requests.get", return_value=response):
            with self.assertRaises(FeedDownloadLimitExceeded):
                download_to_tempfile(
                    "https://example.test/archive",
                    max_bytes=10,
                    timeout=1,
                    suffix=".zip",
                )
            self.assertEqual(list(Path(temp_dir).iterdir()), [])


if __name__ == "__main__":
    unittest.main()