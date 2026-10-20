import tempfile
from collections.abc import Iterator
from pathlib import Path

import requests

CHUNK_SIZE = 1 << 20


class FeedDownloadLimitExceeded(ValueError):
    pass


def _iter_limited_chunks(response: requests.Response, max_bytes: int) -> Iterator[bytes]:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if declared_size < 0:
            raise ValueError("Invalid Content-Length header")
        if declared_size > max_bytes:
            raise FeedDownloadLimitExceeded(
                f"Feed declares {declared_size} bytes; limit is {max_bytes}"
            )

    received = 0
    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
        if not chunk:
            continue
        received += len(chunk)
        if received > max_bytes:
            raise FeedDownloadLimitExceeded(
                f"Feed exceeded the {max_bytes}-byte download limit"
            )
        yield chunk


def download_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> bytes:
    chunks = []
    with requests.get(url, stream=True, timeout=timeout, headers=headers) as response:
        response.raise_for_status()
        chunks.extend(_iter_limited_chunks(response, max_bytes))
    return b"".join(chunks)


def download_to_tempfile(
    url: str,
    *,
    max_bytes: int,
    timeout: int,
    suffix: str,
    headers: dict[str, str] | None = None,
) -> Path:
    target: Path | None = None
    completed = False
    try:
        with tempfile.NamedTemporaryFile(prefix="itl-feed-", suffix=suffix, delete=False) as handle:
            target = Path(handle.name)
            with requests.get(url, stream=True, timeout=timeout, headers=headers) as response:
                response.raise_for_status()
                for chunk in _iter_limited_chunks(response, max_bytes):
                    handle.write(chunk)
        completed = True
        return target
    finally:
        if not completed and target is not None:
            target.unlink(missing_ok=True)