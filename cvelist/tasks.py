import json
import os
import re
import tempfile
import time
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor
from collections.abc import Iterator
from pathlib import Path
from threading import Lock

import psycopg
from prefect import task
from prefect.logging import get_run_logger
from psycopg.types.json import Jsonb

from feed_download import download_bytes, download_to_tempfile
from cvelist.affected_products import (
    DELETE_AFFECTED_PRODUCTS_SQL,
    INSERT_AFFECTED_PRODUCTS_SQL,
    ensure_affected_product_schema,
    extract_affected_product_rows,
)
from cvelist.patch_commits import (
    CREATE_PATCH_COMMITS_SHA_INDEX_SQL,
    CREATE_PATCH_COMMITS_SQL,
    DELETE_PATCH_COMMITS_SQL,
    INSERT_PATCH_COMMITS_SQL,
    extract_patch_commits,
)
from cwe.weaknesses import (
    CREATE_CVE_WEAKNESSES_SQL,
    CREATE_CWE_ID_INDEX_SQL,
    DELETE_CVE_WEAKNESSES_SQL,
    INSERT_CVE_WEAKNESSES_SQL,
    extract_cwe_associations,
)

RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_PATTERNS = {
    "baseline": re.compile(r"_all_CVEs_at_midnight\.zip(\.zip)?$"),
    "delta": re.compile(r"_delta_CVEs_at_(\d{4}Z|end_of_day)\.zip$"),
}
MAX_RELEASE_METADATA_BYTES = 8 * 1024 * 1024
MAX_ASSET_BYTES = {
    "baseline": 2 * 1024**3,
    "delta": 64 * 1024**2,
}
MAX_CVE_RECORD_BYTES = 16 * 1024**2
MAX_NESTED_ARCHIVE_BYTES = 2 * 1024**3
MAX_EXPANDED_ARCHIVE_BYTES = 8 * 1024**3
MAX_NESTED_ARCHIVE_DEPTH = 2
SPOOL_MEMORY_BYTES = 64 * 1024**2
ARCHIVE_CHUNK_SIZE = 1 << 20
DEFAULT_CVE_IMPORT_PARSE_WORKERS = 4
MAX_CVE_IMPORT_PARSE_WORKERS = 8


@task(retries=3, retry_delay_seconds=30)
def download_release_asset(mode: str) -> Path:
    logger = get_run_logger()
    payload = json.loads(download_bytes(
        RELEASES_URL,
        max_bytes=MAX_RELEASE_METADATA_BYTES,
        timeout=60,
        headers={"Accept": "application/vnd.github+json"},
    ))
    pattern = ASSET_PATTERNS[mode]
    asset = next(
        (a for a in payload["assets"] if pattern.search(a["name"])),
        None,
    )
    if asset is None:
        names = [a["name"] for a in payload["assets"]]
        raise RuntimeError(f"No {mode} asset in release {payload.get('tag_name')}: {names}")
    logger.info(
        "Release %s: selected asset %s (%.1f MB) for mode=%s",
        payload.get("tag_name"), asset["name"], asset["size"] / 1e6, mode,
    )

    started = time.monotonic()
    target = download_to_tempfile(
        asset["browser_download_url"],
        max_bytes=MAX_ASSET_BYTES[mode],
        timeout=300,
        suffix=".zip",
    )
    downloaded = target.stat().st_size
    logger.info(
        "Download complete: %.1f MB to %s in %.1fs",
        downloaded / 1e6,
        target,
        time.monotonic() - started,
    )
    return target


class _ArchiveLimitExceeded(ValueError):
    pass


class _ArchiveBudget:
    def __init__(self) -> None:
        self.expanded_bytes = 0
        self._lock = Lock()

    def consume(self, size: int) -> None:
        with self._lock:
            self.expanded_bytes += size
            if self.expanded_bytes > MAX_EXPANDED_ARCHIVE_BYTES:
                raise _ArchiveLimitExceeded(
                    f"Archive expansion exceeded {MAX_EXPANDED_ARCHIVE_BYTES} bytes"
                )


def _configured_parse_workers() -> int:
    value = os.environ.get("CVE_IMPORT_PARSE_WORKERS", str(DEFAULT_CVE_IMPORT_PARSE_WORKERS))
    try:
        workers = int(value)
    except ValueError as exc:
        raise ValueError("CVE_IMPORT_PARSE_WORKERS must be an integer") from exc
    if not 1 <= workers <= MAX_CVE_IMPORT_PARSE_WORKERS:
        raise ValueError(
            f"CVE_IMPORT_PARSE_WORKERS must be between 1 and {MAX_CVE_IMPORT_PARSE_WORKERS}"
        )
    return workers


def _read_cve_record(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    budget: _ArchiveBudget,
) -> dict:
    filename = Path(info.filename).name
    if info.file_size > MAX_CVE_RECORD_BYTES:
        raise _ArchiveLimitExceeded(
            f"CVE record {filename} exceeds {MAX_CVE_RECORD_BYTES} bytes"
        )

    with archive.open(info) as record_file:
        raw_record = record_file.read(MAX_CVE_RECORD_BYTES + 1)
    if len(raw_record) > MAX_CVE_RECORD_BYTES:
        raise _ArchiveLimitExceeded(
            f"CVE record {filename} exceeded {MAX_CVE_RECORD_BYTES} bytes"
        )
    budget.consume(len(raw_record))
    return json.loads(raw_record)


def _resolve_records(pending: list[Future[dict]]) -> Iterator[dict]:
    for future in pending:
        yield future.result()
    pending.clear()


def _iter_archive_records(
    archive: zipfile.ZipFile,
    *,
    depth: int,
    budget: _ArchiveBudget,
    executor: ThreadPoolExecutor,
    max_workers: int,
) -> Iterator[dict]:
    pending: list[Future[dict]] = []
    for info in archive.infolist():
        if info.is_dir():
            continue

        if info.filename.lower().endswith(".zip"):
            yield from _resolve_records(pending)
            if depth >= MAX_NESTED_ARCHIVE_DEPTH:
                raise _ArchiveLimitExceeded(
                    f"Archive nesting exceeded {MAX_NESTED_ARCHIVE_DEPTH} levels"
                )
            if info.file_size > MAX_NESTED_ARCHIVE_BYTES:
                raise _ArchiveLimitExceeded(
                    f"Nested archive exceeds {MAX_NESTED_ARCHIVE_BYTES} bytes"
                )

            with archive.open(info) as source, tempfile.SpooledTemporaryFile(
                max_size=SPOOL_MEMORY_BYTES
            ) as nested_file:
                copied = 0
                while chunk := source.read(ARCHIVE_CHUNK_SIZE):
                    copied += len(chunk)
                    if copied > MAX_NESTED_ARCHIVE_BYTES:
                        raise _ArchiveLimitExceeded(
                            f"Nested archive exceeded {MAX_NESTED_ARCHIVE_BYTES} bytes"
                        )
                    budget.consume(len(chunk))
                    nested_file.write(chunk)

                nested_file.seek(0)
                with zipfile.ZipFile(nested_file) as nested_archive:
                    yield from _iter_archive_records(
                        nested_archive,
                        depth=depth + 1,
                        budget=budget,
                        executor=executor,
                        max_workers=max_workers,
                    )
            continue

        filename = Path(info.filename).name
        if not info.filename.endswith(".json") or "/cves/" not in f"/{info.filename}" or not filename.startswith("CVE-"):
            continue
        pending.append(executor.submit(_read_cve_record, archive, info, budget))
        if len(pending) >= max_workers:
            yield from _resolve_records(pending)

    yield from _resolve_records(pending)


def _iter_records(archive: Path) -> Iterator[dict]:
    max_workers = _configured_parse_workers()
    with zipfile.ZipFile(archive) as zf:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            yield from _iter_archive_records(
                zf,
                depth=0,
                budget=_ArchiveBudget(),
                executor=executor,
                max_workers=max_workers,
            )


def _summarize(record: dict) -> dict:
    metadata = record.get("cveMetadata", {})
    cna = record.get("containers", {}).get("cna", {})
    english = next(
        (d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")),
        None,
    )
    return {
        "cve_id": metadata.get("cveId"),
        "state": metadata.get("state"),
        "date_updated": metadata.get("dateUpdated"),
        "title": cna.get("title"),
        "description": english,
        "raw": Jsonb(record),
    }


UPSERT_SQL = """
    INSERT INTO cve_records (cve_id, state, date_updated, title, description, raw)
    VALUES (%(cve_id)s, %(state)s, %(date_updated)s, %(title)s, %(description)s, %(raw)s)
    ON CONFLICT (cve_id) DO UPDATE SET
        state = EXCLUDED.state,
        date_updated = EXCLUDED.date_updated,
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        raw = EXCLUDED.raw,
        imported_at = now()
"""
BATCH_SIZE = 1000


def _store_batch(
    cur: psycopg.Cursor,
    records: list[dict],
    associations: list[dict],
    affected_products: list[dict],
    patch_commits: list[dict],
) -> None:
    cur.executemany(UPSERT_SQL, records)
    cve_ids = [record["cve_id"] for record in records]
    cur.execute(DELETE_CVE_WEAKNESSES_SQL, (cve_ids,))
    cur.execute(DELETE_AFFECTED_PRODUCTS_SQL, (cve_ids,))
    cur.execute(DELETE_PATCH_COMMITS_SQL, (cve_ids,))
    if associations:
        cur.executemany(INSERT_CVE_WEAKNESSES_SQL, associations)
    if affected_products:
        cur.executemany(INSERT_AFFECTED_PRODUCTS_SQL, affected_products)
    if patch_commits:
        cur.executemany(INSERT_PATCH_COMMITS_SQL, patch_commits)


@task
def process_archive(archive: Path) -> int:
    logger = get_run_logger()
    started = time.monotonic()
    count = 0
    batches = 0
    batch: list[dict] = []
    association_batch: list[dict] = []
    affected_product_batch: list[dict] = []
    patch_commit_batch: list[dict] = []
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(CREATE_CVE_WEAKNESSES_SQL)
        cur.execute(CREATE_CWE_ID_INDEX_SQL)
        ensure_affected_product_schema(cur)
        cur.execute(CREATE_PATCH_COMMITS_SQL)
        cur.execute(CREATE_PATCH_COMMITS_SHA_INDEX_SQL)
        conn.commit()
        logger.info("Upserting records from %s into cve_records", archive.name)
        for record in _iter_records(archive):
            summary = _summarize(record)
            batch.append(summary)
            if summary["cve_id"]:
                association_batch.extend(extract_cwe_associations(summary["cve_id"], record))
                affected_product_batch.extend(
                    extract_affected_product_rows(summary["cve_id"], record)
                )
                patch_commit_batch.extend(extract_patch_commits(summary["cve_id"], record))
            if len(batch) == BATCH_SIZE:
                _store_batch(cur, batch, association_batch, affected_product_batch, patch_commit_batch)
                # Commit per batch so progress is durable and visible, not held in one long transaction.
                conn.commit()
                count += len(batch)
                batches += 1
                batch.clear()
                association_batch.clear()
                affected_product_batch.clear()
                patch_commit_batch.clear()
                if batches % 50 == 0:
                    logger.info("Upserted %d records (%.0f rec/s)", count, count / (time.monotonic() - started))
        if batch:
            _store_batch(cur, batch, association_batch, affected_product_batch, patch_commit_batch)
            conn.commit()
            count += len(batch)
    logger.info("Finished: upserted %d records in %.1fs", count, time.monotonic() - started)
    return count
