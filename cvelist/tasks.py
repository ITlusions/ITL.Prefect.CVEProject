import json
import os
import re
import tempfile
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import psycopg
import requests
from prefect import task
from prefect.logging import get_run_logger
from psycopg.types.json import Jsonb

RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_PATTERNS = {
    "baseline": re.compile(r"_all_CVEs_at_midnight\.zip(\.zip)?$"),
    "delta": re.compile(r"_delta_CVEs_at_\d{4}Z\.zip$"),
}


@task(retries=3, retry_delay_seconds=30)
def download_release_asset(mode: str) -> Path:
    logger = get_run_logger()
    release = requests.get(RELEASES_URL, timeout=60, headers={"Accept": "application/vnd.github+json"})
    release.raise_for_status()
    payload = release.json()
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

    target = Path(tempfile.gettempdir()) / re.sub(r"\.zip\.zip$", ".zip", asset["name"])
    started = time.monotonic()
    downloaded = 0
    next_report = 100 * 1_000_000
    with requests.get(asset["browser_download_url"], stream=True, timeout=300) as response:
        response.raise_for_status()
        with target.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1 << 20):
                handle.write(chunk)
                downloaded += len(chunk)
                if downloaded >= next_report:
                    logger.info("Downloaded %.0f / %.0f MB", downloaded / 1e6, asset["size"] / 1e6)
                    next_report += 100 * 1_000_000
    logger.info("Download complete to %s in %.1fs", target, time.monotonic() - started)
    return target


def _iter_records(archive: Path) -> Iterator[dict]:
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            if name.endswith(".zip"):
                with tempfile.TemporaryDirectory() as tmp:
                    yield from _iter_records(Path(zf.extract(name, tmp)))
            elif name.endswith(".json") and "/cves/" in f"/{name}" and Path(name).name.startswith("CVE-"):
                yield json.loads(zf.read(name))


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


@task
def process_archive(archive: Path) -> int:
    logger = get_run_logger()
    started = time.monotonic()
    count = 0
    batches = 0
    batch: list[dict] = []
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        logger.info("Upserting records from %s into cve_records", archive.name)
        for record in _iter_records(archive):
            batch.append(_summarize(record))
            if len(batch) == BATCH_SIZE:
                cur.executemany(UPSERT_SQL, batch)
                count += len(batch)
                batches += 1
                batch.clear()
                if batches % 50 == 0:
                    logger.info("Upserted %d records (%.0f rec/s)", count, count / (time.monotonic() - started))
        if batch:
            cur.executemany(UPSERT_SQL, batch)
            count += len(batch)
    logger.info("Finished: upserted %d records in %.1fs", count, time.monotonic() - started)
    return count
