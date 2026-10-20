import json
import os
from collections.abc import Callable
from pathlib import Path

import psycopg
from prefect import task
from prefect.logging import get_run_logger

from feed_download import download_bytes, download_to_tempfile
from cvelist.tasks import (
    ASSET_PATTERNS,
    MAX_ASSET_BYTES,
    MAX_RELEASE_METADATA_BYTES,
    RELEASES_URL,
)

FEED = "cvelistv5"
RELEASES_PAGE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100&page={page}"
MAX_RELEASE_PAGES = 50
GITHUB_HEADERS = {"Accept": "application/vnd.github+json"}

CREATE_CHECKPOINT_SQL = """
    CREATE TABLE IF NOT EXISTS cve_import_checkpoint (
        feed TEXT PRIMARY KEY,
        release_tag TEXT NOT NULL,
        asset_name TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
"""
GET_CHECKPOINT_SQL = "SELECT release_tag FROM cve_import_checkpoint WHERE feed = %s"
SET_CHECKPOINT_SQL = """
    INSERT INTO cve_import_checkpoint (feed, release_tag, asset_name)
    VALUES (%(feed)s, %(release_tag)s, %(asset_name)s)
    ON CONFLICT (feed) DO UPDATE SET
        release_tag = EXCLUDED.release_tag,
        asset_name = EXCLUDED.asset_name,
        updated_at = now()
"""


def get_checkpoint() -> str | None:
    """Return the last release tag imported for this feed, or None if none is recorded."""
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(CREATE_CHECKPOINT_SQL)
        cur.execute(GET_CHECKPOINT_SQL, (FEED,))
        row = cur.fetchone()
    return row[0] if row else None


def set_checkpoint(release_tag: str, asset_name: str) -> None:
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(CREATE_CHECKPOINT_SQL)
        cur.execute(
            SET_CHECKPOINT_SQL,
            {"feed": FEED, "release_tag": release_tag, "asset_name": asset_name},
        )


def fetch_release_page(page: int) -> list[dict]:
    """Return one page of releases, newest first, as GitHub lists them."""
    return json.loads(download_bytes(
        RELEASES_PAGE_URL.format(page=page),
        max_bytes=MAX_RELEASE_METADATA_BYTES,
        timeout=60,
        headers=GITHUB_HEADERS,
    ))


def releases_after(
    checkpoint: str | None,
    fetch_page: Callable[[int], list[dict]] = fetch_release_page,
) -> list[dict]:
    """Releases published after the checkpoint, oldest first.

    Without a checkpoint only the latest release is returned. A delta holds only the
    changes since the previous release, so the chain has to be replayed in order from
    the checkpoint. If the checkpoint is not found in the release history, the chain
    is broken and a baseline import is needed.
    """
    if checkpoint is None:
        return fetch_page(1)[:1]

    newer: list[dict] = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        releases = fetch_page(page)
        if not releases:
            break
        for release in releases:
            if release["tag_name"] == checkpoint:
                return list(reversed(newer))
            newer.append(release)
    raise RuntimeError(
        f"Checkpoint {checkpoint} not found in the last {len(newer)} releases; "
        "run the flow in baseline mode to resync"
    )


def delta_asset(release: dict) -> dict:
    asset = next(
        (a for a in release.get("assets", []) if ASSET_PATTERNS["delta"].search(a["name"])),
        None,
    )
    if asset is None:
        names = [a["name"] for a in release.get("assets", [])]
        raise RuntimeError(f"No delta asset in release {release.get('tag_name')}: {names}")
    return asset


@task(retries=3, retry_delay_seconds=30)
def fetch_latest_release() -> dict:
    return json.loads(download_bytes(
        RELEASES_URL,
        max_bytes=MAX_RELEASE_METADATA_BYTES,
        timeout=60,
        headers=GITHUB_HEADERS,
    ))


@task(retries=3, retry_delay_seconds=30)
def download_delta_asset(asset: dict) -> Path:
    logger = get_run_logger()
    logger.info("Downloading delta %s (%.1f MB)", asset["name"], asset["size"] / 1e6)
    return download_to_tempfile(
        asset["browser_download_url"],
        max_bytes=MAX_ASSET_BYTES["delta"],
        timeout=300,
        suffix=".zip",
    )
