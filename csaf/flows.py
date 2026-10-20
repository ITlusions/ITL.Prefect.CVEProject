import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import psycopg
from prefect import flow, task
from prefect.artifacts import create_progress_artifact, update_progress_artifact
from prefect.logging import get_run_logger
from psycopg.types.json import Jsonb

from csaf.csaf_import import (
    CHANGES_URL,
    CSAF_BASE_URL,
    INDEX_URL,
    MAX_DOCUMENT_BYTES,
    MAX_KEY_BYTES,
    MAX_LIST_BYTES,
    MAX_SIGNATURE_BYTES,
    PROVIDER_METADATA_URL,
    Change,
    import_keys,
    parse_changes,
    parse_document,
    select_changes,
    verify_sha512,
    verify_signature,
)
from feed_download import download_bytes

CREATE_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS ncsc_csaf_documents (
        path TEXT PRIMARY KEY,
        tracking_id TEXT NOT NULL,
        title TEXT,
        initial_release_date TIMESTAMPTZ,
        current_release_date TIMESTAMPTZ,
        changed_at TIMESTAMPTZ NOT NULL,
        sha512 TEXT NOT NULL,
        document JSONB NOT NULL,
        imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ncsc_csaf_cves (
        path TEXT NOT NULL REFERENCES ncsc_csaf_documents(path) ON DELETE CASCADE,
        cve_id TEXT NOT NULL,
        PRIMARY KEY (path, cve_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ncsc_csaf_cves_cve_id ON ncsc_csaf_cves (cve_id)",
]

UPSERT_DOCUMENT_SQL = """
    INSERT INTO ncsc_csaf_documents (
        path, tracking_id, title, initial_release_date, current_release_date,
        changed_at, sha512, document
    )
    VALUES (
        %(path)s, %(tracking_id)s, %(title)s, %(initial_release_date)s, %(current_release_date)s,
        %(changed_at)s, %(sha512)s, %(document)s
    )
    ON CONFLICT (path) DO UPDATE SET
        tracking_id = EXCLUDED.tracking_id,
        title = EXCLUDED.title,
        initial_release_date = EXCLUDED.initial_release_date,
        current_release_date = EXCLUDED.current_release_date,
        changed_at = EXCLUDED.changed_at,
        sha512 = EXCLUDED.sha512,
        document = EXCLUDED.document,
        imported_at = now()
"""


def _connect() -> psycopg.Connection:
    return psycopg.connect(os.environ["CVE_DATABASE_URL"])


def ensure_schema() -> None:
    with _connect() as conn, conn.cursor() as cur:
        for statement in CREATE_SCHEMA_SQL:
            cur.execute(statement)


def get_stored_changes() -> dict[str, datetime]:
    """Path -> changed_at of every document already imported."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT path, changed_at FROM ncsc_csaf_documents")
        return {path: changed_at for path, changed_at in cur.fetchall()}


def store_document(change: Change, raw: bytes, document: dict) -> None:
    fields = parse_document(document)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(UPSERT_DOCUMENT_SQL, {
            "path": change.path,
            "tracking_id": fields["tracking_id"],
            "title": fields["title"],
            "initial_release_date": fields["initial_release_date"],
            "current_release_date": fields["current_release_date"],
            "changed_at": change.changed_at,
            "sha512": hashlib.sha512(raw).hexdigest(),
            "document": Jsonb(document),
        })
        # Replace the CVE links so a revised version that drops a CVE does not keep the old link.
        cur.execute("DELETE FROM ncsc_csaf_cves WHERE path = %s", (change.path,))
        cur.executemany(
            "INSERT INTO ncsc_csaf_cves (path, cve_id) VALUES (%s, %s)",
            [(change.path, cve_id) for cve_id in fields["cve_ids"]],
        )
        conn.commit()


@task(retries=3, retry_delay_seconds=30)
def fetch_bytes(url: str, max_bytes: int) -> bytes:
    return download_bytes(url, max_bytes=max_bytes, timeout=60)


def _fetch_text(url: str) -> str:
    return download_bytes(url, max_bytes=MAX_LIST_BYTES, timeout=60).decode("utf-8")


@flow(name="import-ncsc-csaf-flow")
def import_ncsc_csaf_flow() -> int:
    logger = get_run_logger()

    metadata = json.loads(fetch_bytes(PROVIDER_METADATA_URL, MAX_LIST_BYTES))
    keys = metadata["public_openpgp_keys"]
    expected = {key["fingerprint"].upper() for key in keys}
    key_blobs = [fetch_bytes(key["url"], MAX_KEY_BYTES) for key in keys]

    homedir = Path(tempfile.mkdtemp(prefix="csaf-keyring-"))
    try:
        os.chmod(homedir, 0o700)
        import_keys(homedir, key_blobs, expected)

        ensure_schema()
        stored = get_stored_changes()
        changes = parse_changes(_fetch_text(CHANGES_URL))
        if not stored:
            # First run: cross-check the full index against the change list.
            index_paths = {line.strip() for line in _fetch_text(INDEX_URL).splitlines() if line.strip()}
            missing = index_paths - {c.path for c in changes}
            if missing:
                logger.warning("%d documents in index.txt are missing from changes.csv", len(missing))

        pending = select_changes(changes, stored)
        logger.info(
            "%s run: %d documents listed, %d to import",
            "Full" if not stored else "Delta", len(changes), len(pending),
        )

        imported = 0
        rejected: list[str] = []
        total = len(pending)
        progress_id = create_progress_artifact(
            progress=0.0, key="csaf-import", description=f"0 / {total} documents",
        )
        for done, change in enumerate(pending, start=1):
            url = CSAF_BASE_URL + change.path
            logger.info("Processing %d/%d: %s (changed %s)", done, total, change.path, change.changed_at.date())
            raw = fetch_bytes(url, MAX_DOCUMENT_BYTES)
            logger.info("Downloaded %s: %.2f MB", change.path, len(raw) / 1e6)
            sha512_file = fetch_bytes(url + ".sha512", 4096).decode("utf-8")
            signature = fetch_bytes(url + ".asc", MAX_SIGNATURE_BYTES)
            if not verify_sha512(raw, sha512_file) or not verify_signature(homedir, signature, raw, expected):
                rejected.append(change.path)
                logger.error("Rejected %s: hash or signature check failed", change.path)
            else:
                store_document(change, raw, json.loads(raw))
                imported += 1
                logger.info("Stored %s", change.path)

            percent = 100.0 * done / total
            description = (
                f"{done} / {total} documents ({percent:.1f}%): "
                f"{imported} stored, {len(rejected)} rejected"
            )
            update_progress_artifact(progress_id, progress=percent, description=description)
            if done % 50 == 0 or done == total:
                logger.info("Progress: %s", description)

        if rejected:
            # Good documents are already stored. Rejected ones stay out of the database, so the next run retries them.
            raise RuntimeError(f"{len(rejected)} documents failed verification: {rejected[:10]}")
        return imported
    finally:
        shutil.rmtree(homedir, ignore_errors=True)
