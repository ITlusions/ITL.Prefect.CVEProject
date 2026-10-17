import csv
import gzip
import io
import os
import time
from datetime import date

import psycopg
import requests
from prefect import task
from prefect.logging import get_run_logger

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
BATCH_SIZE = 1000

CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS cve_enrichment (
        cve_id text PRIMARY KEY,
        kev boolean NOT NULL DEFAULT false,
        kev_date_added date,
        kev_due_date date,
        kev_ransomware text,
        epss_score double precision,
        epss_percentile double precision,
        enriched_at timestamptz NOT NULL DEFAULT now()
    )
"""

UPSERT_SQL = """
    INSERT INTO cve_enrichment (
        cve_id, kev, kev_date_added, kev_due_date, kev_ransomware,
        epss_score, epss_percentile
    )
    VALUES (
        %(cve_id)s, %(kev)s, %(kev_date_added)s, %(kev_due_date)s, %(kev_ransomware)s,
        %(epss_score)s, %(epss_percentile)s
    )
    ON CONFLICT (cve_id) DO UPDATE SET
        kev = EXCLUDED.kev,
        kev_date_added = EXCLUDED.kev_date_added,
        kev_due_date = EXCLUDED.kev_due_date,
        kev_ransomware = EXCLUDED.kev_ransomware,
        epss_score = EXCLUDED.epss_score,
        epss_percentile = EXCLUDED.epss_percentile,
        enriched_at = now()
"""


@task(retries=3, retry_delay_seconds=30)
def fetch_kev() -> dict[str, dict]:
    logger = get_run_logger()
    response = requests.get(KEV_URL, timeout=120)
    response.raise_for_status()
    vulnerabilities = response.json()["vulnerabilities"]
    logger.info("Fetched %d KEV entries", len(vulnerabilities))
    return {
        v["cveID"]: {
            "kev_date_added": date.fromisoformat(v["dateAdded"]),
            "kev_due_date": date.fromisoformat(v["dueDate"]) if v.get("dueDate") else None,
            "kev_ransomware": v.get("knownRansomwareCampaignUse"),
        }
        for v in vulnerabilities
    }


@task(retries=3, retry_delay_seconds=30)
def fetch_epss() -> dict[str, dict]:
    logger = get_run_logger()
    response = requests.get(EPSS_URL, timeout=300)
    response.raise_for_status()
    text = gzip.decompress(response.content).decode("utf-8")
    reader = csv.DictReader(line for line in io.StringIO(text) if not line.startswith("#"))
    scores = {
        row["cve"]: {
            "epss_score": float(row["epss"]),
            "epss_percentile": float(row["percentile"]),
        }
        for row in reader
    }
    logger.info("Fetched %d EPSS scores", len(scores))
    return scores


@task
def store_enrichment(kev: dict[str, dict], epss: dict[str, dict]) -> int:
    logger = get_run_logger()
    started = time.monotonic()
    rows = [
        {
            "cve_id": cve_id,
            "kev": cve_id in kev,
            "kev_date_added": kev.get(cve_id, {}).get("kev_date_added"),
            "kev_due_date": kev.get(cve_id, {}).get("kev_due_date"),
            "kev_ransomware": kev.get(cve_id, {}).get("kev_ransomware"),
            "epss_score": epss.get(cve_id, {}).get("epss_score"),
            "epss_percentile": epss.get(cve_id, {}).get("epss_percentile"),
        }
        for cve_id in kev.keys() | epss.keys()
    ]
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(CREATE_SQL)
        for start in range(0, len(rows), BATCH_SIZE):
            cur.executemany(UPSERT_SQL, rows[start:start + BATCH_SIZE])
    logger.info("Upserted %d enrichment rows in %.1fs", len(rows), time.monotonic() - started)
    return len(rows)
