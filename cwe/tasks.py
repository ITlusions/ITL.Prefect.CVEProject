import io
import os
import zipfile
from datetime import date
from xml.etree import ElementTree

import psycopg
from prefect import task
from prefect.logging import get_run_logger

from feed_download import download_bytes
from cwe.weaknesses import (
    CREATE_CVE_WEAKNESSES_SQL,
    CREATE_CWE_ID_INDEX_SQL,
    DELETE_CVE_WEAKNESSES_SQL,
    INSERT_CVE_WEAKNESSES_SQL,
    extract_cwe_associations,
)

CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
BATCH_SIZE = 1000
MAX_CWE_CATALOG_BYTES = 16 * 1024 * 1024

CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS cwe_catalog (
        cwe_id text PRIMARY KEY,
        name text NOT NULL,
        description text,
        extended_description text,
        abstraction text,
        structure text,
        status text,
        catalog_version text NOT NULL,
        catalog_date date NOT NULL,
        imported_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS cwe_relationships (
        source_cwe_id text NOT NULL REFERENCES cwe_catalog(cwe_id) ON DELETE CASCADE,
        related_cwe_id text NOT NULL,
        nature text NOT NULL,
        PRIMARY KEY (source_cwe_id, related_cwe_id, nature)
    )
"""

UPSERT_CWE_SQL = """
    INSERT INTO cwe_catalog (
        cwe_id, name, description, extended_description, abstraction,
        structure, status, catalog_version, catalog_date
    )
    VALUES (
        %(cwe_id)s, %(name)s, %(description)s, %(extended_description)s,
        %(abstraction)s, %(structure)s, %(status)s, %(catalog_version)s,
        %(catalog_date)s
    )
    ON CONFLICT (cwe_id) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        extended_description = EXCLUDED.extended_description,
        abstraction = EXCLUDED.abstraction,
        structure = EXCLUDED.structure,
        status = EXCLUDED.status,
        catalog_version = EXCLUDED.catalog_version,
        catalog_date = EXCLUDED.catalog_date,
        imported_at = now()
"""

INSERT_RELATIONSHIP_SQL = """
    INSERT INTO cwe_relationships (source_cwe_id, related_cwe_id, nature)
    VALUES (%(source_cwe_id)s, %(related_cwe_id)s, %(nature)s)
    ON CONFLICT DO NOTHING
"""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ElementTree.Element, name: str) -> str | None:
    child = next((item for item in element if _local_name(item.tag) == name), None)
    if child is None:
        return None
    value = "".join(child.itertext()).strip()
    return value or None


def _parse_catalog(xml_data: bytes) -> tuple[str, date, list[dict], list[dict]]:
    root = ElementTree.fromstring(xml_data)
    if _local_name(root.tag) != "Weakness_Catalog":
        raise ValueError(f"Unexpected CWE catalog root element: {root.tag}")

    catalog_version = root.attrib["Version"]
    catalog_date = date.fromisoformat(root.attrib["Date"])
    weaknesses_element = next(
        (item for item in root if _local_name(item.tag) == "Weaknesses"),
        None,
    )
    if weaknesses_element is None:
        raise ValueError("CWE catalog does not contain a Weaknesses element")

    weaknesses = []
    relationships = []
    for weakness in weaknesses_element:
        if _local_name(weakness.tag) != "Weakness":
            continue
        cwe_id = f"CWE-{weakness.attrib['ID']}"
        weaknesses.append({
            "cwe_id": cwe_id,
            "name": weakness.attrib["Name"],
            "description": _child_text(weakness, "Description"),
            "extended_description": _child_text(weakness, "Extended_Description"),
            "abstraction": weakness.attrib.get("Abstraction"),
            "structure": weakness.attrib.get("Structure"),
            "status": weakness.attrib.get("Status"),
            "catalog_version": catalog_version,
            "catalog_date": catalog_date,
        })
        for related in weakness.iter():
            if _local_name(related.tag) != "Related_Weakness":
                continue
            target_id = related.attrib.get("CWE_ID")
            nature = related.attrib.get("Nature")
            if target_id and nature:
                relationships.append({
                    "source_cwe_id": cwe_id,
                    "related_cwe_id": f"CWE-{target_id}",
                    "nature": nature,
                })

    if not weaknesses:
        raise ValueError("CWE catalog contains no weaknesses")
    return catalog_version, catalog_date, weaknesses, relationships


@task(retries=3, retry_delay_seconds=30)
def fetch_cwe_catalog() -> tuple[str, date, list[dict], list[dict]]:
    logger = get_run_logger()
    payload = download_bytes(CWE_CATALOG_URL, max_bytes=MAX_CWE_CATALOG_BYTES, timeout=120)

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        xml_name = next(
            (name for name in archive.namelist() if name.lower().endswith(".xml")),
            None,
        )
        if xml_name is None:
            raise ValueError("CWE catalog archive does not contain an XML file")
        catalog = _parse_catalog(archive.read(xml_name))

    logger.info(
        "Fetched CWE catalog version %s: %d weaknesses and %d relationships",
        catalog[0], len(catalog[2]), len(catalog[3]),
    )
    return catalog


@task
def store_cwe_catalog(catalog: tuple[str, date, list[dict], list[dict]]) -> int:
    _, _, weaknesses, relationships = catalog
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(CREATE_SQL)
        cur.executemany(UPSERT_CWE_SQL, weaknesses)
        cur.execute("DELETE FROM cwe_relationships")
        if relationships:
            cur.executemany(INSERT_RELATIONSHIP_SQL, relationships)

    get_run_logger().info(
        "Upserted %d CWE weaknesses and %d relationships",
        len(weaknesses), len(relationships),
    )
    return len(weaknesses)


@task(retries=2, retry_delay_seconds=30)
def backfill_cve_weaknesses() -> int:
    logger = get_run_logger()
    total = 0
    last_cve_id = ""
    with psycopg.connect(os.environ["CVE_DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(CREATE_CVE_WEAKNESSES_SQL)
            cur.execute(CREATE_CWE_ID_INDEX_SQL)
        conn.commit()

        while True:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT cve_id, raw FROM cve_records "
                    "WHERE cve_id > %s ORDER BY cve_id LIMIT %s",
                    (last_cve_id, BATCH_SIZE),
                )
                records = cur.fetchall()
                if not records:
                    break

                cve_ids = [cve_id for cve_id, _ in records]
                associations = [
                    association
                    for cve_id, raw in records
                    for association in extract_cwe_associations(cve_id, raw)
                ]
                cur.execute(DELETE_CVE_WEAKNESSES_SQL, (cve_ids,))
                if associations:
                    cur.executemany(INSERT_CVE_WEAKNESSES_SQL, associations)

            conn.commit()
            last_cve_id = cve_ids[-1]
            total += len(associations)
            if total and total % 10000 < len(associations):
                logger.info("Backfilled %d CVE-CWE associations", total)

    logger.info("Backfilled %d CVE-CWE associations", total)
    return total