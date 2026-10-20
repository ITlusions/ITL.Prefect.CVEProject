from typing import Any

import psycopg

MIGRATION_ID = "affected_products_v1"

CREATE_AFFECTED_PRODUCTS_SQL = """
    CREATE TABLE IF NOT EXISTS cve_affected_products (
        cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
        product_index integer NOT NULL,
        version_index integer NOT NULL,
        vendor text NOT NULL DEFAULT '',
        product text NOT NULL DEFAULT '',
        platforms text[] NOT NULL DEFAULT '{}',
        version text,
        less_than text,
        less_than_or_equal text,
        version_status text,
        version_type text,
        PRIMARY KEY (cve_id, product_index, version_index)
    )
"""

CREATE_MIGRATIONS_SQL = """
    CREATE TABLE IF NOT EXISTS cve_data_migrations (
        migration_id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
    )
"""

BACKFILL_AFFECTED_PRODUCTS_SQL = """
    INSERT INTO cve_affected_products (
        cve_id, product_index, version_index, vendor, product, platforms,
        version, less_than, less_than_or_equal, version_status, version_type
    )
    SELECT
        record.cve_id,
        affected.product_index::integer,
        version.version_index::integer,
        COALESCE(affected.value->>'vendor', ''),
        COALESCE(affected.value->>'product', ''),
        ARRAY(
            SELECT jsonb_array_elements_text(
                CASE
                    WHEN jsonb_typeof(affected.value->'platforms') = 'array'
                    THEN affected.value->'platforms'
                    ELSE '[]'::jsonb
                END
            )
        ),
        version.value->>'version',
        version.value->>'lessThan',
        version.value->>'lessThanOrEqual',
        version.value->>'status',
        version.value->>'versionType'
    FROM cve_records AS record
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(record.raw #> '{containers,cna,affected}') = 'array'
            THEN record.raw #> '{containers,cna,affected}'
            ELSE '[]'::jsonb
        END
    ) WITH ORDINALITY AS affected(value, product_index)
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(affected.value->'versions') = 'array'
                AND jsonb_array_length(affected.value->'versions') > 0
            THEN affected.value->'versions'
            ELSE '[{}]'::jsonb
        END
    ) WITH ORDINALITY AS version(value, version_index)
    ON CONFLICT DO NOTHING
"""

CREATE_AFFECTED_PRODUCT_INDEXES_SQL = (
    "CREATE INDEX IF NOT EXISTS ix_cve_affected_vendor_product "
    "ON cve_affected_products (lower(vendor), lower(product))",
    "CREATE INDEX IF NOT EXISTS ix_cve_affected_product "
    "ON cve_affected_products (lower(product))",
    "CREATE INDEX IF NOT EXISTS ix_cve_affected_platforms "
    "ON cve_affected_products USING GIN (platforms)",
    "CREATE INDEX IF NOT EXISTS ix_cve_affected_status "
    "ON cve_affected_products (version_status)",
)

CREATE_CVSS_INDEX_SQL = """
    CREATE INDEX IF NOT EXISTS ix_cve_records_cvss_score
    ON cve_records (((jsonb_path_query_first(
        raw, '$.containers.cna.metrics[*].cvssV3_1.baseScore'
    ) #>> '{}')::float8))
"""

DELETE_AFFECTED_PRODUCTS_SQL = "DELETE FROM cve_affected_products WHERE cve_id = ANY(%s)"

INSERT_AFFECTED_PRODUCTS_SQL = """
    INSERT INTO cve_affected_products (
        cve_id, product_index, version_index, vendor, product, platforms,
        version, less_than, less_than_or_equal, version_status, version_type
    )
    VALUES (
        %(cve_id)s, %(product_index)s, %(version_index)s, %(vendor)s, %(product)s,
        %(platforms)s, %(version)s, %(less_than)s, %(less_than_or_equal)s,
        %(version_status)s, %(version_type)s
    )
    ON CONFLICT DO NOTHING
"""

INSERT_MIGRATION_SQL = "INSERT INTO cve_data_migrations (migration_id) VALUES (%s)"


def extract_affected_product_rows(cve_id: str, record: dict[str, Any]) -> list[dict[str, Any]]:
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    affected = cna.get("affected") if isinstance(cna, dict) else None
    if not isinstance(affected, list):
        return []

    rows = []
    for product_index, product in enumerate(affected, start=1):
        if not isinstance(product, dict):
            continue
        platforms = product.get("platforms")
        versions = product.get("versions")
        if not isinstance(versions, list) or not versions:
            versions = [{}]
        for version_index, version in enumerate(versions, start=1):
            if not isinstance(version, dict):
                version = {}
            rows.append(
                {
                    "cve_id": cve_id,
                    "product_index": product_index,
                    "version_index": version_index,
                    "vendor": product.get("vendor") if isinstance(product.get("vendor"), str) else "",
                    "product": product.get("product") if isinstance(product.get("product"), str) else "",
                    "platforms": [value for value in platforms if isinstance(value, str)]
                    if isinstance(platforms, list) else [],
                    "version": version.get("version") if isinstance(version.get("version"), str) else None,
                    "less_than": version.get("lessThan") if isinstance(version.get("lessThan"), str) else None,
                    "less_than_or_equal": version.get("lessThanOrEqual")
                    if isinstance(version.get("lessThanOrEqual"), str) else None,
                    "version_status": version.get("status") if isinstance(version.get("status"), str) else None,
                    "version_type": version.get("versionType")
                    if isinstance(version.get("versionType"), str) else None,
                }
            )
    return rows


def ensure_affected_product_schema(cur: psycopg.Cursor) -> None:
    cur.execute(CREATE_AFFECTED_PRODUCTS_SQL)
    cur.execute(CREATE_MIGRATIONS_SQL)
    cur.execute(CREATE_CVSS_INDEX_SQL)
    cur.execute("SELECT 1 FROM cve_data_migrations WHERE migration_id = %s", (MIGRATION_ID,))
    if cur.fetchone() is None:
        cur.execute(BACKFILL_AFFECTED_PRODUCTS_SQL)
        cur.execute(INSERT_MIGRATION_SQL, (MIGRATION_ID,))
    for statement in CREATE_AFFECTED_PRODUCT_INDEXES_SQL:
        cur.execute(statement)