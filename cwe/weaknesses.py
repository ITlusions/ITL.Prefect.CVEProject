CREATE_CVE_WEAKNESSES_SQL = """
    CREATE TABLE IF NOT EXISTS cve_weaknesses (
        cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
        cwe_id text NOT NULL,
        source text NOT NULL,
        description text NOT NULL DEFAULT '',
        PRIMARY KEY (cve_id, cwe_id, source, description)
    )
"""

CREATE_CWE_ID_INDEX_SQL = """
    CREATE INDEX IF NOT EXISTS ix_cve_weaknesses_cwe_id
    ON cve_weaknesses (cwe_id)
"""

DELETE_CVE_WEAKNESSES_SQL = "DELETE FROM cve_weaknesses WHERE cve_id = ANY(%s)"

INSERT_CVE_WEAKNESSES_SQL = """
    INSERT INTO cve_weaknesses (cve_id, cwe_id, source, description)
    VALUES (%(cve_id)s, %(cwe_id)s, %(source)s, %(description)s)
    ON CONFLICT DO NOTHING
"""


def extract_cwe_associations(cve_id: str, record: dict) -> list[dict[str, str]]:
    containers = record.get("containers", {})
    sources = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        sources.append(("cna", cna))
    adp = containers.get("adp", [])
    if isinstance(adp, list):
        sources.extend(("adp", container) for container in adp if isinstance(container, dict))

    associations = []
    seen = set()
    for container_type, container in sources:
        provider = container.get("providerMetadata", {})
        source_id = provider.get("shortName") or provider.get("orgId")
        source = f"{container_type}:{source_id}" if source_id else container_type
        for problem_type in container.get("problemTypes", []) or []:
            for description in problem_type.get("descriptions", []) or []:
                cwe_id = description.get("cweId")
                if not isinstance(cwe_id, str) or not cwe_id.strip():
                    continue
                cwe_id = cwe_id.strip().upper()
                text = description.get("description")
                text = text.strip() if isinstance(text, str) else ""
                association = {
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "source": source,
                    "description": text,
                }
                key = (cve_id, cwe_id, source, text)
                if key not in seen:
                    associations.append(association)
                    seen.add(key)
    return associations