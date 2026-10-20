from prefect import flow

from cwe.tasks import backfill_cve_weaknesses, fetch_cwe_catalog, store_cwe_catalog


@flow(name="import-cwe-catalog-flow")
def import_cwe_catalog_flow(backfill_existing_cves: bool = False) -> dict[str, int]:
    catalog = fetch_cwe_catalog()
    imported_cwes = store_cwe_catalog(catalog)
    result = {"catalog_weaknesses": imported_cwes}
    if backfill_existing_cves:
        result["cve_weakness_associations"] = backfill_cve_weaknesses()
    return result