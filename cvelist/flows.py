from prefect import flow

from cvelist.enrich import fetch_epss, fetch_kev, store_enrichment
from cvelist.tasks import download_release_asset, process_archive


@flow(name="import-cvelistv5-flow")
def import_cvelistv5_flow(mode: str = "delta") -> int:
    archive = download_release_asset(mode)
    return process_archive(archive)


@flow(name="enrich-kev-epss-flow")
def enrich_kev_epss_flow() -> int:
    kev = fetch_kev()
    epss = fetch_epss()
    return store_enrichment(kev, epss)


if __name__ == "__main__":
    print(import_cvelistv5_flow())
