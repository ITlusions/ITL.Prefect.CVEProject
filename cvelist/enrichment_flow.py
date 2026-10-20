from prefect import flow

from cvelist.enrich import fetch_epss, fetch_kev, store_enrichment


@flow(name="enrich-kev-epss-flow")
def enrich_kev_epss_flow() -> int:
    kev = fetch_kev()
    epss = fetch_epss()
    return store_enrichment(kev, epss)