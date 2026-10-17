from prefect import flow

from cvelist.tasks import download_release_asset, process_archive


@flow(name="import-cvelistv5-flow")
def import_cvelistv5_flow(mode: str = "delta") -> int:
    archive = download_release_asset(mode)
    return process_archive(archive)


if __name__ == "__main__":
    print(import_cvelistv5_flow())
