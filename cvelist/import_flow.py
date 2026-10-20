from prefect import flow
from prefect.logging import get_run_logger

from cvelist.checkpoint import (
    delta_asset,
    download_delta_asset,
    fetch_latest_release,
    get_checkpoint,
    releases_after,
    set_checkpoint,
)
from cvelist.tasks import download_release_asset, process_archive


@flow(name="import-cvelistv5-flow")
def import_cvelistv5_flow(mode: str = "delta") -> int:
    logger = get_run_logger()
    if mode == "baseline":
        # Read the tag before downloading. If a newer release lands in between, the stored
        # tag is older than the data, and the next delta run replays a release that is
        # already imported. That replay is harmless, because the upserts are idempotent.
        latest = fetch_latest_release()
        archive = download_release_asset(mode)
        try:
            count = process_archive(archive)
        finally:
            archive.unlink(missing_ok=True)
        set_checkpoint(latest["tag_name"], "baseline")
        return count

    checkpoint = get_checkpoint()
    if checkpoint is None:
        logger.warning("No checkpoint recorded; importing only the latest delta. Run baseline mode first to establish full state.")
    count = 0
    for release in releases_after(checkpoint):
        asset = delta_asset(release)
        logger.info("Replaying release %s (%s)", release["tag_name"], asset["name"])
        archive = download_delta_asset(asset)
        try:
            count += process_archive(archive)
        finally:
            archive.unlink(missing_ok=True)
        # Recorded only after the archive is committed, so a failed run resumes here.
        set_checkpoint(release["tag_name"], asset["name"])
    return count
