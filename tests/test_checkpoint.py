import unittest

from cvelist.checkpoint import delta_asset, releases_after
from cvelist.tasks import ASSET_PATTERNS


def release(tag: str, assets: list[str]) -> dict:
    return {
        "tag_name": tag,
        "assets": [{"name": name, "size": 1, "browser_download_url": f"https://example/{name}"} for name in assets],
    }


# Newest first, the same order the GitHub releases API returns.
PAGES = [
    [
        release("cve_2026-10-20_0000Z", ["2026-10-20_delta_CVEs_at_0000Z.zip"]),
        release("cve_2026-10-19_at_end_of_day", ["2026-10-19_delta_CVEs_at_end_of_day.zip"]),
        release("cve_2026-10-19_2300Z", ["2026-10-19_delta_CVEs_at_2300Z.zip"]),
    ],
    [
        release("cve_2026-10-19_2200Z", ["2026-10-19_delta_CVEs_at_2200Z.zip"]),
        release("cve_2026-10-19_2100Z", ["2026-10-19_delta_CVEs_at_2100Z.zip"]),
    ],
]


def fake_fetch(page: int) -> list[dict]:
    return PAGES[page - 1] if page <= len(PAGES) else []


class DeltaAssetPatternTests(unittest.TestCase):
    def test_matches_hourly_and_end_of_day_deltas(self):
        for name in [
            "2026-10-20_delta_CVEs_at_0000Z.zip",
            "2026-10-19_delta_CVEs_at_end_of_day.zip",
        ]:
            self.assertIsNotNone(ASSET_PATTERNS["delta"].search(name), name)

    def test_rejects_baseline_checksums_and_notes(self):
        for name in [
            "2026-10-19_all_CVEs_at_midnight.zip.zip",
            "2026-10-19_delta_CVEs_at_end_of_day.zip.sha256",
            "release_notes.md",
        ]:
            self.assertIsNone(ASSET_PATTERNS["delta"].search(name), name)


class DeltaAssetTests(unittest.TestCase):
    def test_picks_end_of_day_delta(self):
        rel = release("cve_2026-10-19_at_end_of_day", ["2026-10-19_delta_CVEs_at_end_of_day.zip", "release_notes.md"])
        self.assertEqual(delta_asset(rel)["name"], "2026-10-19_delta_CVEs_at_end_of_day.zip")

    def test_missing_delta_raises(self):
        with self.assertRaises(RuntimeError):
            delta_asset(release("cve_x", ["2026-10-19_all_CVEs_at_midnight.zip.zip"]))


class ReleasesAfterTests(unittest.TestCase):
    def test_no_checkpoint_returns_only_latest(self):
        tags = [r["tag_name"] for r in releases_after(None, fake_fetch)]
        self.assertEqual(tags, ["cve_2026-10-20_0000Z"])

    def test_replays_missed_releases_oldest_first(self):
        tags = [r["tag_name"] for r in releases_after("cve_2026-10-19_2100Z", fake_fetch)]
        self.assertEqual(tags, [
            "cve_2026-10-19_2200Z",
            "cve_2026-10-19_2300Z",
            "cve_2026-10-19_at_end_of_day",
            "cve_2026-10-20_0000Z",
        ])

    def test_checkpoint_at_latest_returns_nothing(self):
        self.assertEqual(releases_after("cve_2026-10-20_0000Z", fake_fetch), [])

    def test_unknown_checkpoint_raises_for_baseline_resync(self):
        with self.assertRaises(RuntimeError):
            releases_after("cve_2020-01-01_0000Z", fake_fetch)


if __name__ == "__main__":
    unittest.main()
