import unittest

from cvelist.patch_commits import extract_patch_commits

SHA = "2864e767053317538feafa815046fff89e5a16be"
SHA2 = "cf1a0c411b2668c57c41e9c4efd15ba17b6b322c"


def record(*urls: str) -> dict:
    return {"containers": {"cna": {"references": [{"url": url} for url in urls]}}}


class ExtractPatchCommitsTests(unittest.TestCase):
    def test_extracts_github_commit(self):
        rows = extract_patch_commits("CVE-1", record(f"https://github.com/bminor/glibc/commit/{SHA}"))
        self.assertEqual(rows, [{
            "cve_id": "CVE-1", "repo": "bminor/glibc", "sha": SHA,
            "url": f"https://github.com/bminor/glibc/commit/{SHA}", "source": "github",
        }])

    def test_extracts_kernel_commit(self):
        url = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={SHA2}"
        rows = extract_patch_commits("CVE-2", record(url))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha"], SHA2)
        self.assertEqual(rows[0]["source"], "kernel.org")
        self.assertEqual(rows[0]["repo"], "torvalds/linux")

    def test_extracts_kernel_stable_commit(self):
        rows = extract_patch_commits("CVE-6", record(f"https://git.kernel.org/stable/c/{SHA}"))
        self.assertEqual(rows[0]["sha"], SHA)
        self.assertEqual(rows[0]["repo"], "torvalds/linux")
        self.assertEqual(rows[0]["source"], "kernel.org")

    def test_ignores_other_references(self):
        rows = extract_patch_commits("CVE-3", record(
            "https://example.com/advisory",
            "https://github.com/owner/repo/pull/12",
            "https://github.com/owner/repo/commit/short",
        ))
        self.assertEqual(rows, [])

    def test_deduplicates_same_sha_within_a_record(self):
        rows = extract_patch_commits("CVE-4", record(
            f"https://github.com/bminor/glibc/commit/{SHA}",
            f"https://github.com/bminor/glibc/commit/{SHA}.patch",
        ))
        self.assertEqual(len(rows), 1)

    def test_handles_missing_containers(self):
        self.assertEqual(extract_patch_commits("CVE-5", {}), [])
        self.assertEqual(extract_patch_commits("CVE-5", {"containers": {"cna": {}}}), [])


if __name__ == "__main__":
    unittest.main()
