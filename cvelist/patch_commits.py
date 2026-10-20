import re
from typing import Any

CREATE_PATCH_COMMITS_SQL = """
    CREATE TABLE IF NOT EXISTS cve_patch_commits (
        cve_id TEXT NOT NULL,
        repo TEXT NOT NULL,
        sha TEXT NOT NULL,
        url TEXT NOT NULL,
        source TEXT NOT NULL,
        extracted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, sha)
    )
"""
CREATE_PATCH_COMMITS_SHA_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS cve_patch_commits_sha ON cve_patch_commits (sha)"
)

DELETE_PATCH_COMMITS_SQL = "DELETE FROM cve_patch_commits WHERE cve_id = ANY(%s)"
INSERT_PATCH_COMMITS_SQL = """
    INSERT INTO cve_patch_commits (cve_id, repo, sha, url, source)
    VALUES (%(cve_id)s, %(repo)s, %(sha)s, %(url)s, %(source)s)
    ON CONFLICT (cve_id, sha) DO NOTHING
"""

GITHUB_COMMIT = re.compile(r"^https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{40})")
KERNEL_COMMIT = re.compile(r"^https://git\.kernel\.org/(.+?)\?.*\bid=([0-9a-f]{40})")
KERNEL_STABLE_COMMIT = re.compile(r"^https://git\.kernel\.org/stable/c/([0-9a-f]{40})")

# Every kernel commit lives in the same object store, so both URL forms map to one repo name.
KERNEL_REPO = "torvalds/linux"


def kernel_repo(path: str) -> str:
    return KERNEL_REPO if "linux" in path else "git.kernel.org/" + path


def extract_patch_commits(cve_id: str, record: dict[str, Any]) -> list[dict[str, str]]:
    """Commit IDs linked from a CVE record's CNA references (GitHub and kernel.org only)."""
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    references = cna.get("references") if isinstance(cna, dict) else None
    if not isinstance(references, list):
        return []

    rows: dict[str, dict[str, str]] = {}
    for reference in references:
        url = reference.get("url") if isinstance(reference, dict) else None
        if not isinstance(url, str):
            continue
        if match := GITHUB_COMMIT.match(url):
            repo, sha = match.group(1), match.group(2)
            source = "github"
        elif match := KERNEL_COMMIT.match(url):
            repo, sha = kernel_repo(match.group(1)), match.group(2)
            source = "kernel.org"
        elif match := KERNEL_STABLE_COMMIT.match(url):
            repo, sha = KERNEL_REPO, match.group(1)
            source = "kernel.org"
        else:
            continue
        rows.setdefault(sha, {"cve_id": cve_id, "repo": repo, "sha": sha, "url": url, "source": source})
    return list(rows.values())
