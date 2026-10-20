import csv
import hashlib
import io
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

CSAF_BASE_URL = "https://advisories.ncsc.nl/csaf/v2/"
CHANGES_URL = CSAF_BASE_URL + "changes.csv"
INDEX_URL = CSAF_BASE_URL + "index.txt"
PROVIDER_METADATA_URL = "https://advisories.ncsc.nl/.well-known/csaf/provider-metadata.json"
MAX_LIST_BYTES = 4 * 1024**2
MAX_DOCUMENT_BYTES = 64 * 1024**2  # Some advisories are large, e.g. 2025/ncsc-2025-0051.json at 56.5 MB.
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_KEY_BYTES = 256 * 1024


@dataclass(frozen=True)
class Change:
    path: str
    changed_at: datetime


def parse_changes(text: str) -> list[Change]:
    """Parse changes.csv: one `path,timestamp` row per CSAF document."""
    changes = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not row[0].endswith(".json"):
            continue
        changes.append(Change(path=row[0], changed_at=datetime.fromisoformat(row[1])))
    return changes


def select_changes(changes: list[Change], stored: dict[str, datetime]) -> list[Change]:
    """Documents that are new, or whose published timestamp differs from the stored one.

    A new version of an advisory changes its timestamp, so it is picked up here even
    though its path is already known. Oldest first, so later versions win on conflict.
    """
    pending = [c for c in changes if stored.get(c.path) != c.changed_at]
    return sorted(pending, key=lambda c: c.changed_at)


def verify_sha512(document: bytes, sha512_file: str) -> bool:
    """Check a `.sha512` companion file: `<hex>  <filename>`.

    The filename inside the file is not compared. NCSC writes names such as
    `ncsc-2025-0050-0.json` next to documents called `ncsc-2025-0050.json`. The file is
    fetched from the document's own URL, so the hash is the only thing that matters.
    """
    parts = sha512_file.split()
    if not parts:
        return False
    return hashlib.sha512(document).hexdigest() == parts[0].lower()


def _gpg(homedir: Path, args: list[str], *, data: bytes | None = None, text: bool = False):
    """Run gpg against a keyring, from its parent folder, using relative names.

    Git-for-Windows gpg misreads absolute Windows paths, so every path is passed relative
    to the keyring's parent. Linux containers behave the same way.
    """
    return subprocess.run(
        ["gpg", "--homedir", homedir.name, "--batch", *args],
        cwd=homedir.parent, input=data, capture_output=True, text=text,
    )


def primary_keys(homedir: Path) -> dict[str, int]:
    """Primary-key fingerprint -> expiry as a Unix time (0 when the key never expires)."""
    result = _gpg(homedir, ["--with-colons", "--list-keys"], text=True)
    if result.returncode != 0:
        raise RuntimeError(f"gpg --list-keys failed: {result.stderr.strip()}")
    keys: dict[str, int] = {}
    expiry = None
    expecting_primary = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            expiry = int(fields[6]) if fields[6] else 0
            expecting_primary = True
        elif fields[0] == "fpr" and expecting_primary:
            keys[fields[9]] = expiry
            expecting_primary = False
    return keys


def import_keys(homedir: Path, key_blobs: list[bytes], expected: set[str]) -> None:
    """Import the publisher's keys and require them to match the fingerprints in provider metadata."""
    for blob in key_blobs:
        result = _gpg(homedir, ["--import"], data=blob)
        if result.returncode != 0:
            raise RuntimeError(f"gpg --import failed: {result.stderr.decode(errors='replace').strip()}")
    actual = set(primary_keys(homedir))
    if actual != expected:
        raise ValueError(
            f"Keyring fingerprints {sorted(actual)} do not match provider metadata {sorted(expected)}"
        )


def verify_signature(homedir: Path, signature: bytes, document: bytes, trusted: set[str]) -> bool:
    """True for a valid signature from a trusted primary key.

    gpg reports GOODSIG for a current key. Once a key has expired, it reports EXPKEYSIG
    instead, even for a signature made before the expiry. Those are accepted when the
    signature time is earlier than the key's expiry, because the key was valid then.
    """
    # Write the files inside the keyring folder, so gpg only ever sees relative paths.
    with tempfile.TemporaryDirectory(prefix="verify-", dir=homedir) as tmp:
        (Path(tmp) / "document.json.asc").write_bytes(signature)
        (Path(tmp) / "document.json").write_bytes(document)
        # Relative to the keyring's parent, where _gpg runs.
        relative = f"{homedir.name}/{Path(tmp).name}"
        result = _gpg(
            homedir,
            ["--status-fd", "1", "--verify",
             f"{relative}/document.json.asc", f"{relative}/document.json"],
            text=True,
        )
    if result.returncode != 0:
        return False
    good = False
    expired_key = False
    signer_primary = None
    signed_at = None
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] GOODSIG"):
            good = True
        elif line.startswith("[GNUPG:] EXPKEYSIG"):
            expired_key = True
        elif line.startswith("[GNUPG:] VALIDSIG"):
            fields = line.split()
            # VALIDSIG: field 4 is the signature time; the last field is the primary key fingerprint.
            signed_at = int(fields[4])
            signer_primary = fields[-1]
    if signer_primary not in trusted:
        return False
    if good:
        return True
    if expired_key and signed_at is not None:
        expiry = primary_keys(homedir).get(signer_primary, 0)
        return expiry != 0 and signed_at < expiry
    return False


def parse_document(document: dict) -> dict:
    """Pull the fields the database needs out of a CSAF 2.0 document."""
    tracking = document["document"]["tracking"]
    return {
        "tracking_id": tracking["id"],
        "title": document["document"]["title"],
        "initial_release_date": tracking.get("initial_release_date"),
        "current_release_date": tracking.get("current_release_date"),
        "cve_ids": sorted({v["cve"] for v in document.get("vulnerabilities", []) if v.get("cve")}),
    }
