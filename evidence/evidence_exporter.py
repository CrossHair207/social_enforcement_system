"""Build a self-describing evidence package (ZIP) for a case."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from database.models import EnforcementCase
from evidence.evidence_manager import absolute_path, inventory
from utils.exporters import to_csv

PACKAGE_README = """\
EVIDENCE PACKAGE - {case_ref}
Generated: {generated}

This package contains the evidence filed for one enforcement case.

Integrity
--------
Every file's SHA-256 digest is listed in manifest.json and inventory.csv.
Verify a file after transfer with, for example:

    sha256sum <file>                          # Linux / macOS
    Get-FileHash <file> -Algorithm SHA256     # Windows PowerShell

The digest must match the value recorded at collection time.

Contents
--------
* manifest.json  - structured case metadata and file digests
* inventory.csv  - tabular evidence list
* files/         - the original evidence files, unmodified

Do not edit files inside this package. If additional context is needed, add a
new evidence item to the case and export a fresh package.
"""


def build_manifest(case: EnforcementCase) -> dict:
    target = case.target
    return {
        "case_reference": case.case_ref,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": target.platform if target else "",
        "target_url": target.url if target else "",
        "target_identifier": target.public_identifier if target else "",
        "violation_category": case.violation_category,
        "status": case.status,
        "requested_action": case.requested_action,
        "evidence_confidence": case.evidence_confidence,
        "confidence_score": case.confidence_score,
        "evidence": inventory(case),
        "notice": (
            "Evidence files are unmodified originals. SHA-256 digests prove integrity; "
            "they do not by themselves prove the captured content is authentic."
        ),
    }


def write_package(case: EnforcementCase, destination: Path) -> Path:
    """Write a ZIP package and return its path."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(case)

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        archive.writestr(
            "inventory.csv",
            to_csv(
                inventory(case),
                [
                    "id", "file", "kind", "media_type", "size_bytes", "sha256",
                    "captured_at", "added_at", "source_url", "description",
                ],
            ),
        )
        archive.writestr(
            "README.txt",
            PACKAGE_README.format(
                case_ref=case.case_ref, generated=manifest["generated_at"]
            ),
        )
        for item in case.evidence:
            path = absolute_path(item)
            if not path.is_file():
                archive.writestr(
                    f"files/MISSING-{item.id}.txt", "file missing at export time"
                )
                continue
            archive.write(path, arcname=f"files/{item.id}-{item.original_name}")
    return destination


def verify_package(path: Path) -> list[dict[str, object]]:
    """Re-hash every file in an exported package and compare with the manifest."""
    results: list[dict[str, object]] = []
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        recorded = {entry["file"]: entry["sha256"] for entry in manifest.get("evidence", [])}
        for info in archive.infolist():
            if not info.filename.startswith("files/") or info.filename.endswith(".txt"):
                continue
            actual = hashlib.sha256(archive.read(info)).hexdigest()
            original = info.filename.split("/", 1)[1]
            original = original.split("-", 1)[1] if "-" in original else original
            expected = recorded.get(original, "")
            results.append(
                {
                    "file": original,
                    "expected": expected,
                    "actual": actual,
                    "ok": expected == actual,
                }
            )
    return results