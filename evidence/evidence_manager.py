"""Storage, integrity verification and history for case evidence."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import settings
from database.models import EnforcementCase, Evidence, EvidenceEvent, User
from evidence.file_validator import validate_upload
from evidence.hash_manager import hashes_match, sha256_bytes, sha256_file
from utils.validators import ValidationError

EVIDENCE_KINDS = (
    "screenshot",
    "screen_recording",
    "profile_url",
    "post_url",
    "image",
    "video",
    "text_description",
    "correspondence",
    "ownership_document",
    "other",
)


def _case_directory(case_id: int) -> Path:
    directory = settings.evidence_dir / f"case-{case_id}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def store_evidence(
    db: Session,
    case: EnforcementCase,
    *,
    filename: str,
    data: bytes,
    kind: str = "screenshot",
    description: str = "",
    source_url: str = "",
    captured_at: Optional[datetime] = None,
    actor: Optional[User] = None,
    allow_duplicate: bool = False,
) -> Evidence:
    """Validate, hash and persist one evidence file for a case."""
    if kind not in EVIDENCE_KINDS:
        raise ValidationError(f"unknown evidence kind '{kind}'")

    result = validate_upload(
        filename,
        data,
        allowed_extensions=settings.allowed_extensions,
        max_bytes=settings.max_upload_mb * 1024 * 1024,
    )
    if not result.ok:
        raise ValidationError(result.reason)

    digest = sha256_bytes(data)
    duplicate = db.scalar(
        select(Evidence).where(Evidence.case_id == case.id, Evidence.sha256 == digest)
    )
    if duplicate and not allow_duplicate:
        raise ValidationError(
            f"identical file already filed on this case as evidence #{duplicate.id}"
        )

    stored_name = f"{uuid.uuid4().hex}{result.extension}"
    path = _case_directory(case.id) / stored_name
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows
        pass

    evidence = Evidence(
        case_id=case.id,
        original_name=result.safe_name,
        stored_name=stored_name,
        rel_path=str(path.relative_to(settings.evidence_dir)),
        media_type=result.media_type,
        size_bytes=len(data),
        sha256=digest,
        kind=kind,
        description=(description or "").strip()[:4000],
        source_url=(source_url or "").strip()[:700],
        captured_at=captured_at,
        uploaded_by_id=actor.id if actor else None,
    )
    db.add(evidence)
    db.flush()
    db.add(
        EvidenceEvent(
            evidence_id=evidence.id,
            action="uploaded",
            detail=f"sha256={digest} size={len(data)} kind={kind}",
            actor_id=actor.id if actor else None,
        )
    )
    db.commit()
    return evidence


def absolute_path(evidence: Evidence) -> Path:
    return settings.evidence_dir / evidence.rel_path


def verify_integrity(db: Session, evidence: Evidence) -> dict[str, object]:
    """Recompute the digest and record the check in the evidence history."""
    path = absolute_path(evidence)
    if not path.is_file():
        db.add(
            EvidenceEvent(
                evidence_id=evidence.id, action="integrity_check", detail="file missing"
            )
        )
        db.commit()
        return {"ok": False, "reason": "file missing", "expected": evidence.sha256, "actual": ""}

    actual = sha256_file(path)
    ok = hashes_match(evidence.sha256, actual)
    db.add(
        EvidenceEvent(
            evidence_id=evidence.id,
            action="integrity_check",
            detail=("verified" if ok else "MISMATCH") + f" actual={actual}",
        )
    )
    db.commit()
    return {
        "ok": ok,
        "expected": evidence.sha256,
        "actual": actual,
        "reason": "" if ok else "hash mismatch",
    }


def verify_case_integrity(db: Session, case: EnforcementCase) -> list[dict[str, object]]:
    return [
        {"evidence_id": item.id, **verify_integrity(db, item)} for item in case.evidence
    ]


def delete_evidence(db: Session, evidence: Evidence, actor: Optional[User] = None) -> None:
    path = absolute_path(evidence)
    if path.is_file():
        path.unlink()
    db.delete(evidence)
    db.commit()


def inventory(case: EnforcementCase) -> list[dict[str, object]]:
    """Evidence inventory used by documents and the export package."""
    return [
        {
            "id": item.id,
            "file": item.original_name,
            "kind": item.kind,
            "media_type": item.media_type,
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
            "captured_at": item.captured_at.isoformat() if item.captured_at else "",
            "added_at": item.created_at.isoformat() if item.created_at else "",
            "source_url": item.source_url,
            "description": item.description,
        }
        for item in case.evidence
    ]


def duplicate_groups(case: EnforcementCase) -> dict[str, list[int]]:
    seen: dict[str, list[int]] = {}
    for item in case.evidence:
        seen.setdefault(item.sha256, []).append(item.id)
    return {digest: ids for digest, ids in seen.items() if len(ids) > 1}


def by_kind(items: Iterable[Evidence]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.kind] = counts.get(item.kind, 0) + 1
    return counts
