"""Evidence validation, integrity and packaging tests."""

from __future__ import annotations

import zipfile

import pytest

from evidence import evidence_exporter, evidence_manager
from evidence.hash_manager import sha256_bytes, sha256_file
from tests.conftest import create_case, create_target
from utils.validators import ValidationError

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PDF = b"%PDF-1.4\n" + b"content" * 10


def _case(db):
    target = create_target(db, platform_key="instagram", url="https://www.instagram.com/evi")
    return create_case(db, target)


def test_store_and_verify_integrity(db):
    case = _case(db)
    item = evidence_manager.store_evidence(
        db, case, filename="screen.png", data=PNG, kind="screenshot"
    )
    assert item.sha256 == sha256_bytes(PNG)
    assert evidence_manager.absolute_path(item).is_file()
    result = evidence_manager.verify_integrity(db, item)
    assert result["ok"] is True


def test_tampering_is_detected(db):
    case = _case(db)
    item = evidence_manager.store_evidence(
        db, case, filename="screen.png", data=PNG, kind="screenshot"
    )
    path = evidence_manager.absolute_path(item)
    path.write_bytes(PNG + b"tampered")
    result = evidence_manager.verify_integrity(db, item)
    assert result["ok"] is False
    assert result["reason"] == "hash mismatch"


def test_duplicate_content_rejected(db):
    case = _case(db)
    evidence_manager.store_evidence(db, case, filename="a.png", data=PNG, kind="screenshot")
    with pytest.raises(ValidationError):
        evidence_manager.store_evidence(
            db, case, filename="b.png", data=PNG, kind="screenshot"
        )


def test_executable_extension_rejected(db):
    case = _case(db)
    with pytest.raises(ValidationError):
        evidence_manager.store_evidence(
            db, case, filename="payload.exe", data=PNG, kind="screenshot"
        )


def test_magic_bytes_must_match_extension(db):
    case = _case(db)
    with pytest.raises(ValidationError):
        evidence_manager.store_evidence(
            db, case, filename="fake.png", data=PDF, kind="screenshot"
        )


def test_html_with_script_rejected(db):
    case = _case(db)
    with pytest.raises(ValidationError):
        evidence_manager.store_evidence(
            db,
            case,
            filename="page.html",
            data=b"<html><script>alert(1)</script></html>",
            kind="other",
        )


def test_inventory_and_duplicate_groups(db):
    case = _case(db)
    evidence_manager.store_evidence(db, case, filename="a.png", data=PNG, kind="screenshot")
    evidence_manager.store_evidence(db, case, filename="b.pdf", data=PDF, kind="other")
    rows = evidence_manager.inventory(case)
    assert {row["file"] for row in rows} == {"a.png", "b.pdf"}
    assert evidence_manager.duplicate_groups(case) == {}


def test_export_package_verifies(db, tmp_path):
    case = _case(db)
    evidence_manager.store_evidence(
        db, case, filename="a.png", data=PNG, kind="screenshot", description="proof"
    )
    path = evidence_exporter.write_package(case, tmp_path / "package.zip")
    assert path.is_file()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert "inventory.csv" in names
        assert any(name.startswith("files/") for name in names)
    results = evidence_exporter.verify_package(path)
    assert results and all(result["ok"] for result in results)


def test_hash_file_helper(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"abc")
    assert sha256_file(path) == sha256_bytes(b"abc")