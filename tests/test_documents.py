"""Document generation tests: exports must never invent facts."""

from __future__ import annotations

import json

from documents import docx_generator, pdf_generator, report_generator
from tests.conftest import create_case, create_target


def _case(db):
    target = create_target(
        db,
        platform_key="facebook_pages",
        url="https://www.facebook.com/pages/Acme/1234567890",
    )
    return create_case(
        db,
        target=target,
        violation_category="fraudulent_business_page",
        title="Fraudulent Page",
        description="The Page took payment for goods that were never delivered.",
        reporter_name="Jane Analyst",
        reporter_email="jane@example.com",
        reporter_org="Acme",
        requested_action="page_removal",
    )


def test_text_export_contains_case_facts(db):
    case = _case(db)
    package = report_generator.build_package(case)
    text = report_generator.render_text(package)
    assert case.case_ref in text
    assert "https://www.facebook.com/pages/1234567890" in text
    assert "No platform-confirmed outcome recorded" in text
    assert "DISCLAIMER" in text
    assert "jane@example.com" in text


def test_json_export_is_structured(db):
    case = _case(db)
    payload = json.loads(report_generator.render_json(report_generator.build_package(case)))
    assert payload["case_reference"] == case.case_ref
    assert payload["decision"]["confirmed_by_platform"] is False
    assert payload["violation"]["category"] == "fraudulent_business_page"


def test_missing_fields_render_as_not_recorded(db):
    case = _case(db)
    case.decision_summary = ""
    case.decision_reference = ""
    package = report_generator.build_package(case)
    text = report_generator.render_text(package)
    assert "not recorded" in text
    assert "permanently disabled" not in text.lower()


def test_contact_can_be_excluded(db):
    case = _case(db)
    package = report_generator.build_package(case, include_contact=False)
    assert package.reporter == {}


def test_pdf_and_docx_are_generated(db, tmp_path):
    case = _case(db)
    package = report_generator.build_package(case)
    pdf_path = pdf_generator.build_pdf(package, tmp_path / "case.pdf")
    docx_path = docx_generator.build_docx(package, tmp_path / "case.docx")
    assert pdf_path.stat().st_size > 1000
    assert docx_path.stat().st_size > 1000
    assert pdf_path.read_bytes().startswith(b"%PDF")
    assert docx_path.read_bytes()[:2] == b"PK"