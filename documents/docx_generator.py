"""DOCX rendering of a case package (python-docx)."""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.shared import Pt

from documents.report_generator import CasePackage


def build_docx(package: CasePackage, destination: Path | str) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    document = Document()
    styles = document.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10)

    document.add_heading("Enforcement Request Package", level=0)
    document.add_paragraph(
        f"{package.platform_label} - case {package.case_reference} - "
        f"generated {package.generated_at}"
    )

    document.add_heading("Case details", level=1)
    table = document.add_table(rows=0, cols=2)
    table.style = "Light Grid Accent 1"
    for label, value in [
        ("Case reference", package.case_reference),
        ("Platform", package.platform_label),
        ("Target URL", package.target_url),
        ("Target handle", package.target_identifier),
        ("Display name", package.target_display_name),
        ("Alleged category", package.violation_label),
        ("Requested action", package.requested_action),
        ("Case status", package.status_label),
    ]:
        cells = table.add_row().cells
        cells[0].text = label
        cells[1].text = value

    document.add_heading("Documented conduct", level=1)
    document.add_paragraph(package.description)

    document.add_heading("Policies cited", level=1)
    if package.policies:
        for policy in package.policies:
            document.add_paragraph(str(policy.get("title")), style="List Bullet")
            document.add_paragraph(str(policy.get("url")))
            document.add_paragraph(str(policy.get("summary")))
    else:
        document.add_paragraph("No policy reference recorded.")

    document.add_heading("Evidence inventory", level=1)
    if package.evidence:
        evidence_table = document.add_table(rows=1, cols=5)
        evidence_table.style = "Light Grid Accent 1"
        headers = evidence_table.rows[0].cells
        for index, header in enumerate(["#", "File", "Kind", "Captured", "SHA-256"]):
            headers[index].text = header
        for item in package.evidence:
            cells = evidence_table.add_row().cells
            cells[0].text = str(item["id"])
            cells[1].text = item["file"]
            cells[2].text = item["kind"]
            cells[3].text = item["captured_at"] or "not recorded"
            cells[4].text = item["sha256"]
    else:
        document.add_paragraph("No evidence filed.")

    document.add_heading("Assessment", level=1)
    document.add_paragraph(
        f"Evidence support: {package.evidence_confidence} "
        f"({package.confidence_score}/100)"
    )
    document.add_paragraph(
        "Manual review: "
        + ("confirmed" if package.manual_review_confirmed else "not confirmed")
    )
    document.add_paragraph(f"Platform decision: {package.decision.get('label')}")
    document.add_paragraph(f"Decision reference: {package.decision.get('reference')}")
    if package.missing_evidence:
        document.add_heading("Outstanding evidence", level=2)
        for item in package.missing_evidence:
            document.add_paragraph(item, style="List Bullet")

    document.add_heading("Case timeline", level=1)
    if package.timeline:
        for entry in package.timeline:
            document.add_paragraph(
                f"{entry['at']} - {entry['event']} [{entry['source']}]", style="List Bullet"
            )
    else:
        document.add_paragraph("No status history recorded.")

    document.add_heading("Submissions", level=1)
    if package.submissions:
        for item in package.submissions:
            document.add_paragraph(
                f"{item['at']} - {item['channel']} ({item['method']}), "
                f"reference {item['reference']}",
                style="List Bullet",
            )
    else:
        document.add_paragraph("No submission recorded.")

    if package.reporter:
        document.add_heading("Reporter contact", level=1)
        document.add_paragraph(f"Name: {package.reporter.get('name')}")
        document.add_paragraph(f"Organisation: {package.reporter.get('organisation')}")
        document.add_paragraph(f"E-mail: {package.reporter.get('email')}")

    if package.channel:
        document.add_heading("Official reporting channel", level=1)
        document.add_paragraph(
            f"{package.channel.get('label')} - {package.channel.get('url')}"
        )

    document.add_heading("Disclaimer", level=1)
    document.add_paragraph(package.disclaimer)

    document.save(destination)
    return destination