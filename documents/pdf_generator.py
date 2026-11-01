"""PDF rendering of a case package (ReportLab)."""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from documents.report_generator import CasePackage


def _styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "SemsTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            "SemsMeta",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(
            "SemsBody",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=13,
        )
    )
    return styles


def _kv_table(rows: list[tuple[str, str]], styles) -> Table:
    data = [
        [Paragraph(f"<b>{escape(key)}</b>", styles["SemsBody"]),
         Paragraph(escape(value), styles["SemsBody"])]
        for key, value in rows
    ]
    table = Table(data, colWidths=[42 * mm, 118 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _bullets(items: list[str], styles) -> ListFlowable:
    return ListFlowable(
        [ListItem(Paragraph(escape(item), styles["SemsBody"])) for item in items],
        bulletType="bullet",
        leftIndent=12,
    )


def build_pdf(package: CasePackage, destination: Path | str) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()

    doc = SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        leftMargin=22 * mm,
        rightMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"Enforcement request {package.case_reference}",
        author="Social Enforcement Management System",
        subject=f"{package.violation_label} - {package.platform_label}",
    )

    flow = [
        Paragraph("Enforcement Request Package", styles["SemsTitle"]),
        Paragraph(
            escape(
                f"{package.platform_label} - case {package.case_reference} - "
                f"generated {package.generated_at}"
            ),
            styles["SemsMeta"],
        ),
        Spacer(1, 8),
        _kv_table(
            [
                ("Case reference", package.case_reference),
                ("Platform", package.platform_label),
                ("Target URL", package.target_url),
                ("Target handle", package.target_identifier),
                ("Display name", package.target_display_name),
                ("Alleged category", package.violation_label),
                ("Requested action", package.requested_action),
                ("Case status", package.status_label),
            ],
            styles,
        ),
        Spacer(1, 10),
        Paragraph("Documented conduct", styles["Heading2"]),
        Paragraph(escape(package.description).replace("\n", "<br/>"), styles["SemsBody"]),
        Spacer(1, 8),
        Paragraph("Policies cited", styles["Heading2"]),
    ]

    if package.policies:
        for policy in package.policies:
            flow.append(
                Paragraph(
                    f"<b>{escape(str(policy.get('title')))}</b><br/>"
                    f"{escape(str(policy.get('url')))}<br/>"
                    f"{escape(str(policy.get('summary')))}",
                    styles["SemsBody"],
                )
            )
            flow.append(Spacer(1, 4))
    else:
        flow.append(Paragraph("No policy reference recorded.", styles["SemsBody"]))

    flow.extend(
        [
            Spacer(1, 8),
            Paragraph("Evidence inventory", styles["Heading2"]),
        ]
    )
    if package.evidence:
        rows = [["#", "File", "Kind", "Captured", "SHA-256"]]
        for item in package.evidence:
            rows.append(
                [
                    str(item["id"]),
                    item["file"][:34],
                    item["kind"],
                    (item["captured_at"] or "not recorded")[:10],
                    item["sha256"][:20] + "...",
                ]
            )
        table = Table(rows, colWidths=[8 * mm, 52 * mm, 26 * mm, 24 * mm, 50 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        flow.append(table)
        flow.append(
            Paragraph(
                "Full SHA-256 digests are listed in the machine-readable export and "
                "the evidence package manifest.",
                styles["SemsMeta"],
            )
        )
    else:
        flow.append(Paragraph("No evidence filed.", styles["SemsBody"]))

    flow.extend(
        [
            Spacer(1, 8),
            Paragraph("Assessment", styles["Heading2"]),
            _kv_table(
                [
                    ("Evidence support", f"{package.evidence_confidence} ({package.confidence_score}/100)"),
                    (
                        "Manual review",
                        "confirmed" if package.manual_review_confirmed else "not confirmed",
                    ),
                    ("Platform decision", str(package.decision.get("label"))),
                    ("Decision reference", str(package.decision.get("reference"))),
                ],
                styles,
            ),
        ]
    )
    if package.missing_evidence:
        flow.extend(
            [
                Spacer(1, 6),
                Paragraph("Outstanding evidence", styles["Heading3"]),
                _bullets(package.missing_evidence, styles),
            ]
        )

    flow.append(PageBreak())
    flow.append(Paragraph("Case timeline", styles["Heading2"]))
    if package.timeline:
        timeline_rows = [["When", "Event", "Source"]]
        for entry in package.timeline:
            timeline_rows.append([entry["at"], entry["event"], entry["source"]])
        table = Table(timeline_rows, colWidths=[36 * mm, 88 * mm, 36 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        flow.append(table)
    else:
        flow.append(Paragraph("No status history recorded.", styles["SemsBody"]))

    flow.append(Spacer(1, 8))
    flow.append(Paragraph("Submissions", styles["Heading2"]))
    if package.submissions:
        flow.append(
            _bullets(
                [
                    f"{item['at']} - {item['channel']} ({item['method']}), reference {item['reference']}"
                    for item in package.submissions
                ],
                styles,
            )
        )
    else:
        flow.append(Paragraph("No submission recorded.", styles["SemsBody"]))

    if package.reporter:
        flow.extend(
            [
                Spacer(1, 8),
                Paragraph("Reporter contact", styles["Heading2"]),
                _kv_table(
                    [
                        ("Name", str(package.reporter.get("name"))),
                        ("Organisation", str(package.reporter.get("organisation"))),
                        ("E-mail", str(package.reporter.get("email"))),
                    ],
                    styles,
                ),
            ]
        )

    if package.channel:
        flow.extend(
            [
                Spacer(1, 8),
                Paragraph("Official reporting channel", styles["Heading2"]),
                Paragraph(
                    escape(
                        f"{package.channel.get('label')} - {package.channel.get('url')}"
                    ),
                    styles["SemsBody"],
                ),
            ]
        )

    flow.extend(
        [
            Spacer(1, 10),
            Paragraph("Disclaimer", styles["Heading2"]),
            Paragraph(escape(package.disclaimer), styles["SemsMeta"]),
        ]
    )

    doc.build(flow)
    return destination
