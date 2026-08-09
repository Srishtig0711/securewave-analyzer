from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4


def export_pdf_report(
    stats,
    audit_result,
    filename="SecureWave_Audit_Report.pdf"
):
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4
    )

    styles = getSampleStyleSheet()
    elements = []

    # --------------------------
    # Report Header
    # --------------------------

    elements.append(
        Paragraph(
            "SecureWave Wireless Security Audit Report",
            styles["Heading1"]
        )
    )

    elements.append(Spacer(1, 12))

    elements.append(
        Paragraph(
            f"Generated on: "
            f"{audit_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # --------------------------
    # Traffic Statistics
    # --------------------------

    elements.append(
        Paragraph(
            "Traffic Statistics",
            styles["Heading2"]
        )
    )

    elements.append(Spacer(1, 10))

    data = [["Protocol", "Count"]]

    for key, value in stats.items():
        data.append([key, value])

    table = Table(data)

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.grey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.black
            ),
            (
                "ALIGN",
                (1, 1),
                (-1, -1),
                "CENTER"
            )
        ])
    )

    elements.append(table)
    elements.append(Spacer(1, 20))

    # --------------------------
    # Risk Summary
    # --------------------------

    elements.append(
        Paragraph(
            f"Risk Score: {audit_result.score}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Risk Level: {audit_result.level}",
            styles["Normal"]
        )
    )

    if audit_result.level == "HIGH":
        overall_status = "CRITICAL"
    elif audit_result.level == "MEDIUM":
        overall_status = "AT RISK"
    else:
        overall_status = "SECURE"

    elements.append(
        Paragraph(
            f"Overall Status: {overall_status}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # --------------------------
    # Security Findings
    # --------------------------

    elements.append(
        Paragraph(
            "Security Findings",
            styles["Heading2"]
        )
    )

    elements.append(Spacer(1, 10))

    if not audit_result.findings:

        elements.append(
            Paragraph(
                "No significant security findings detected.",
                styles["Normal"]
            )
        )

    else:

        for finding in audit_result.findings:

            elements.append(
                Paragraph(
                    f"<b>{finding.title}</b>",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Severity:</b> "
                    f"{finding.severity}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Description:</b> "
                    f"{finding.description}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Evidence:</b> "
                    f"{finding.evidence}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{finding.recommendation}",
                    styles["Normal"]
                )
            )

            elements.append(
                Spacer(1, 12)
            )

    # --------------------------
    # Build PDF
    # --------------------------

    doc.build(elements)