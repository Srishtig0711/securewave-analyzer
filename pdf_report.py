from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from reportlab.lib.pagesizes import A4
from datetime import datetime


def export_pdf_report(stats, audit_data, filename="SecureWave_Audit_Report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SecureWave Wireless Security Audit Report", styles["Heading1"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Traffic Statistics", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    data = [["Protocol", "Count"]]
    for key, value in stats.items():
        data.append([key, value])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (1, 1), (-1, -1), 'CENTER')
    ]))

    elements.append(table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph(f"Risk Score: {audit_data['risk_score']}", styles["Normal"]))
    elements.append(Paragraph(f"Risk Level: {audit_data['risk_level']}", styles["Normal"]))
    elements.append(Paragraph(f"Overall Status: {audit_data['overall_status']}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for item in audit_data["summary"]:
        elements.append(Paragraph(f"- {item}", styles["Normal"]))
        elements.append(Spacer(1, 6))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Recommendations", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for item in audit_data["recommendations"]:
        elements.append(Paragraph(f"- {item}", styles["Normal"]))
        elements.append(Spacer(1, 6))

    doc.build(elements)