import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(incident_data: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()

    # Title
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#1E293B'))
    story.append(Paragraph("🛡️ CyberShield AI — Incident Executive Summary", title_style))
    story.append(Spacer(1, 12))

    triage = incident_data.get("triage", {})
    policy = incident_data.get("policy", {})

    # Summary Table
    table_data = [
        ["Field", "Details"],
        ["Threat Vector", triage.get("threat_vector", "N/A")],
        ["Severity Level", triage.get("severity", "N/A")],
        ["Policy Status", policy.get("action_status", "N/A")],
        ["Threat Summary", triage.get("threat_summary", "N/A")]
    ]

    t = Table(table_data, colWidths=[150, 370])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
    ]))
    story.append(t)
    story.append(Spacer(1, 18))

    # Remediation Section
    story.append(Paragraph("<b>Recommended Mitigation Steps:</b>", styles['Heading2']))
    remediation_text = incident_data.get("remediation", "No remediation plan provided.").replace("\n", "<br/>")
    story.append(Paragraph(remediation_text, styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()