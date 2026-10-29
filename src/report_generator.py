import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(findings: list, filename="code_review_report.pdf") -> str:
    """
    Generates a professional PDF code review report containing findings, 
    severities, CWE/OWASP mappings, and remediation guidance.
    """
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1f2937'),
        spaceAfter=10
    )
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#374151'),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#4b5563'),
        spaceAfter=6
    )

    # Title & Header
    story.append(Paragraph("🛡️ AI Code Review & Security Analysis Report", title_style))
    story.append(Paragraph("Automated Multi-Agent SAST & RAG Compliance Summary", body_style))
    story.append(Spacer(1, 10))

    # Summary Metrics Table
    high_count = sum(1 for f in findings if f.severity == "High")
    med_count = sum(1 for f in findings if f.severity == "Medium")
    low_count = sum(1 for f in findings if f.severity == "Low")

    summary_data = [
        ['Total Findings', 'High Severity', 'Medium Severity', 'Low Severity'],
        [str(len(findings)), str(high_count), str(med_count), str(low_count)]
    ]
    t = Table(summary_data, colWidths=[120, 120, 120, 120])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#1f2937')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))

    # Detailed Findings Section
    story.append(Paragraph("Detailed Findings & Remediation Roadmap", heading_style))
    
    if not findings:
        story.append(Paragraph("No vulnerabilities or code smells detected.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            severity_color = colors.HexColor('#dc2626') if f.severity == "High" else colors.HexColor('#d97706')
            
            finding_text = f"<b>#{idx} [{f.severity}] {f.agent} - Line {f.line_number}</b><br/>" \
                           f"<b>Category:</b> {f.category}<br/>" \
                           f"<b>Issue:</b> {f.message}<br/>" \
                           f"<b>CWE/OWASP:</b> {f.cwe or 'N/A'} | {f.owasp or 'N/A'}<br/>" \
                           f"<b>Remediation:</b> {f.recommendation or 'Review code pattern.'}"
            
            story.append(Paragraph(finding_text, body_style))
            story.append(Spacer(1, 8))

    doc.build(story)
    return filename