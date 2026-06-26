import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from backend.config import settings, logger

def generate_pdf_report(alert_data: dict, summary: str, remediation: str, analyst_name: str) -> str:
    """Generate a structured security incident PDF report using ReportLab."""
    pdf_filename = f"incident_report_{alert_data['id']}_{int(datetime.utcnow().timestamp())}.pdf"
    pdf_path = os.path.join(settings.REPORTS_DIR, pdf_filename)
    
    # Create document templates
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    # Primary theme colors: Deep navy (#0f172a), accent teal (#14b8a6), alert red (#ef4444)
    primary_color = colors.HexColor("#0f172a")
    accent_color = colors.HexColor("#14b8a6")
    critical_color = colors.HexColor("#ef4444")
    warning_color = colors.HexColor("#f97316")
    info_color = colors.HexColor("#3b82f6")
    bg_light = colors.HexColor("#f8fafc")
    text_color = colors.HexColor("#1e293b")
    
    # Title style
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.white,
        spaceAfter=15
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=primary_color,
        spaceBefore=15,
        spaceAfter=8,
        borderPadding=2
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=text_color,
        leading=14,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        textColor=colors.HexColor("#0f172a"),
        backColor=bg_light,
        borderPadding=6,
        spaceAfter=8
    )

    story = []
    
    # Header Banner block (Title & Brand)
    banner_data = [
        [Paragraph("AI SOC INCIDENT REPORT", title_style)],
        [Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Analyst: {analyst_name}", ParagraphStyle('BannerMeta', parent=title_style, fontSize=10, fontName='Helvetica-Oblique', spaceAfter=0))]
    ]
    banner_table = Table(banner_data, colWidths=[doc.width])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), primary_color),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('TOPPADDING', (0,0), (-1,-1), 15),
        ('BOTTOMPADDING', (0,0), (-1,-1), 15),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 15))

    # Alert Meta Information Summary Table
    severity_int = alert_data.get("severity", 5)
    if severity_int >= 8:
        sev_color = "Critical" if severity_int >= 9 else "High"
        sev_badge_color = critical_color if severity_int >= 9 else warning_color
    elif severity_int >= 4:
        sev_color = "Medium"
        sev_badge_color = warning_color
    else:
        sev_color = "Low"
        sev_badge_color = info_color
        
    meta_data = [
        [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(f"INC-{alert_data['id']}", body_style),
         Paragraph("<b>Severity Score:</b>", body_style), Paragraph(f"<font color='{sev_badge_color.hexval()}'><b>{severity_int}/10 ({sev_color})</b></font>", body_style)],
        [Paragraph("<b>Threat Type:</b>", body_style), Paragraph(alert_data.get('threat_type', 'N/A'), body_style),
         Paragraph("<b>MITRE ID:</b>", body_style), Paragraph(alert_data.get('mitre_id', 'N/A'), body_style)],
        [Paragraph("<b>Source IP:</b>", body_style), Paragraph(alert_data.get('source_ip', '0.0.0.0'), body_style),
         Paragraph("<b>Destination IP:</b>", body_style), Paragraph(alert_data.get('destination_ip', '0.0.0.0'), body_style)],
        [Paragraph("<b>Target System:</b>", body_style), Paragraph(alert_data.get('target_system', 'N/A'), body_style),
         Paragraph("<b>Incident Time:</b>", body_style), Paragraph(str(alert_data.get('timestamp', 'N/A')), body_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[100, 160, 100, doc.width - 360])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Section 1: Threat Analysis & Explanation
    story.append(Paragraph("Threat Analysis & Explanation", section_heading))
    # Replace markdown elements with simple HTML tags for ReportLab Paragraph rendering
    formatted_summary = summary.replace("### ", "<b>").replace("#### ", "<b>").replace("**", "<b>").replace("`", "")
    # Add newlines replacement
    paragraphs = formatted_summary.split("\n\n")
    for para in paragraphs:
        if para.strip():
            story.append(Paragraph(para.strip().replace("\n", "<br/>"), body_style))
            
    story.append(Spacer(1, 10))

    # Section 2: Raw Event Trigger payload
    if alert_data.get("raw_log_payload"):
        story.append(Paragraph("Raw Event Trigger Log Context", section_heading))
        story.append(Paragraph(alert_data["raw_log_payload"].replace("\n", "<br/>"), code_style))
        story.append(Spacer(1, 10))

    # Section 3: Recommended Action & Remediation
    story.append(Paragraph("Containment & Remediation Checklist", section_heading))
    formatted_remed = remediation.replace("### ", "<b>").replace("#### ", "<b>").replace("**", "<b>").replace("`", "")
    remed_paras = formatted_remed.split("\n")
    for r_para in remed_paras:
        if r_para.strip():
            story.append(Paragraph(r_para.strip(), body_style))

    story.append(Spacer(1, 20))
    
    # Footer disclaimer
    story.append(Paragraph("<font size='8' color='#64748b'>CONFIDENTIAL SOC DOCUMENT. DO NOT DISTRIBUTE OUTSIDE OF SECURITY TEAMS.</font>", ParagraphStyle('FooterStyle', parent=body_style, align='CENTER')))

    # Build the document
    try:
        doc.build(story)
        logger.info(f"PDF Incident Report successfully generated at {pdf_path}")
        return pdf_path
    except Exception as e:
        logger.error(f"Failed to build PDF document: {e}")
        raise e
