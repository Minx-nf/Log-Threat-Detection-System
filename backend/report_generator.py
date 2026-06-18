from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

# --- 1. THREAT KNOWLEDGE BASE ---
# Add new threats here anytime. The PDF will handle them automatically.
THREAT_ADVICE_DB = {
    "privilege_escalation": "Immediate audit of IAM roles is required. Revoke unverified administrative grants.",
    "failed_login": "Potential brute-force attack. Review account lockout policies and enforce MFA.",
    "port_scan": "Reconnaissance activity identified. Verify perimeter firewall rules and update IPS configurations.",
    "sql_injection": "Database attack detected. Immediately review Web Application Firewall (WAF) rules and sanitize input queries.",
    "malware_detected": "Malicious payload identified. Isolate the affected host from the network and initiate forensic imaging.",
    "successful_login": "Standard authentication verified. Ensure session timeouts are properly configured."
}

# --- 2. DYNAMIC CONTENT ENGINE ---
def get_dynamic_content(stats, alerts, analytics):
    recommendations = []
    
    # Risk Logic
    alert_count = stats.get('total_alerts', 0)
    risk_level = "CRITICAL" if alert_count > 25 else "HIGH" if alert_count > 10 else "MEDIUM" if alert_count > 0 else "LOW"
    
    # Automated Recommendation Loop
    event_types = analytics.get('event_types', {})
    
    for event_name, count in event_types.items():
        if count > 0:
            display_name = str(event_name).replace('_', ' ').title()
            
            if event_name in THREAT_ADVICE_DB:
                advice = THREAT_ADVICE_DB[event_name]
                recommendations.append(f"<b>{display_name} ({count} events):</b> {advice}")
            else:
                recommendations.append(f"<b>{display_name} ({count} events):</b> Unrecognized anomaly detected. Investigate the raw system logs immediately.")
    
    if not recommendations:
        recommendations.append("<b>System Stable:</b> The environment is operating normally. Maintain standard monitoring.")
        
    return risk_level, recommendations

# --- 3. UI COMPONENTS ---
def create_banner(text):
    t = Table([[text]], colWidths=[495], hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.navy),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 14),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    return t

# --- 4. REPORT GENERATOR ---
def generate_pdf(stats, alerts, analytics, filename):
    doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(name='Title', fontSize=24, leading=30, textColor=colors.navy, bold=True, alignment=0, spaceAfter=15)
    sub_style = ParagraphStyle(name='Sub', fontSize=10, textColor=colors.grey, alignment=0, spaceAfter=15)
    body_style = ParagraphStyle(name='Body', fontSize=10, leading=15)

    elements = []

    # Header 
    elements.append(Paragraph("Log Analysis & Threat Detection System", title_style))
    elements.append(Paragraph("Automated security and threat analysis report.", sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.navy))
    elements.append(Spacer(1, 25))

    # Executive Summary
    disclaimer = "Note: Automated detection systems are subject to false positives. All critical alerts, particularly privilege escalations and off-hours access, require manual verification by the security team against scheduled maintenance logs."
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(disclaimer, ParagraphStyle(name='Italic', fontSize=9, textColor=colors.dimgrey, fontName='Helvetica-Oblique')))
    elements.append(create_banner("Executive Summary"))
    elements.append(Spacer(1, 10))
    summary = (f"This report provides a comprehensive overview of the system environment. "
               f"Our automated analysis engine has scanned a total of {stats.get('total_logs', 0)} log entries. "
               f"The system has identified {stats.get('total_alerts', 0)} security findings that require attention. "
               f"This document summarizes the current security posture, threat distribution, and actionable recommendations.")
    elements.append(Paragraph(summary, body_style))
    elements.append(Spacer(1, 25))

    # Threat Statistics Table
    elements.append(create_banner("Threat Statistics"))
    elements.append(Spacer(1, 10))
    stat_data = [
        ["Metric", "Value"], 
        ["Total Logs", stats.get('total_logs', 0)], 
        ["Total Alerts", stats.get('total_alerts', 0)], 
        ["Critical Alerts", stats.get('critical_alerts', 0)], 
        ["Security Score", stats.get('security_score', 'N/A')]
    ]
    t_stat = Table(stat_data, colWidths=[200, 295], hAlign='LEFT') 
    t_stat.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey), 
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.whitesmoke])
    ]))
    elements.append(t_stat)
    elements.append(Spacer(1, 25))

    # Event Distribution
    elements.append(create_banner("Event Distribution"))
    elements.append(Spacer(1, 10))
    event_data = [["Event Type", "Count"]] + [[str(k), str(v)] for k, v in analytics.get('event_types', {}).items()]
    t_event = Table(event_data, colWidths=[200, 295], hAlign='LEFT')
    t_event.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey), 
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.whitesmoke])
    ]))
    elements.append(t_event)
    elements.append(Spacer(1, 25))

    # Visual Analysis 
    elements.append(create_banner("Visual Analysis"))
    elements.append(Spacer(1, 10))
    sev = analytics.get('severity_counts', {})
    if sev:
        d = Drawing(400, 160)
        bc = VerticalBarChart()
        bc.x = 20
        bc.y = 25 
        bc.height = 120
        bc.width = 250
        bc.data = [list(sev.values())]
        bc.categoryAxis.categoryNames = list(sev.keys())
        d.add(bc)
        elements.append(d)
    elements.append(Spacer(1, 25))

    # Risk Assessment
    risk, recs = get_dynamic_content(stats, alerts, analytics)
    elements.append(create_banner("Risk Assessment"))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Current Risk Level: <font color='red'><b>{risk}</b></font>", body_style))
    elements.append(Spacer(1, 25))
    
    # Recommendations
    elements.append(create_banner("Recommendations"))
    elements.append(Spacer(1, 10))
    for r in recs: 
        elements.append(Paragraph(f"• {r}", body_style))
        elements.append(Spacer(1, 5))
    elements.append(Spacer(1, 20))

    # Recent Threats
    elements.append(create_banner("Recent Threats"))
    elements.append(Spacer(1, 10))
    t_data = [['Severity', 'Source IP', 'Threat']] + [[str(a.get("severity", "")), a.get("source_ip", ""), a.get("threat", "")[:50]] for a in alerts[:8]]
    t_threat = Table(t_data, colWidths=[90, 105, 300], hAlign='LEFT')
    t_threat.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey), 
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.whitesmoke])
    ]))
    elements.append(t_threat)

    doc.build(elements)