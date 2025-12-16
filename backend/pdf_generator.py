from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
from datetime import datetime

def generate_pdf(data):
    path = f"scan_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
    c = canvas.Canvas(path, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750
    c.drawString(50, y, f"Security Scan Report for {data['target']}")
    y -= 30
    c.drawString(50, y, f"Score: {data['score']}/100")
    y -= 30

    c.drawString(50, y, "TLS Info:")
    y -= 20
    tls = data.get("tls", {})
    for k,v in tls.items():
        c.drawString(60, y, f"{k}: {v}")
        y -= 15

    y -= 10
    c.drawString(50, y, "Security Headers:")
    y -= 20
    for k,v in data.get("headers", {}).items():
        c.drawString(60, y, f"{k}: {'Present' if v else 'Missing'}")
        y -= 15

    y -= 10
    c.drawString(50, y, "CSP Analysis:")
    y -= 20
    c.drawString(60, y, f"Status: {data['csp_analysis'].get('status')}")
    y -= 15
    for issue in data['csp_analysis'].get('issues', []):
        c.drawString(60, y, f"Issue: {issue}")
        y -= 15

    y -= 10
    c.drawString(50, y, f"CDN / Reverse Proxy: {data.get('cdn')}")
    y -= 20
    c.drawString(50, y, "Recommendations:")
    y -= 20
    for rec in data.get("recommendations", []):
        c.drawString(60, y, f"- {rec}")
        y -= 15

    c.showPage()
    c.save()
    return path

