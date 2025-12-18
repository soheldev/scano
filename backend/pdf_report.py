from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import io

def build_pdf(data):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    def new_page():
        c.showPage()
        c.setFont("Helvetica", 11)
        return h - 50

    y = h - 50

    # ======================
    # Header
    # ======================
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "Web Security Scan Report")

    y -= 30
    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Target: {data['target']}")
    y -= 15
    c.drawString(50, y, f"Score: {data['score']}/100")
    y -= 15
    c.drawString(50, y, f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

    # ======================
    # Security Headers
    # ======================
    y -= 30
    if y < 100:
        y = new_page()

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Security Headers")

    y -= 20
    c.setFont("Helvetica", 11)
    for k, v in data.get("headers", {}).items():
        if y < 80:
            y = new_page()
        c.drawString(60, y, f"{k}: {'Present' if v else 'Missing'}")
        y -= 15

    # ======================
    # TLS Information
    # ======================
    y -= 20
    if y < 100:
        y = new_page()

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "TLS Information")

    y -= 20
    c.setFont("Helvetica", 11)
    for k, v in data.get("tls", {}).items():
        if y < 80:
            y = new_page()
        c.drawString(60, y, f"{k.replace('_', ' ').title()}: {v}")
        y -= 15

    # ======================
    # DNS Resolution Panel
    # ======================
    y -= 20
    if y < 120:
        y = new_page()

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "DNS Resolution")

    y -= 20
    c.setFont("Helvetica", 11)
    dns = data.get("dns", {})

    c.drawString(60, y, f"Domain: {dns.get('domain', '-')}")
    y -= 15
    c.drawString(60, y, f"Primary Resolved IP: {dns.get('resolved_ip', '-')}")
    y -= 20

    for r in dns.get("results", []):
        if y < 100:
            y = new_page()

        c.setFont("Helvetica-Bold", 11)
        c.drawString(60, y, f"Resolver: {r.get('resolver', '-')}")
        y -= 15

        c.setFont("Helvetica", 11)
        c.drawString(80, y, f"Location: {r.get('location', '-')}")
        y -= 15
        c.drawString(80, y, f"Provider: {r.get('provider', '-')}")
        y -= 15

        ips = r.get("ips", [])
        if ips:
            c.drawString(80, y, "IPs:")
            y -= 15
            for ip in ips:
                if y < 80:
                    y = new_page()
                c.drawString(100, y, f"- {ip}")
                y -= 15
        else:
            c.drawString(80, y, "IPs: None")
            y -= 15

        y -= 10

    # ======================
    # Recommendations
    # ======================
    y -= 10
    if y < 120:
        y = new_page()

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Recommendations")

    y -= 20
    c.setFont("Helvetica", 11)

    recs = data.get("recommendations", [])
    if not recs:
        c.drawString(60, y, "No recommendations 🎉")
    else:
        for r in recs:
            if y < 80:
                y = new_page()
            c.drawString(60, y, f"- {r}")
            y -= 15

    # ======================
    # Finalize
    # ======================
    c.showPage()
    c.save()
    buf.seek(0)
    return buf

