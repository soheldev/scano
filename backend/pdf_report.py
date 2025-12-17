from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import io

def build_pdf(data):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, h - 50, "Web Security Scan Report")

    c.setFont("Helvetica", 11)
    c.drawString(50, h - 80, f"Target: {data['target']}")
    c.drawString(50, h - 100, f"Score: {data['score']}/100")
    c.drawString(50, h - 120, f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

    y = h - 160
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Security Headers")

    y -= 20
    c.setFont("Helvetica", 11)
    for k, v in data["headers"].items():
        c.drawString(60, y, f"{k}: {'Present' if v else 'Missing'}")
        y -= 15

    y -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "TLS Information")

    y -= 20
    for k, v in data["tls"].items():
        c.setFont("Helvetica", 11)
        c.drawString(60, y, f"{k}: {v}")
        y -= 15

    y -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Recommendations")

    y -= 20
    c.setFont("Helvetica", 11)
    for r in data["recommendations"]:
        c.drawString(60, y, f"- {r}")
        y -= 15

    c.showPage()
    c.save()
    buf.seek(0)
    return buf

