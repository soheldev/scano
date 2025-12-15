from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
from fastapi.responses import StreamingResponse

def generate_pdf(data):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750
    c.drawString(50, y, f"Security Scan Report for {data['target']}")
    y -= 30
    c.drawString(50, y, f"Score: {data['score']}/100")
    y -= 30
    for check, val in data["checks"].items():
        status = "OK" if val else "Missing"
        c.drawString(50, y, f"{check}: {status}")
        y -= 20
    c.showPage()
    c.save()
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": "inline; filename=scan_report.pdf"})
