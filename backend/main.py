from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from scanner import scan
from pdf_report import build_pdf

app = FastAPI(title="Scano API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/scan")
async def run_scan(payload: dict):
    return await scan(payload["url"])

@app.get("/api/scan/pdf")
async def scan_pdf(url: str):
    data = await scan(url)
    pdf = build_pdf(data)
    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline; filename=scan_report.pdf"}
    )

