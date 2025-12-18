from fastapi import FastAPI, HTTPException
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
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    return await scan(url)

@app.get("/api/scan/pdf")
async def scan_pdf(url: str):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    data = await scan(url)
    pdf = build_pdf(data)

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline; filename=scan_report.pdf"}
    )

