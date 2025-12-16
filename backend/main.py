from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from scanner import scan_url
from pdf_generator import generate_pdf
import os

app = FastAPI(title="Scano Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.post("/api/scan")
def scan(request: ScanRequest):
    result = scan_url(request.url)
    if not result:
        raise HTTPException(status_code=400, detail="Unable to fetch target or blocked URL")
    return result

@app.get("/api/scan/pdf")
def scan_pdf(url: str):
    result = scan_url(url)
    if not result:
        raise HTTPException(status_code=400, detail="Unable to fetch target")

    pdf_path = generate_pdf(result)
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="PDF generation failed")

    return FileResponse(pdf_path, media_type='application/pdf', filename="scan_report.pdf")

