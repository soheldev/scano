from pydantic import BaseModel
from typing import Dict, List

class TLSInfo(BaseModel):
    issuer: str
    valid_from: str
    valid_to: str
    days_remaining: int
    tls_version: str

class ScanResult(BaseModel):
    target: str
    score: int
    headers: Dict[str, bool]
    csp_status: str
    tls: TLSInfo
    cdn: str
    recommendations: List[str]

