from pydantic import BaseModel
from typing import Dict, List, Optional

class ScanRequest(BaseModel):
    url: str

class ScanResult(BaseModel):
    target: str
    score: int
    checks: Dict[str, Optional[str]]
    recommendations: List[str]

