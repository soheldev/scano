from pydantic import BaseModel
from typing import Dict, List, Optional

class CheckResult(BaseModel):
    status: str        # pass, needs_improvement, not_configured, info
    details: Optional[str]

class ScanResult(BaseModel):
    target: str
    score: int
    checks: Dict[str, CheckResult]
    recommendations: List[str]

class ScanRequest(BaseModel):
    url: str
