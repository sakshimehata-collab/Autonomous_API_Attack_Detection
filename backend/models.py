from pydantic import BaseModel
from typing import Optional


class SecurityLog(BaseModel):

    request_id: Optional[str] = None

    ip_address: str

    method: Optional[str] = None

    endpoint: Optional[str] = None

    attack_type: Optional[str] = "Normal"

    risk_score: Optional[float] = 0

    confidence: Optional[float] = 0

    status: Optional[str] = "normal"

    action: Optional[str] = "allowed"