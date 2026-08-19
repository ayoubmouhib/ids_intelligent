from pydantic import BaseModel
from datetime import datetime
from typing import List

class AlertOut(BaseModel):
    id: int
    decision: str
    rf_probability: float | None = None
    if_score: float | None = None
    rf_prediction: bool
    if_anomaly: bool
    created_at: datetime

    class Config:
        from_attributes = True   # (was orm_mode in Pydantic v1)


class AlertListOut(BaseModel):
    count: int
    alerts: List[AlertOut]