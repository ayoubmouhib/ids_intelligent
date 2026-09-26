from datetime import datetime
from pydantic import BaseModel

class StatisticsOut(BaseModel):
    total_flows: int
    attacks: int
    normal: int
    suspicious: int
    attack_rate: float

class TimelinePoint(BaseModel):
    time: datetime
    total: int
    attacks: int
    normal: int
    suspicious: int
