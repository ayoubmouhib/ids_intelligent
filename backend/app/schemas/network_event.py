from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NetworkEventOut(BaseModel):
    id: int

    timestamp: float | None

    uid: str | None

    source_ip: str
    source_port: int | None

    destination_ip: str
    destination_port: int | None

    protocol: str | None
    service: str | None

    duration: float | None

    source_bytes: float | None
    destination_bytes: float | None

    connection_state: str | None

    source_packets: int | None
    destination_packets: int | None

    decision: str

    rf_probability: float
    rf_prediction: bool

    if_score: float
    if_anomaly: bool

    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkEventListOut(BaseModel):
    count: int
    events: list[NetworkEventOut]
