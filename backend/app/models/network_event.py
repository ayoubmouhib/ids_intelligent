from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from datetime import datetime, timezone

from backend.app.db.database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(Float, nullable=True)

    uid = Column(String(100), nullable=True, index=True)

    source_ip = Column(String(45), nullable=False)
    source_port = Column(Integer, nullable=True)

    destination_ip = Column(String(45), nullable=False)
    destination_port = Column(Integer, nullable=True)

    protocol = Column(String(20), nullable=True)
    service = Column(String(50), nullable=True)

    duration = Column(Float, nullable=True)

    source_bytes = Column(Float, nullable=True)
    destination_bytes = Column(Float, nullable=True)

    connection_state = Column(String(20), nullable=True)

    source_packets = Column(Integer, nullable=True)
    destination_packets = Column(Integer, nullable=True)

    decision = Column(String(20), nullable=False)

    rf_probability = Column(Float, nullable=False)
    rf_prediction = Column(Boolean, nullable=False)

    if_score = Column(Float, nullable=False)
    if_anomaly = Column(Boolean, nullable=False)

    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
