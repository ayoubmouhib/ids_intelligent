from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Boolean

from backend.app.db.database import Base


class Alert(Base):

    __tablename__ = "alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    decision = Column(
        String(20),
        nullable=False,
    )

    rf_probability = Column(
        Float,
        nullable=False,
    )

    if_score = Column(
        Float,
        nullable=False,
    )

    rf_prediction = Column(
        Boolean,
        nullable=False,
    )

    if_anomaly = Column(
        Boolean,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )