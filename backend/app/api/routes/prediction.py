from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.schemas.prediction import TrafficFeatures
from backend.app.schemas.batch_prediction import BatchPredictionRequest
from backend.app.services.prediction_service import (
    predict_traffic,
    predict_traffic_batch,
)
from backend.app.db.database import get_db
from backend.app.services.alert_service import create_alert
from backend.app.models.network_event import NetworkEvent 

router = APIRouter(
    prefix="/predict",
    tags=["Prediction"],
)


@router.post("")
def predict(data: TrafficFeatures, db: Session = Depends(get_db)):
    features = data.model_dump()

    # 1. Run ML Inference
    result = predict_traffic(features)

    # 2. Save event to DB
    try:
        now = datetime.now(timezone.utc)
        
        event = NetworkEvent(
            timestamp=now.timestamp(),  # Fix: Convert datetime to Unix float (double precision)
            source_ip=features.get("source_ip", "10.0.2.15"),
            destination_ip=features.get("destination_ip", "192.150.187.43"),
            source_port=features.get("source_port", 80),
            destination_port=features.get("destination_port", 80),
            protocol=features.get("protocol_type", "tcp"),
            service=features.get("service", "http"),
            duration=features.get("duration", 0.0),
            decision=result["decision"],
            rf_probability=result.get("rf_probability", 0.0),
            rf_prediction=result.get("rf_prediction", 0),
            if_score=result.get("if_score", 0.0),
            if_anomaly=result.get("if_anomaly", 1),
            created_at=now,             # Keeps native datetime object
        )
        db.add(event)
        db.commit()
        db.refresh(event)
    except Exception as e:
        db.rollback()
        print(f"⚠️ Error saving NetworkEvent to DB: {e}")

    # 3. Create alert for ATTACK or SUSPICIOUS decisions
    if result["decision"] in ["ATTACK", "SUSPICIOUS"]:
        create_alert(
            db=db,
            decision=result["decision"],
            rf_probability=result["rf_probability"],
            if_score=result["if_score"],
            rf_prediction=result.get("rf_prediction", 0),
            if_anomaly=result.get("if_anomaly", 1),
        )

    return result


@router.post("/batch")
def predict_batch(data: BatchPredictionRequest):
    samples = [sample.model_dump() for sample in data.samples]
    predictions = predict_traffic_batch(samples)

    return {
        "count": len(predictions),
        "predictions": predictions,
    }