from fastapi import APIRouter

from backend.app.schemas.prediction import TrafficFeatures
from backend.app.schemas.batch_prediction import BatchPredictionRequest
from backend.app.services.prediction_service import (
    predict_traffic,
    predict_traffic_batch,
    )

from fastapi import Depends
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.services.alert_service import create_alert


router = APIRouter(
    prefix="/predict",
    tags=["Prediction"],
)


@router.post("")
def predict(data: TrafficFeatures, db: Session = Depends(get_db)):

    features = data.model_dump()

    result = predict_traffic(features)

    if result["decision"] in ["ATTACK", "SUSPICIOUS"]:
        create_alert(
            db=db,
            decision=result["decision"],
            rf_probability=result["rf_probability"],
            if_score=result["if_score"],
            rf_prediction=result["rf_prediction"],
            if_anomaly=result["if_anomaly"],
        )

    return result

@router.post("/batch")
def predict_batch(data: BatchPredictionRequest):

    samples = [
        sample.model_dump()
        for sample in data.samples
    ]

    predictions = predict_traffic_batch(samples)

    return {
        "count": len(predictions),
        "predictions": predictions,
    }