from fastapi import APIRouter

from backend.app.schemas.prediction import TrafficFeatures
from backend.app.schemas.batch_prediction import BatchPredictionRequest
from backend.app.services.prediction_service import (
    predict_traffic,
    predict_traffic_batch,
    )


router = APIRouter(
    prefix="/predict",
    tags=["Prediction"],
)


@router.post("")
def predict(data: TrafficFeatures):

    features = data.model_dump()

    result = predict_traffic(features)

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