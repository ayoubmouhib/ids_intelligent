from fastapi import APIRouter

from backend.app.schemas.prediction import TrafficFeatures
from backend.app.services.prediction_service import predict_traffic


router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post("")
def analyze(data: TrafficFeatures):

    features = data.model_dump()

    result = predict_traffic(features)

    return {
        "analysis": result,
    }
