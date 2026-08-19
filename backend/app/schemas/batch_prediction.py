from pydantic import BaseModel

from backend.app.schemas.prediction import TrafficFeatures


class BatchPredictionRequest(BaseModel):
    samples: list[TrafficFeatures]