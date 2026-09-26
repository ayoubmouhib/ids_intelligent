from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.prediction import TrafficFeatures
from backend.app.schemas.prediction import ZeekAnalyzeRequest
from backend.app.services.prediction_service import predict_traffic
from backend.app.services.alert_service import create_alert
from backend.app.services.network_event_service import create_network_event

router = APIRouter(
    prefix="/zeek",
    tags=["Zeek"],
)


@router.post("/analyze")
def analyze_zeek(payload: ZeekAnalyzeRequest, db: Session = Depends(get_db)):
    features_dict = payload.features.model_dump()
    result = predict_traffic(features_dict)

    create_network_event(db, meta=payload.meta, features=payload.features, result=result)

    if result["decision"] in ["ATTACK", "SUSPICIOUS"]:
        create_alert(
            db=db,
            decision=result["decision"],
            rf_probability=result["rf_probability"],
            if_score=result["if_score"],
            rf_prediction=result["rf_prediction"],
            if_anomaly=result["if_anomaly"],
        )

    return {"source": "zeek", **result}
