from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.prediction import TrafficFeatures
from backend.app.services.prediction_service import predict_traffic
from backend.app.services.alert_service import create_alert


router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post("")
def analyze(
    data: TrafficFeatures,
    db: Session = Depends(get_db),
):
    """
    Analyze a network traffic sample using the hybrid IDS.

    The request is evaluated by:
    - Random Forest
    - Isolation Forest
    - Hybrid decision strategy

    ATTACK and SUSPICIOUS decisions are stored as alerts.
    """

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

    return {
        "analysis": result,
        "alert_created": result["decision"] in ["ATTACK", "SUSPICIOUS"],
    }
