from sqlalchemy.orm import Session

from backend.app.models.alert import Alert


def create_alert(
    db: Session,
    decision: str,
    rf_probability: float,
    if_score: float,
    rf_prediction: bool,
    if_anomaly: bool,
):
    alert = Alert(
        decision=decision,
        rf_probability=rf_probability,
        if_score=if_score,
        rf_prediction=rf_prediction,
        if_anomaly=if_anomaly,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert