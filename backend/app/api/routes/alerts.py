from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.services.alert_service import get_alerts
from backend.app.schemas.alert import AlertListOut

router = APIRouter()

@router.get("/alerts", response_model=AlertListOut)
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: str | None = Query(None, description="Filter by ATTACK or NORMAL"),
    db: Session = Depends(get_db),
):
    total_count, alerts = get_alerts(db, limit=limit, offset=offset, decision=decision)
    return AlertListOut(count=total_count, alerts=alerts)