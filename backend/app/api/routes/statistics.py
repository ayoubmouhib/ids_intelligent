from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.services.statistics_service import (
	get_statistics,
	get_statistics_timeline,
)
from backend.app.schemas.statistics import StatisticsOut

router = APIRouter()

@router.get("/statistics", response_model=StatisticsOut)
def statistics(db: Session = Depends(get_db)):
    stats = get_statistics(db)
    return StatisticsOut(**stats)

@router.get("/statistics/timeline")
def statistics_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    return get_statistics_timeline(
        db=db,
        hours=hours,
        bucket_minutes=bucket_minutes,
    )
