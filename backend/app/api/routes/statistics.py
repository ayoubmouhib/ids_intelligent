from datetime import datetime, timezone

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
def statistics(
    decision: str | None = Query(
        None,
        pattern="^(NORMAL|ATTACK|SUSPICIOUS)$",
    ),
    source_ip: str | None = Query(
        None,
        min_length=1,
        max_length=45,
    ),
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    db: Session = Depends(get_db),
):
    if start_time and start_time.tzinfo is not None:
        start_time = start_time.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

    if end_time and end_time.tzinfo is not None:
        end_time = end_time.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

    stats = get_statistics(
        db=db,
        decision=decision,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
    )

    return StatisticsOut(**stats)


@router.get("/statistics/timeline")
def statistics_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=1, le=1440),
    decision: str | None = Query(
        None,
        pattern="^(NORMAL|ATTACK|SUSPICIOUS)$",
    ),
    source_ip: str | None = Query(
        None,
        min_length=1,
        max_length=45,
    ),
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    db: Session = Depends(get_db),
):
    if start_time and start_time.tzinfo is not None:
        start_time = start_time.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

    if end_time and end_time.tzinfo is not None:
        end_time = end_time.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

    return get_statistics_timeline(
        db=db,
        hours=hours,
        bucket_minutes=bucket_minutes,
        decision=decision,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
    )