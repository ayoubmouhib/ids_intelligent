from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.network_event import NetworkEventListOut
from backend.app.services.network_event_service import get_network_events


router = APIRouter(
    prefix="/zeek",
    tags=["Zeek"],
)


@router.get("/events", response_model=NetworkEventListOut)
def list_zeek_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),

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

    total_count, events = get_network_events(
        db=db,
        limit=limit,
        offset=offset,
        decision=decision,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
    )

    return {
        "count": total_count,
        "events": events,
    }