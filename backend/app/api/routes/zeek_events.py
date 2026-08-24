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
    db: Session = Depends(get_db),
):
    total_count, events = get_network_events(
        db=db,
        limit=limit,
        offset=offset,
        decision=decision,
    )

    return {
        "count": total_count,
        "events": events,
    }
