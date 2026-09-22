import json
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from backend.app.models.network_event import NetworkEvent
from backend.app.db.redis_client import redis_client

STATISTICS_CACHE_KEY = "stats:global"
STATISTICS_CACHE_TTL_SECONDS = 10


def compute_statistics_from_db(
    db: Session,
    decision: str | None = None,
    source_ip: str | None = None,
    start_time=None,
    end_time=None,
) -> dict:
    """Computes traffic statistics directly from NetworkEvent."""

    query = db.query(NetworkEvent)

    if decision:
        query = query.filter(
            NetworkEvent.decision == decision.upper()
        )

    if source_ip:
        query = query.filter(
            NetworkEvent.source_ip == source_ip
        )

    if start_time:
        query = query.filter(
            NetworkEvent.created_at >= start_time
        )

    if end_time:
        query = query.filter(
            NetworkEvent.created_at < end_time
        )

    result = (
        query.with_entities(
            func.count(NetworkEvent.id).label("total"),
            func.sum(
                case(
                    (NetworkEvent.decision == "ATTACK", 1),
                    else_=0,
                )
            ).label("attacks"),
            func.sum(
                case(
                    (NetworkEvent.decision == "NORMAL", 1),
                    else_=0,
                )
            ).label("normal"),
            func.sum(
                case(
                    (NetworkEvent.decision == "SUSPICIOUS", 1),
                    else_=0,
                )
            ).label("suspicious"),
        )
        .first()
    )

    total_flows = result.total or 0
    attacks = result.attacks or 0
    normal = result.normal or 0
    suspicious = result.suspicious or 0

    attack_rate = (
        round((attacks / total_flows) * 100, 2)
        if total_flows
        else 0.0
    )

    return {
        "total_flows": total_flows,
        "attacks": attacks,
        "normal": normal,
        "suspicious": suspicious,
        "attack_rate": attack_rate,
    }

def get_statistics(
    db: Session,
    decision: str | None = None,
    source_ip: str | None = None,
    start_time=None,
    end_time=None,
) -> dict:
    """Returns statistics with optional dashboard filters."""

    # Only cache the unfiltered global statistics.
    if not any(
        [
            decision,
            source_ip,
            start_time,
            end_time,
        ]
    ):
        cached = redis_client.get(STATISTICS_CACHE_KEY)

        if cached is not None:
            return json.loads(cached)

        stats = compute_statistics_from_db(db)

        redis_client.set(
            STATISTICS_CACHE_KEY,
            json.dumps(stats),
            ex=STATISTICS_CACHE_TTL_SECONDS,
        )

        return stats

    return compute_statistics_from_db(
        db=db,
        decision=decision,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
    )

def get_statistics_timeline(
    db: Session,
    hours: int = 24,
    bucket_minutes: int = 60,
    decision: str | None = None,
    source_ip: str | None = None,
    start_time=None,
    end_time=None,
):
    """Returns network activity timeline grouped into time buckets."""

    if hours < 1:
        hours = 1

    if bucket_minutes < 1:
        bucket_minutes = 60

    # Current time as timezone-aware UTC.
    now = datetime.now(timezone.utc)

    # If an explicit time range was supplied, use it.
    # Otherwise calculate the range from `hours`.
    if start_time is not None:
        timeline_start = start_time.replace(tzinfo=timezone.utc)
    else:
        timeline_start = now - timedelta(hours=hours)

    if end_time is not None:
        timeline_end = end_time.replace(tzinfo=timezone.utc)
    else:
        timeline_end = now

    # The database column is `timestamp without time zone`,
    # so use naive UTC values for PostgreSQL comparisons.
    db_start_time = timeline_start.replace(tzinfo=None)
    db_end_time = timeline_end.replace(tzinfo=None)

    query = (
        db.query(NetworkEvent)
        .filter(NetworkEvent.created_at >= db_start_time)
        .filter(NetworkEvent.created_at < db_end_time)
    )

    if decision:
        query = query.filter(
            NetworkEvent.decision == decision.upper()
        )

    if source_ip:
        query = query.filter(
            NetworkEvent.source_ip == source_ip
        )

    events = (
        query
        .order_by(NetworkEvent.created_at.asc())
        .all()
    )

    # Number of buckets for the requested time window.
    total_minutes = (
        timeline_end - timeline_start
    ).total_seconds() / 60

    bucket_count = max(
        1,
        int(total_minutes // bucket_minutes)
    )

    buckets = []

    for i in range(bucket_count):
        bucket_start = (
            timeline_start
            + timedelta(minutes=i * bucket_minutes)
        )

        buckets.append(
            {
                "time": bucket_start.isoformat(),
                "total": 0,
                "attacks": 0,
                "normal": 0,
                "suspicious": 0,
            }
        )

    for event in events:
        event_time = event.created_at

        # Database stores UTC without timezone information.
        if event_time.tzinfo is None:
            event_time = event_time.replace(
                tzinfo=timezone.utc
            )

        elapsed_minutes = (
            event_time - timeline_start
        ).total_seconds() / 60

        bucket_index = int(
            elapsed_minutes // bucket_minutes
        )

        if 0 <= bucket_index < len(buckets):
            bucket = buckets[bucket_index]

            bucket["total"] += 1

            if event.decision == "ATTACK":
                bucket["attacks"] += 1

            elif event.decision == "NORMAL":
                bucket["normal"] += 1

            elif event.decision == "SUSPICIOUS":
                bucket["suspicious"] += 1

    return buckets