import json
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from backend.app.models.alert import Alert
from backend.app.db.redis_client import redis_client
from datetime import datetime, timedelta

STATISTICS_CACHE_KEY = "stats:global"
STATISTICS_CACHE_TTL_SECONDS = 10   # tune based on how "live" your dashboard needs to be


def compute_statistics_from_db(db: Session) -> dict:
    """The real work — hits PostgreSQL directly. Called only on cache miss."""
    result = (
        db.query(
            func.count(Alert.id).label("total"),
            func.sum(case((Alert.decision == "ATTACK", 1), else_=0)).label("attacks"),
            func.sum(case((Alert.decision == "NORMAL", 1), else_=0)).label("normal"),
            func.sum(case((Alert.decision == "SUSPICIOUS", 1), else_=0)).label("suspicious"),
        )
        .first()
    )

    total_flows = result.total or 0
    attacks = result.attacks or 0
    normal = result.normal or 0
    suspicious = result.suspicious or 0
    attack_rate = round((attacks / total_flows) * 100, 2) if total_flows else 0.0

    return {
        "total_flows": total_flows,
        "attacks": attacks,
        "normal": normal,
        "suspicious": suspicious,
        "attack_rate": attack_rate,
    }


def get_statistics(db: Session) -> dict:
    """Cache-aside pattern: check Redis first, fall back to Postgres on miss."""
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

def get_statistics_timeline(db, hours: int = 24, bucket_minutes: int = 60):
    """
    Return alert activity grouped into time buckets.

    The current database stores security alerts, so this timeline
    represents detected security events rather than raw network packets.
    """

    if hours < 1:
        hours = 1

    if bucket_minutes < 1:
        bucket_minutes = 60

    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)

    alerts = (
        db.query(Alert)
        .filter(Alert.created_at >= start_time)
        .order_by(Alert.created_at.asc())
        .all()
    )

    # Create all buckets first so periods with zero alerts
    # still appear in the chart.
    bucket_count = ((hours * 60) // bucket_minutes) + 1

    buckets = []

    for i in range(bucket_count):
        bucket_start = start_time + timedelta(
            minutes=i * bucket_minutes
        )

        buckets.append(
            {
                "time": bucket_start,
                "total": 0,
                "attacks": 0,
                "normal": 0,
                "suspicious": 0,
            }
        )

    # Put each alert into the correct bucket.
    for alert in alerts:

        elapsed_minutes = (
            alert.created_at - start_time
        ).total_seconds() / 60

        bucket_index = int(
            elapsed_minutes // bucket_minutes
        )

        if bucket_index < 0 or bucket_index >= len(buckets):
            continue

        bucket = buckets[bucket_index]

        bucket["total"] += 1

        if alert.decision == "ATTACK":
            bucket["attacks"] += 1

        elif alert.decision == "NORMAL":
            bucket["normal"] += 1

        elif alert.decision == "SUSPICIOUS":
            bucket["suspicious"] += 1

    return buckets
