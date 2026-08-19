import json
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from backend.app.models.alert import Alert
from backend.app.db.redis_client import redis_client

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