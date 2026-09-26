from sqlalchemy.orm import Session

from backend.app.models.network_event import NetworkEvent


def get_network_events(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    decision: str | None = None,
    source_ip: str | None = None,
    start_time=None,
    end_time=None,
):
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

    total_count = query.count()

    events = (
        query
        .order_by(NetworkEvent.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return total_count, events

def create_network_event(db, meta, features, result: dict):
    event = NetworkEvent(
        timestamp=meta.timestamp,
        uid=meta.uid,
        source_ip=meta.source_ip,
        source_port=meta.source_port,
        destination_ip=meta.destination_ip,
        destination_port=meta.destination_port,
        protocol=features.protocol_type,
        service=features.service,
        duration=features.duration,
        source_bytes=features.src_bytes,
        destination_bytes=features.dst_bytes,
        connection_state=meta.connection_state or features.flag,
        source_packets=meta.source_packets,
        destination_packets=meta.destination_packets,
        decision=result["decision"],
        rf_probability=result["rf_probability"],
        rf_prediction=result["rf_prediction"],
        if_score=result["if_score"],
        if_anomaly=result["if_anomaly"],
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
