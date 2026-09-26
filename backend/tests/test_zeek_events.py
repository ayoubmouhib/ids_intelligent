from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_zeek_events():
    response = client.get("/zeek/events")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "events" in data

    assert isinstance(data["count"], int)
    assert isinstance(data["events"], list)

def test_zeek_events_attack_filter():
    response = client.get(
        "/zeek/events?decision=ATTACK"
    )

    assert response.status_code == 200

    data = response.json()

    for event in data["events"]:
        assert event["decision"] == "ATTACK"

def test_zeek_events_pagination():
    response = client.get(
        "/zeek/events?limit=1&offset=0"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["events"]) <= 1
