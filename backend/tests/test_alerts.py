from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_get_alerts():
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "alerts" in data

    assert isinstance(data["count"], int)
    assert isinstance(data["alerts"], list)
