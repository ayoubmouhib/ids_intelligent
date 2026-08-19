from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_statistics():
    response = client.get("/statistics")

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, dict)
