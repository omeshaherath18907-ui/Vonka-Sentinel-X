from fastapi.testclient import TestClient

from app.services.api import APP_NAME, APP_VERSION, api

client = TestClient(api)


def test_root_returns_application_information():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["application"] == APP_NAME
    assert response.json()["version"] == APP_VERSION


def test_health_endpoint_reports_healthy():
    response = client.get("/health")

    assert response.status_code == 200

    result = response.json()
    assert result["status"] == "healthy"
    assert result["application"] == APP_NAME
    assert result["version"] == APP_VERSION
    assert "timestamp" in result
