"""
Tests for Alert Ingestion and Latency Performance (< 2 seconds Non-Functional Requirement)
"""
import time
import pytest
from fastapi.testclient import TestClient
from threatsynth.api.server import app
from threatsynth.data.generator import create_sample_alert


@pytest.fixture
def client():
    return TestClient(app)


def test_single_alert_ingestion_and_latency(client):
    """Verify single alert ingestion completes well within the 2-second constraint."""
    alert = create_sample_alert("HIGH_SQLI")
    start = time.perf_counter()

    res = client.post(
        "/api/alerts/ingest",
        json=alert,
        headers={"Authorization": "Bearer soc_analyst"}
    )
    duration = time.perf_counter() - start

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["processed_count"] == 1
    # Check non-functional latency requirement (< 2.0s)
    assert duration < 2.0
    print(f"[Latency Test] Ingestion duration: {duration*1000:.2f}ms (Constraint: <2000ms)")


def test_batch_alert_ingestion(client):
    """Verify batch ingestion of multiple alerts."""
    batch = [
        create_sample_alert("HIGH_TRAVEL"),
        create_sample_alert("MED_BRUTE"),
        create_sample_alert("LOW_HEALTHCHECK")
    ]
    res = client.post(
        "/api/alerts/ingest",
        json=batch,
        headers={"Authorization": "Bearer admin"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["processed_count"] == 3
