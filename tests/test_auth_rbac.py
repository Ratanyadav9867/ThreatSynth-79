"""
Tests for Identity-Based Role-Based Access Control (RBAC) and Security Controls
"""
import pytest
from fastapi.testclient import TestClient
from threatsynth.api.server import app, ALERTS_STORE, init_system_state
from threatsynth.core.auth import authenticate_user, generate_jwt_token, decode_jwt_token, MOCK_USERS
from threatsynth.core.audit import audit_logger


@pytest.fixture(autouse=True)
def ensure_state():
    init_system_state()


@pytest.fixture
def client():
    return TestClient(app)


def test_jwt_generation_and_decoding():
    """Verify standard RFC 7519 JWT creation and signature verification."""
    user = MOCK_USERS["soc_analyst"]
    token = generate_jwt_token(user)
    assert isinstance(token, str)
    assert len(token) > 20

    decoded = decode_jwt_token(token)
    assert decoded["sub"] == user["user_id"]
    assert decoded["role"] == "soc_analyst"
    assert decoded["username"] == "soc_analyst"


def test_mock_idp_authentication(client):
    """Test login endpoint returns valid JWT and user persona."""
    res = client.post("/api/auth/login", json={"username": "soc_analyst"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "soc_analyst"
    assert data["user"]["user_id"] == "usr-analyst-02"


def test_authorized_soc_analyst_access_to_alert_forensics(client):
    """Verify SOC Analyst identity can inspect full sensitive threat forensics and SHAP weights."""
    auth = authenticate_user("soc_analyst")
    token = auth["access_token"]

    assert len(ALERTS_STORE) > 0
    target_id = ALERTS_STORE[0]["alert_id"]

    res = client.get(
        f"/api/alerts/{target_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    alert_data = res.json()
    assert alert_data["access_level"] == "FULL_ACCESS"
    assert alert_data["sensitive_payload"] != "[REDACTED - RESTRICTED TO SOC ANALYSTS & ADMINS]"
    assert "top_risk_drivers" in alert_data["explainability"]


def test_unauthorized_guest_access_blocked_with_403(client):
    """Verify unauthorized guest identity is rejected with 403 Forbidden on sensitive alert endpoints."""
    auth = authenticate_user("unauthorized_guest")
    token = auth["access_token"]

    assert len(ALERTS_STORE) > 0
    target_id = ALERTS_STORE[0]["alert_id"]
    res = client.get(
        f"/api/alerts/{target_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 403
    assert "Access Denied" in res.json()["detail"]

    # Verify security rejection is recorded in audit ledger
    recent_audits = audit_logger.query(role="unauthorized_guest", outcome="DENIED")
    assert len(recent_audits) > 0
    assert recent_audits[0]["status_code"] == 403


def test_tier1_viewer_sees_redacted_alert_feed(client):
    """Verify Tier 1 Viewer receives redacted sensitive payloads."""
    auth = authenticate_user("tier1_viewer")
    token = auth["access_token"]

    res = client.get(
        "/api/alerts",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    alerts = res.json()["alerts"]
    assert len(alerts) > 0
    for a in alerts:
        assert a["access_level"] == "REDACTED_TIER1"
        assert a["sensitive_payload"] == "[REDACTED - RESTRICTED TO SOC ANALYSTS & ADMINS]"
