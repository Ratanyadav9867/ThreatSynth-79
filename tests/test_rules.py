"""
Tests for Multi-Alert Correlation & Conflict Rule Engine
"""
from threatsynth.rules.engine import CorrelationRuleEngine
from threatsynth.data.generator import create_sample_alert


def test_brute_force_to_privilege_escalation_rule():
    """Verify detection of brute force followed by privilege escalation attack chain."""
    engine = CorrelationRuleEngine()

    # Past alert: failed logins
    past_alert = create_sample_alert("MED_BRUTE", "ALT-TEST-01")
    past_alert["username"] = "sarah.vance"
    past_alert["failed_login_count"] = 8
    engine.add_alert(past_alert)

    # Current alert: privilege escalation
    curr_alert = create_sample_alert("HIGH_SQLI", "ALT-TEST-02")
    curr_alert["username"] = "sarah.vance"
    curr_alert["privilege_escalation"] = True

    result = engine.evaluate_correlations(curr_alert)
    assert result["has_correlation"] is True
    assert any(r["rule_id"] == "RULE-CORR-01" for r in result["matched_rules"])


def test_impossible_travel_correlation():
    """Verify impossible travel velocity correlation across geographical locations."""
    engine = CorrelationRuleEngine()

    past_alert = {
        "alert_id": "ALT-GEO-01",
        "username": "alex.foreman",
        "country": "GB",
        "source_country": "GB"
    }
    engine.add_alert(past_alert)

    curr_alert = {
        "alert_id": "ALT-GEO-02",
        "username": "alex.foreman",
        "country": "SG",
        "source_country": "SG",
        "impossible_travel_speed_kmh": 950.0
    }

    result = engine.evaluate_correlations(curr_alert)
    assert result["has_correlation"] is True
    assert any(r["rule_id"] == "RULE-CORR-02" for r in result["matched_rules"])


def test_conflicting_alert_detection():
    """Verify detection of conflicting benign labels originating from anonymized TOR nodes."""
    engine = CorrelationRuleEngine()
    evasive_alert = {
        "alert_id": "ALT-CONF-01",
        "classification": "Benign Scheduled Backup",
        "is_tor": True,
        "country": "TOR_EXIT",
        "payload_entropy": 4.8
    }

    result = engine.evaluate_correlations(evasive_alert)
    assert len(result["conflicts"]) > 0
