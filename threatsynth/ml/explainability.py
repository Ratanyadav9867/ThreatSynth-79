"""
ML Explainability Engine (SHAP-style Feature Attribution & Decision Attribution)
Explains why an alert was classified as High, Medium, or Low risk.
"""
from typing import Dict, Any, List
import numpy as np
from threatsynth.ml.features import FEATURE_NAMES


FEATURE_DESCRIPTIONS = {
    "failed_login_count": "Number of consecutive failed authentication attempts",
    "request_rate_per_sec": "Burst request velocity against API endpoints",
    "payload_entropy": "Shannon randomness metric indicative of payload obfuscation or binary injection",
    "payload_length": "Size of raw HTTP or query payload",
    "is_admin_targeted": "Targeting privileged accounts (root/admin/db_owner)",
    "impossible_travel_speed_kmh": "Physical velocity required between consecutive geographic access events",
    "port_scan_distinct_ports": "Breadth of reconnaissance targeting internal network ports",
    "outbound_bytes_mb": "Volume of outbound data transfer indicative of data exfiltration",
    "error_status_rate": "Frequency of HTTP 4xx/5xx security and server errors",
    "sql_injection_indicator": "Presence of SQL injection syntax and evasion patterns",
    "privilege_escalation_signal": "System commands or tokens attempting kernel/root privilege escalation",
    "geo_risk_weight": "Geopolitical risk or anonymizing proxy/TOR node usage",
    "off_hours_activity": "Operations triggered outside normal business hours",
    "known_attack_signature_match": "Exact match against known threat intelligence CVE/signature database"
}


def explain_prediction(
    model,
    anomaly_model,
    feature_vector: np.ndarray,
    predicted_risk: str,
    probabilities: Dict[str, float]
) -> Dict[str, Any]:
    """
    Compute local feature attribution and decision drivers for an individual alert.
    Uses tree feature importances combined with normalized feature deviations from baseline.
    """
    vec = feature_vector.flatten()
    
    # Get global feature importances if available
    if hasattr(model, "feature_importances_"):
        global_importances = model.feature_importances_
    else:
        global_importances = np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)

    # Heuristic baseline expectations for normal traffic
    baseline = np.array([
        0.0,   # failed_login_count
        1.0,   # request_rate_per_sec
        2.5,   # payload_entropy
        50.0,  # payload_length
        0.0,   # is_admin_targeted
        0.0,   # impossible_travel_speed_kmh
        0.0,   # port_scan_distinct_ports
        0.5,   # outbound_bytes_mb
        0.0,   # error_status_rate
        0.0,   # sql_injection_indicator
        0.0,   # privilege_escalation_signal
        0.0,   # geo_risk_weight
        0.0,   # off_hours_activity
        0.0    # known_attack_signature_match
    ])

    # Normalization scale for calculating standardized deviations
    scales = np.array([5.0, 50.0, 4.0, 500.0, 1.0, 800.0, 20.0, 50.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0])

    # Local contribution = importance * ((value - baseline) / scale)
    deviations = (vec - baseline) / scales
    raw_contributions = global_importances * deviations

    # Normalize contributions so they sum intuitively to explain the risk score
    factors = []
    for i, name in enumerate(FEATURE_NAMES):
        val = float(vec[i])
        contrib = float(raw_contributions[i])
        
        impact = "NEUTRAL"
        if contrib > 0.02:
            impact = "INCREASES_RISK"
        elif contrib < -0.02 or (val == 0 and name in ["failed_login_count", "sql_injection_indicator"]):
            impact = "DECREASES_RISK"

        # Generate descriptive factor explanation
        reason = f"{FEATURE_DESCRIPTIONS.get(name, name)}: observed value = {val}"
        if name == "impossible_travel_speed_kmh" and val > 500:
            reason = f"Impossible Travel Velocity of {val:.0f} km/h detected between consecutive logins (Physical impossibility)"
        elif name == "sql_injection_indicator" and val == 1:
            reason = "Active SQL injection syntax patterns matched in request payload"
        elif name == "failed_login_count" and val >= 5:
            reason = f"High volume of failed authentications ({int(val)} attempts) indicating brute force attack"
        elif name == "is_admin_targeted" and val == 1:
            reason = "Target resource/account belongs to administrative tier"
        elif name == "outbound_bytes_mb" and val > 10:
            reason = f"Massive abnormal outbound data spike ({val:.1f} MB) indicative of exfiltration"
        elif name == "port_scan_distinct_ports" and val >= 10:
            reason = f"Port scanning probe across {int(val)} distinct ports"

        factors.append({
            "feature": name,
            "display_name": name.replace("_", " ").title(),
            "value": round(val, 2),
            "importance_weight": round(float(global_importances[i]), 4),
            "contribution_score": round(contrib, 4),
            "impact": impact,
            "explanation": reason
        })

    # Sort factors by impact magnitude
    factors.sort(key=lambda x: abs(x["contribution_score"]), reverse=True)
    top_drivers = [f for f in factors if f["impact"] == "INCREASES_RISK"][:4]
    mitigating_factors = [f for f in factors if f["impact"] == "DECREASES_RISK"][:2]

    # Human-readable summary sentence
    if predicted_risk == "High":
        primary_drivers = ", ".join([f["display_name"] for f in top_drivers[:2]]) or "Multiple anomaly vectors"
        summary = f"Classified as HIGH RISK primarily driven by {primary_drivers}. Requires immediate SOC containment."
    elif predicted_risk == "Medium":
        summary = f"Classified as MEDIUM RISK with suspicious signals in {top_drivers[0]['display_name'] if top_drivers else 'telemetry'}. Monitor and review."
    else:
        summary = "Classified as LOW RISK. Activity aligns with benign baseline operational telemetry."

    return {
        "predicted_risk": predicted_risk,
        "confidence": probabilities.get(predicted_risk, 0.95),
        "probabilities": probabilities,
        "explanation_summary": summary,
        "top_risk_drivers": top_drivers,
        "mitigating_factors": mitigating_factors,
        "all_factors": factors,
        "model_architecture": "Ensemble Random Forest Classifier + Isolation Forest Anomaly Detector"
    }
