"""
Cyber Telemetry Feature Extraction Module
Parses and normalizes raw SIEM alert JSON payloads into numerical feature vectors for ML models.
"""
import re
import math
from typing import Dict, Any, List, Tuple
import numpy as np

# Feature Column Names
FEATURE_NAMES = [
    "failed_login_count",
    "request_rate_per_sec",
    "payload_entropy",
    "payload_length",
    "is_admin_targeted",
    "impossible_travel_speed_kmh",
    "port_scan_distinct_ports",
    "outbound_bytes_mb",
    "error_status_rate",
    "sql_injection_indicator",
    "privilege_escalation_signal",
    "geo_risk_weight",
    "off_hours_activity",
    "known_attack_signature_match"
]

# SQL injection patterns
SQLI_REGEX = re.compile(
    r"(\b(select|union|insert|update|delete|drop|alter|exec|system|cmd)\b|"
    r"(--|#|/\*|;|\bOR\b\s+['\"0-9\(\)]+[\s=]+['\"0-9\(\)]+|'--|'\s+or\s+'1'='1'))",
    re.IGNORECASE
)

# Admin keywords
ADMIN_REGEX = re.compile(r"(admin|root|sysadmin|superuser|db_owner|administrator|system)", re.IGNORECASE)

# High risk countries/TOR/VPN flags
HIGH_RISK_GEO = {"RU", "KP", "IR", "SY", "TOR_EXIT", "ANONYMOUS_PROXY", "UNKNOWN_VPN"}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (measures payload randomness/obfuscation)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for c in data:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_features_from_alert(alert: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Extract standardized feature vector from a single raw SIEM alert dict.
    Returns (feature_vector_array, parsed_metadata_dict).
    """
    # 1. Failed Login Count
    failed_login = float(
        alert.get("failed_login_count")
        or alert.get("failed_logins")
        or (alert.get("telemetry", {}).get("failed_attempts", 0))
    )

    # 2. Request Rate per Second
    req_rate = float(
        alert.get("request_rate_per_sec")
        or alert.get("request_rate")
        or (alert.get("telemetry", {}).get("req_per_sec", 1.0))
    )

    # 3 & 4. Payload string extraction & Entropy / Length
    payload_str = str(
        alert.get("payload")
        or alert.get("raw_payload")
        or alert.get("query_string")
        or alert.get("command")
        or alert.get("sensitive_payload")
        or alert.get("message")
        or ""
    )
    payload_entropy = calculate_shannon_entropy(payload_str)
    payload_len = float(len(payload_str))

    # 5. Is Admin Targeted
    target_user = str(alert.get("username") or alert.get("user") or alert.get("target_user") or "")
    target_resource = str(alert.get("resource") or alert.get("endpoint") or alert.get("target") or "")
    is_admin = 1.0 if (ADMIN_REGEX.search(target_user) or ADMIN_REGEX.search(target_resource)) else 0.0

    # 6. Impossible Travel Speed (km/h)
    speed_kmh = float(
        alert.get("impossible_travel_speed_kmh")
        or alert.get("travel_speed_kmh")
        or alert.get("telemetry", {}).get("travel_velocity_kmh", 0.0)
    )

    # 7. Port Scan Distinct Ports
    ports = float(
        alert.get("port_scan_distinct_ports")
        or alert.get("distinct_ports")
        or alert.get("telemetry", {}).get("scanned_ports_count", 0)
    )

    # 8. Outbound Bytes in MB
    outbound_mb = float(
        alert.get("outbound_bytes_mb")
        or alert.get("bytes_transferred_mb")
        or (float(alert.get("outbound_bytes", 0)) / (1024 * 1024))
    )

    # 9. Error Status Rate (HTTP 4xx / 5xx percentage)
    error_rate = float(
        alert.get("error_status_rate")
        or alert.get("error_rate")
        or (1.0 if int(alert.get("status_code", 200)) >= 400 else 0.0)
    )

    # 10. SQL Injection Indicator
    has_sqli = 1.0 if (
        SQLI_REGEX.search(payload_str)
        or alert.get("attack_type") == "SQL_INJECTION"
        or "sqli" in str(alert.get("alert_name", "")).lower()
    ) else 0.0

    # 11. Privilege Escalation Signal
    priv_escalation = float(
        1.0 if (
            alert.get("privilege_escalation") is True
            or "privilege escalation" in str(alert.get("alert_name", "")).lower()
            or "sudo" in payload_str
            or "setuid" in payload_str
            or "shadow" in payload_str
        ) else 0.0
    )

    # 12. Geo Risk Weight
    country = str(alert.get("country") or alert.get("source_country") or "").upper()
    geo_risk = 1.0 if (country in HIGH_RISK_GEO or alert.get("is_tor") is True) else (0.5 if country and country not in {"US", "GB", "CA", "DE", "FR", "IN", "JP", "AU"} else 0.0)

    # 13. Off Hours Activity
    hour = int(alert.get("hour_of_day", 14))
    is_off_hours = 1.0 if (hour < 6 or hour > 22 or alert.get("is_weekend", False)) else 0.0

    # 14. Known Attack Signature Match
    sig_match = 1.0 if (
        alert.get("signature_match") is True
        or alert.get("cve_id")
        or "malicious" in str(alert.get("classification", "")).lower()
    ) else 0.0

    vector = np.array([
        failed_login,
        req_rate,
        payload_entropy,
        payload_len,
        is_admin,
        speed_kmh,
        ports,
        outbound_mb,
        error_rate,
        has_sqli,
        priv_escalation,
        geo_risk,
        is_off_hours,
        sig_match
    ], dtype=np.float32)

    metadata = {
        "failed_login": failed_login,
        "req_rate": req_rate,
        "payload_entropy": payload_entropy,
        "is_admin": bool(is_admin),
        "speed_kmh": speed_kmh,
        "ports": ports,
        "outbound_mb": outbound_mb,
        "has_sqli": bool(has_sqli),
        "priv_escalation": bool(priv_escalation),
        "geo_risk": geo_risk
    }

    return vector, metadata


def batch_extract_features(alerts: List[Dict[str, Any]]) -> np.ndarray:
    """Extract 2D numpy feature matrix from a list of alerts."""
    vectors = []
    for alert in alerts:
        vec, _ = extract_features_from_alert(alert)
        vectors.append(vec)
    return np.vstack(vectors) if vectors else np.empty((0, len(FEATURE_NAMES)))
