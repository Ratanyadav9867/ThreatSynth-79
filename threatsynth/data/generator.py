"""
Synthetic FinTech SIEM Alert Dataset Generator
Generates realistic, diverse security alerts for model training, testing, and SOC drill demonstrations.
"""
import os
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from threatsynth.config import SAMPLES_DIR, DATA_DIR


FINTECH_RESOURCES = [
    "/api/v1/payments/transfer",
    "/api/v2/auth/oauth/token",
    "/admin/accounts/manage",
    "/api/v1/cards/pin/verify",
    "/internal/k8s/etcd/keys",
    "/api/v1/wallets/crypto/withdraw",
    "/healthz",
    "/metrics",
    "/ci/deploy/webhook"
]

USERS = [
    "alex.foreman@fintech.io",
    "sarah.vance@fintech-shield.internal",
    "devops_deploy_bot",
    "root",
    "admin",
    "db_backup_service",
    "john.doe@fintech.io",
    "anonymous_client_99"
]

SQLI_PAYLOADS = [
    "admin' OR '1'='1' --",
    "1 UNION SELECT null, username, password_hash FROM admin_users --",
    "'; DROP TABLE audit_log; --",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
    "1 OR 1=1; EXEC xp_cmdshell('whoami');"
]

BENIGN_PAYLOADS = [
    '{"status": "ok", "service": "payment-gateway", "uptime": 86400}',
    '{"grant_type": "password", "client_id": "mobile-app-v3"}',
    '{"limit": 20, "offset": 0, "sort": "timestamp"}',
    'GET /healthz HTTP/1.1 200 OK',
    '{"event": "push", "ref": "refs/heads/main", "sender": "github-actions"}'
]


def create_sample_alert(
    category: str,
    alert_id: str = None,
    timestamp: str = None
) -> Dict[str, Any]:
    """Generate a single realistic synthetic security alert."""
    aid = alert_id or f"ALT-FIN-{uuid.uuid4().hex[:8].upper()}"
    ts = timestamp or datetime.now(timezone.utc).isoformat()

    if category == "HIGH_SQLI":
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Critical SQL Injection Attempt on Core Payment API",
            "source_ip": f"198.51.100.{random.randint(10, 250)}",
            "source_country": random.choice(["RU", "KP", "IR", "TOR_EXIT"]),
            "is_tor": True,
            "username": "admin",
            "resource": "/api/v1/payments/transfer",
            "status_code": 500,
            "attack_type": "SQL_INJECTION",
            "failed_login_count": 0,
            "request_rate_per_sec": 45.0,
            "payload": random.choice(SQLI_PAYLOADS),
            "outbound_bytes_mb": 14.5,
            "impossible_travel_speed_kmh": 0.0,
            "port_scan_distinct_ports": 0,
            "privilege_escalation": True,
            "hour_of_day": 3,
            "sensitive_payload": "SELECT * FROM cardholder_vault WHERE token='NULL' OR 1=1; -- EXFILTRATE",
            "classification": "High",
            "ground_truth_risk": "High"
        }

    elif category == "HIGH_TRAVEL":
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Impossible Travel Velocity & Executive Account Compromise",
            "source_ip": f"203.0.113.{random.randint(1, 200)}",
            "source_country": "SG",
            "is_tor": False,
            "username": "sarah.vance@fintech-shield.internal",
            "resource": "/admin/accounts/manage",
            "status_code": 200,
            "attack_type": "IMPOSSIBLE_TRAVEL",
            "failed_login_count": 1,
            "request_rate_per_sec": 8.0,
            "payload": '{"action": "export_all_customer_financial_records", "override_mfa": true}',
            "outbound_bytes_mb": 28.2,
            "impossible_travel_speed_kmh": 1250.0,
            "port_scan_distinct_ports": 0,
            "privilege_escalation": True,
            "hour_of_day": 2,
            "sensitive_payload": "SESSION_TOKEN=jwt.ey...; LOCATION_DELTA=London_to_Singapore_in_15_mins",
            "classification": "High",
            "ground_truth_risk": "High"
        }

    elif category == "MED_BRUTE":
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Authentication Brute Force Password Spray",
            "source_ip": f"185.220.101.{random.randint(1, 254)}",
            "source_country": "DE",
            "is_tor": False,
            "username": "john.doe@fintech.io",
            "resource": "/api/v2/auth/oauth/token",
            "status_code": 401,
            "attack_type": "BRUTE_FORCE",
            "failed_login_count": random.randint(8, 25),
            "request_rate_per_sec": 30.0,
            "payload": '{"username": "john.doe", "password": "password123"}',
            "outbound_bytes_mb": 0.05,
            "impossible_travel_speed_kmh": 0.0,
            "port_scan_distinct_ports": 0,
            "privilege_escalation": False,
            "hour_of_day": 19,
            "sensitive_payload": "FAILED_ATTEMPTS=18; USER_AGENT=Hydra/9.2",
            "classification": "Medium",
            "ground_truth_risk": "Medium"
        }

    elif category == "MED_PORTSCAN":
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Internal Network Reconnaissance & Port Probe",
            "source_ip": f"10.244.{random.randint(1, 10)}.{random.randint(1, 200)}",
            "source_country": "US",
            "is_tor": False,
            "username": "anonymous_client_99",
            "resource": "/internal/k8s/etcd/keys",
            "status_code": 404,
            "attack_type": "PORT_SCAN",
            "failed_login_count": 0,
            "request_rate_per_sec": 65.0,
            "payload": "SYN_PROBE port=2379,2380,6443,10250,8080",
            "outbound_bytes_mb": 0.12,
            "impossible_travel_speed_kmh": 0.0,
            "port_scan_distinct_ports": random.randint(15, 60),
            "privilege_escalation": False,
            "hour_of_day": 14,
            "sensitive_payload": "NMAP_SWEEP: targets=10.0.0.0/16 open_ports=2379",
            "classification": "Medium",
            "ground_truth_risk": "Medium"
        }

    elif category == "LOW_HEALTHCHECK":
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Routine Kubernetes Liveness Health Probe",
            "source_ip": "10.0.0.1",
            "source_country": "US",
            "is_tor": False,
            "username": "kubelet-health-probe",
            "resource": "/healthz",
            "status_code": 200,
            "attack_type": "BENIGN_PROBE",
            "failed_login_count": 0,
            "request_rate_per_sec": 1.0,
            "payload": "GET /healthz HTTP/1.1",
            "outbound_bytes_mb": 0.001,
            "impossible_travel_speed_kmh": 0.0,
            "port_scan_distinct_ports": 1,
            "privilege_escalation": False,
            "hour_of_day": 12,
            "sensitive_payload": "HEALTHCHECK_OK: latency_ms=1.2",
            "classification": "Low",
            "ground_truth_risk": "Low"
        }

    else:  # LOW_CICD
        return {
            "alert_id": aid,
            "timestamp": ts,
            "alert_name": "Authorized CI/CD Deployment Pipeline Execution",
            "source_ip": "140.82.112.4",
            "source_country": "US",
            "is_tor": False,
            "username": "devops_deploy_bot",
            "resource": "/ci/deploy/webhook",
            "status_code": 200,
            "attack_type": "BENIGN_DEPLOY",
            "failed_login_count": 0,
            "request_rate_per_sec": 2.0,
            "payload": '{"build_id": "b-98421", "branch": "release/2026.08", "status": "deployed"}',
            "outbound_bytes_mb": 0.45,
            "impossible_travel_speed_kmh": 0.0,
            "port_scan_distinct_ports": 0,
            "privilege_escalation": False,
            "hour_of_day": 15,
            "sensitive_payload": "COMMIT_SHA=7a9f2bc; VERIFIED_KEY=sig_ok",
            "classification": "Low",
            "ground_truth_risk": "Low"
        }


def generate_dataset(n_samples: int = 800) -> List[Dict[str, Any]]:
    """Generate a balanced synthetic dataset for training."""
    categories = [
        ("HIGH_SQLI", 0.18),
        ("HIGH_TRAVEL", 0.15),
        ("MED_BRUTE", 0.20),
        ("MED_PORTSCAN", 0.15),
        ("LOW_HEALTHCHECK", 0.18),
        ("LOW_CICD", 0.14)
    ]
    dataset = []
    base_time = datetime.now(timezone.utc) - timedelta(days=7)

    for i in range(n_samples):
        r = random.random()
        cumulative = 0.0
        chosen_cat = "LOW_HEALTHCHECK"
        for cat, weight in categories:
            cumulative += weight
            if r <= cumulative:
                chosen_cat = cat
                break

        event_time = (base_time + timedelta(minutes=i * 12)).isoformat()
        alert = create_sample_alert(chosen_cat, alert_id=f"ALT-DRN-{i+1:04d}", timestamp=event_time)
        dataset.append(alert)

    return dataset


def save_mvp_samples():
    """Write individual sample JSON files for the MVP demo."""
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    samples = {
        "01_sql_injection_exfil.json": create_sample_alert("HIGH_SQLI", "ALT-DEMO-001"),
        "02_impossible_travel_admin.json": create_sample_alert("HIGH_TRAVEL", "ALT-DEMO-002"),
        "03_brute_force_auth.json": create_sample_alert("MED_BRUTE", "ALT-DEMO-003"),
        "04_internal_port_scan.json": create_sample_alert("MED_PORTSCAN", "ALT-DEMO-004"),
        "05_benign_healthcheck.json": create_sample_alert("LOW_HEALTHCHECK", "ALT-DEMO-005"),
        "06_benign_cicd_deploy.json": create_sample_alert("LOW_CICD", "ALT-DEMO-006")
    }

    for filename, data in samples.items():
        path = SAMPLES_DIR / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # Batch drill file
    batch_drill = list(samples.values())
    with open(SAMPLES_DIR / "batch_incident_drill.json", "w", encoding="utf-8") as f:
        json.dump(batch_drill, f, indent=2)

    print(f"[DataGenerator] Saved MVP sample alerts to {SAMPLES_DIR}")
