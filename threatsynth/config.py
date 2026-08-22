"""
ThreatSynth 79 Configuration Settings
"""
import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "threatsynth" / "data"
SAMPLES_DIR = DATA_DIR / "samples"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "threatsynth" / "reports" / "generated"
AUDIT_LOG_FILE = BASE_DIR / "threatsynth" / "audit.jsonl"
STATIC_DIR = BASE_DIR / "threatsynth" / "static"

# Ensure runtime directories exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

# Security & JWT Configuration
JWT_SECRET = os.getenv("THREATSYNTH_JWT_SECRET", "threatsynth-super-secret-key-fintech-secops-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60 * 24  # 24 hours

# ML Model Configuration
MODEL_PATH = MODELS_DIR / "threatsynth_model.joblib"
RANDOM_STATE = 42

# Risk Thresholds
RISK_LEVELS = ["Low", "Medium", "High"]
HIGH_RISK_ANOMALY_THRESHOLD = 0.70
MEDIUM_RISK_ANOMALY_THRESHOLD = 0.40

# Preconfigured Mock Identity Provider Users
MOCK_USERS = {
    "admin": {
        "user_id": "usr-admin-01",
        "username": "admin",
        "password": "AdminPassword123!",
        "full_name": "Commander Sarah Vance",
        "role": "admin",
        "email": "sarah.vance@fintech-shield.internal",
        "department": "Global InfoSec Command",
        "description": "Full administrative authority, ML retraining, rule configuration & audit export."
    },
    "soc_analyst": {
        "user_id": "usr-analyst-02",
        "username": "soc_analyst",
        "password": "AnalystPassword123!",
        "full_name": "Alice Chen, CISSP",
        "role": "soc_analyst",
        "email": "alice.chen@fintech-shield.internal",
        "department": "Security Operations Center",
        "description": "Authorized to view full risk summaries, forensic payloads, SHAP factors & AI playbooks."
    },
    "tier1_viewer": {
        "user_id": "usr-tier1-03",
        "username": "tier1_viewer",
        "password": "ViewerPassword123!",
        "full_name": "Bob Martinez (Tier 1)",
        "role": "tier1_viewer",
        "email": "bob.martinez@fintech-shield.internal",
        "department": "IT Helpdesk & Triage Support",
        "description": "Limited read access. Sees high-level metadata only; sensitive threat payload & risk summaries redacted."
    },
    "unauthorized_guest": {
        "user_id": "usr-guest-99",
        "username": "unauthorized_guest",
        "password": "GuestPassword123!",
        "full_name": "Charlie Guest (External)",
        "role": "unauthorized_guest",
        "email": "charlie@external-vendor.com",
        "department": "External Guest / Auditor",
        "description": "Unauthorized account. Blocked with 403 Forbidden on all sensitive threat intelligence."
    }
}
